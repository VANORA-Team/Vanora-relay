package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"
	"vanora-relay/adapter/account"
	"vanora-relay/adapter/desktop"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/pairnet"
)

// Optional build-time defaults injected via -ldflags when embedding
// vanora-desktop as a sidecar inside Vanora.
var (
	// Legacy single-channel build defaults.
	defaultIdentityURL = ""
	defaultSignalURL   = ""
	defaultCAHex       = ""

	// Official dual-site build defaults (CN and GLOBAL use independent
	// identity authorities, Ed25519 public keys, and relay endpoints).
	defaultCNIdentityURL     = ""
	defaultCNSignalURL       = ""
	defaultCNCAHex           = ""
	defaultGlobalIdentityURL = ""
	defaultGlobalSignalURL   = ""
	defaultGlobalCAHex       = ""
)

type jsonEmitter struct {
	mu  sync.Mutex
	out io.Writer
}

func (e *jsonEmitter) Emit(ev map[string]any) {
	if e == nil || e.out == nil {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	b = append(b, '\n')
	e.mu.Lock()
	_, _ = e.out.Write(b)
	e.mu.Unlock()
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

type officialSlotConfig struct {
	name      string
	account   *account.Account
	ca        ed25519.PublicKey
	signalURL string
}

func parseChannelFlag(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case "cn":
		return "cn", nil
	case "global":
		return "global", nil
	case "self":
		return "self", nil
	default:
		return "", fmt.Errorf("unknown channel %q (want cn, global or self)", raw)
	}
}

func openOfficialSlot(dir, vaultChannel, name, identityURL, caFile, caHexFlag, signalURL string) (*officialSlotConfig, error) {
	identityURL = strings.TrimSpace(identityURL)
	caFile = strings.TrimSpace(caFile)
	caHexFlag = strings.TrimSpace(caHexFlag)
	signalURL = strings.TrimSpace(signalURL)
	hasCA := caFile != "" || caHexFlag != ""
	if identityURL == "" && !hasCA && signalURL == "" {
		return nil, nil
	}
	if identityURL == "" || !hasCA {
		return nil, fmt.Errorf("channel %s requires identity URL and pinned public key (-ca or -ca-hex)", name)
	}
	pubRaw := []byte(caHexFlag)
	if caFile != "" {
		var err error
		pubRaw, err = os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
	}
	ca, err := identity.ParsePublicKey(pubRaw)
	if err != nil {
		return nil, err
	}
	caHex := hex.EncodeToString(ca)
	a, err := account.New(identityURL, caHex, openChannelVault(dir, vaultChannel, identityURL, caHex))
	if err != nil {
		return nil, err
	}
	return &officialSlotConfig{
		name:      name,
		account:   a,
		ca:        ca,
		signalURL: signalURL,
	}, nil
}

func run(args []string) error {
	const usage = "usage: vanora-desktop login|serve|whoami|status|logout|ctl [-channel cn|global|self -identity URL -ca FILE|-ca-hex HEX -signal WSS_URL -cn-identity URL -cn-ca FILE|-cn-ca-hex HEX -cn-signal WSS_URL -global-identity URL -global-ca FILE|-global-ca-hex HEX -global-signal WSS_URL -self-signal WSS_URL -self-token TOKEN -lan-listen IP:PORT -relay=false -config FILE -name NAME -state-dir DIR -token TOKEN|-token-stdin -sidecar -json]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd := args[0]
	if cmd == "ctl" {
		return runCtl(args[1:])
	}
	switch cmd {
	case "login", "serve", "whoami", "status", "logout":
	default:
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	channelFlag := fs.String("channel", envOrDefault("VANORA_RELAY_CHANNEL", ""), "relay channel: cn, global, or self")

	// Legacy single-channel flags (retained for standalone CLI compatibility).
	identityURL := fs.String("identity", envOrDefault("VANORA_RELAY_IDENTITY_URL", defaultIdentityURL), "identity authority URL")
	caFile := fs.String("ca", "", "pinned identity public key file")
	caHexFlag := fs.String("ca-hex", envOrDefault("VANORA_RELAY_CA_PUBLIC_KEY", defaultCAHex), "pinned identity public key (hex or base64)")
	signalURL := fs.String("signal", envOrDefault("VANORA_RELAY_SIGNAL_URL", defaultSignalURL), "full relay WebSocket URL")
	signalToken := fs.String("signal-token", envOrDefault("VANORA_RELAY_SIGNAL_TOKEN", ""), "bearer token for a self-hosted relay (alias for -self-token)")

	// Per-site official channel flags for simultaneous CN and GLOBAL slots.
	cnIdentityURL := fs.String("cn-identity", envOrDefault("VANORA_RELAY_CN_IDENTITY_URL", defaultCNIdentityURL), "CN site identity authority URL")
	cnCAFile := fs.String("cn-ca", "", "CN site pinned identity public key file")
	cnCAHex := fs.String("cn-ca-hex", envOrDefault("VANORA_RELAY_CN_CA_PUBLIC_KEY", defaultCNCAHex), "CN site pinned identity public key (hex or base64)")
	cnSignalURL := fs.String("cn-signal", envOrDefault("VANORA_RELAY_CN_SIGNAL_URL", defaultCNSignalURL), "CN site official relay WebSocket URL")

	globalIdentityURL := fs.String("global-identity", envOrDefault("VANORA_RELAY_GLOBAL_IDENTITY_URL", defaultGlobalIdentityURL), "GLOBAL site identity authority URL")
	globalCAFile := fs.String("global-ca", "", "GLOBAL site pinned identity public key file")
	globalCAHex := fs.String("global-ca-hex", envOrDefault("VANORA_RELAY_GLOBAL_CA_PUBLIC_KEY", defaultGlobalCAHex), "GLOBAL site pinned identity public key (hex or base64)")
	globalSignalURL := fs.String("global-signal", envOrDefault("VANORA_RELAY_GLOBAL_SIGNAL_URL", defaultGlobalSignalURL), "GLOBAL site official relay WebSocket URL")

	// Account-free self-hosted relay flags.
	selfSignalURL := fs.String("self-signal", envOrDefault("VANORA_RELAY_SELF_SIGNAL_URL", ""), "self-hosted relay WebSocket URL")
	selfToken := fs.String("self-token", envOrDefault("VANORA_RELAY_SELF_TOKEN", ""), "bearer token for a self-hosted relay (RELAY_SELF_TOKEN)")

	root := fs.String("state-dir", "", "profile directory (defaults to user config)")
	lanListen := fs.String("lan-listen", "", "listen for paired LAN clients on a private IP address and port")
	relayEnabled := fs.Bool("relay", true, "enable the configured WAN relay channel")
	config := fs.String("config", "", "local Vanora session and permission config")
	hostname, _ := os.Hostname()
	name := fs.String("name", hostname, "published desktop name")
	tokenFlag := fs.String("token", envOrDefault("VANORA_CLIENT_TOKEN", ""), "existing client auth token (or set VANORA_CLIENT_TOKEN)")
	tokenStdin := fs.Bool("token-stdin", false, "read client auth token from stdin")
	jsonOutput := fs.Bool("json", false, "emit structured JSON lines on stdout")
	sidecar := fs.Bool("sidecar", false, "sidecar mode: JSONL stdout events, stdin commands, exit on stdin EOF")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}

	channel, err := parseChannelFlag(*channelFlag)
	if err != nil {
		return err
	}
	if *sidecar {
		*jsonOutput = true
	}
	var emitter *jsonEmitter
	if *jsonOutput {
		emitter = &jsonEmitter{out: os.Stdout}
	}
	if *root == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		*root = filepath.Join(dir, "Vanora", "relay")
	}
	dir, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, "profile.lock"))
	ok, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("desktop profile is already open")
	}
	defer lock.Unlock()

	resolvedSelfSignal := strings.TrimSpace(*selfSignalURL)
	resolvedSelfToken := strings.TrimSpace(*selfToken)
	if resolvedSelfToken == "" {
		resolvedSelfToken = strings.TrimSpace(*signalToken)
	}
	legacyID := strings.TrimSpace(*identityURL)
	legacyCAFile := strings.TrimSpace(*caFile)
	legacyCAHex := strings.TrimSpace(*caHexFlag)
	legacySig := strings.TrimSpace(*signalURL)

	if channel == "self" {
		if resolvedSelfSignal == "" {
			resolvedSelfSignal = legacySig
		}
		legacySig = ""
	}

	slots := make(map[string]*officialSlotConfig, 2)
	cnSlot, err := openOfficialSlot(dir, "cn", "cn", *cnIdentityURL, *cnCAFile, *cnCAHex, *cnSignalURL)
	if err != nil {
		return err
	}
	if cnSlot != nil {
		slots["cn"] = cnSlot
	}
	globalSlot, err := openOfficialSlot(dir, "global", "global", *globalIdentityURL, *globalCAFile, *globalCAHex, *globalSignalURL)
	if err != nil {
		return err
	}
	if globalSlot != nil {
		slots["global"] = globalSlot
	}

	hasLegacy := legacyID != "" || legacyCAFile != "" || legacyCAHex != "" || legacySig != ""
	if hasLegacy {
		slotName := "cn"
		vaultChannel := ""
		if channel == "global" {
			slotName = "global"
			vaultChannel = "global"
		} else if channel == "cn" {
			slotName = "cn"
			vaultChannel = "cn"
		}
		if _, exists := slots[slotName]; exists {
			return fmt.Errorf("channel %s cannot be configured with both legacy flags and -%s-* flags", slotName, slotName)
		}
		legacySlot, err := openOfficialSlot(dir, vaultChannel, slotName, legacyID, legacyCAFile, legacyCAHex, legacySig)
		if err != nil {
			return err
		}
		if legacySlot != nil {
			slots[slotName] = legacySlot
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	selectOfficialSlot := func(action string) (*officialSlotConfig, error) {
		if channel == "self" {
			return nil, fmt.Errorf("self-hosted relay uses pairing and does not support %s", action)
		}
		if channel != "" {
			slot := slots[channel]
			if slot == nil {
				return nil, fmt.Errorf("channel %s is not configured (identity URL and pinned public key required)", channel)
			}
			return slot, nil
		}
		if len(slots) == 0 {
			return nil, errors.New("identity URL and pinned public key (-ca or -ca-hex) required")
		}
		if len(slots) == 1 {
			for _, slot := range slots {
				return slot, nil
			}
		}
		return nil, fmt.Errorf("multiple official channels configured; specify -channel cn or -channel global for %s", action)
	}

	switch cmd {
	case "whoami", "status":
		if channel == "" && len(slots) > 1 {
			channelsOut := map[string]any{}
			for _, name := range []string{"cn", "global"} {
				if slot := slots[name]; slot != nil {
					channelsOut[name] = map[string]any{
						"enrolled":  slot.account.UserID() != "",
						"user_id":   slot.account.UserID(),
						"device_id": slot.account.DeviceID(),
					}
				}
			}
			if emitter != nil {
				emitter.Emit(map[string]any{
					"type":      "status",
					"channels":  channelsOut,
					"state_dir": dir,
				})
				return nil
			}
			for _, name := range []string{"cn", "global"} {
				if slot := slots[name]; slot != nil {
					fmt.Printf("[%s]\nenrolled=%t\nuser_id=%s\ndevice_id=%s\n", name, slot.account.UserID() != "", slot.account.UserID(), slot.account.DeviceID())
				}
			}
			return nil
		}
		slot, err := selectOfficialSlot(cmd)
		if err != nil {
			return err
		}
		enrolled := slot.account.UserID() != ""
		if emitter != nil {
			emitter.Emit(map[string]any{
				"type":      "status",
				"channel":   slot.name,
				"enrolled":  enrolled,
				"user_id":   slot.account.UserID(),
				"device_id": slot.account.DeviceID(),
				"state_dir": dir,
			})
			return nil
		}
		fmt.Printf("enrolled=%t\nuser_id=%s\ndevice_id=%s\n", enrolled, slot.account.UserID(), slot.account.DeviceID())
		return nil
	case "logout":
		slot, err := selectOfficialSlot("logout")
		if err != nil {
			return err
		}
		if err := slot.account.Reset(); err != nil {
			return err
		}
		if emitter != nil {
			emitter.Emit(map[string]any{"type": "logout.ok", "channel": slot.name})
			return nil
		}
		fmt.Println("logged out")
		return nil
	case "login":
		slot, err := selectOfficialSlot("login")
		if err != nil {
			return err
		}
		return login(ctx, slot.account, loginOptions{
			channel:    slot.name,
			token:      *tokenFlag,
			tokenStdin: *tokenStdin,
			in:         os.Stdin,
			emitter:    emitter,
		})
	case "serve":
		if *config == "" {
			return errors.New("serve requires -config and an enabled relay channel, -lan-listen, or -sidecar")
		}
		if *tokenStdin && *sidecar {
			return errors.New("-token-stdin cannot be combined with -sidecar; send {\"type\":\"auth.token\",\"channel\":\"cn|global\",\"token\":\"...\"} on stdin or set VANORA_CLIENT_TOKEN")
		}
		tok := strings.TrimSpace(*tokenFlag)
		if *tokenStdin {
			tok, err = readTokenInput("", true, os.Stdin)
			if err != nil {
				return err
			}
		}

		activeChannel := channel
		if activeChannel == "" && *relayEnabled {
			if len(slots) == 1 {
				for name := range slots {
					activeChannel = name
				}
			} else if len(slots) == 0 && resolvedSelfSignal != "" {
				activeChannel = "self"
			}
		}
		if !*relayEnabled {
			activeChannel = ""
		}

		if !*sidecar && *lanListen == "" && activeChannel == "" {
			return errors.New("serve requires -config and an enabled relay channel, -lan-listen, or -sidecar")
		}
		if activeChannel == "self" {
			if err := selfrelay.ValidateSignalURL(resolvedSelfSignal); err != nil {
				return err
			}
			if err := selfrelay.ValidateRelayToken(resolvedSelfToken); err != nil {
				return err
			}
		}
		if activeChannel == "cn" || activeChannel == "global" {
			slot := slots[activeChannel]
			if slot == nil || slot.signalURL == "" {
				return fmt.Errorf("channel %s requires configured identity, public key, and signal URL", activeChannel)
			}
			if !*sidecar && *lanListen == "" && slot.account.UserID() == "" && tok == "" {
				return errors.New("endpoint not enrolled; run vanora-desktop login or provide -token / VANORA_CLIENT_TOKEN")
			}
			if !*sidecar && *lanListen == "" && tok != "" {
				if slot.account.UserID() == "" {
					enrollCtx, cancelEnroll := context.WithTimeout(ctx, 30*time.Second)
					err = slot.account.Enroll(enrollCtx, tok)
					cancelEnroll()
				} else {
					err = slot.account.UpdateToken(tok)
				}
				if err != nil {
					return err
				}
				tok = ""
			}
		}

		initialTokens := map[string]string{}
		if tok != "" {
			target := activeChannel
			if target == "" && len(slots) == 1 {
				for name := range slots {
					target = name
				}
			}
			if target == "cn" || target == "global" {
				initialTokens[target] = tok
			}
		}
		return serveMulti(ctx, slots, *name, *config, dir, *sidecar, emitter, accessOptions{
			lanListen:     *lanListen,
			relayEnabled:  *relayEnabled && activeChannel != "",
			activeChannel: activeChannel,
			selfURL:       resolvedSelfSignal,
			selfToken:     resolvedSelfToken,
			tokens:        initialTokens,
		})
	default:
		return errors.New("unknown subcommand")
	}
}

// Only authenticated local proof refreshes extend desktop execution, including while phones are offline.
type authority struct {
	account *account.Account
	adapter *desktop.Adapter
	ca      ed25519.PublicKey
	mu      sync.Mutex
}

func (s *authority) PairingIdentity(scope, role string) (*pairnet.Group, pairnet.Member) {
	return s.account.PairingIdentity(scope, role)
}

func (s *authority) Current(ctx context.Context) (*endpoint.Credentials, endpoint.LeaseProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	creds, p, err := s.account.Current(ctx)
	if err == nil {
		var cert identity.Principal
		cert, err = identity.VerifyCertificate(p.Certificate, s.ca, time.Now())
		if err == nil {
			var until time.Time
			until, err = identity.VerifyEndpointLease(p.Lease, s.ca, time.Now(), p.Certificate, cert)
			if err == nil {
				s.adapter.AuthorityUntil(until)
				return creds, p, nil
			}
		}
	}
	s.adapter.AuthorityLost()
	return nil, endpoint.LeaseProof{}, err
}

func isAuthRequiredError(err error) bool {
	return errors.Is(err, account.ErrNotEnrolled) ||
		errors.Is(err, account.ErrExpired) ||
		errors.Is(err, account.ErrCredential) ||
		errors.Is(err, account.ErrStateInvalid) ||
		errors.Is(err, account.ErrAuthorityChanged)
}

func guests(cfg *desktop.Config, owner string) ([]string, error) {
	seen := map[string]bool{}
	for _, s := range cfg.Sessions {
		if s.Owner != owner && s.Owner != desktop.LocalOwner {
			return nil, fmt.Errorf("session %q must belong to this desktop account", s.ID)
		}
		for _, g := range s.Users {
			if g.UserID != owner && (g.Read || g.Tools) {
				seen[g.UserID] = true
			}
		}
	}
	for _, w := range cfg.Workspaces {
		if w.Owner != owner && w.Owner != desktop.LocalOwner {
			return nil, fmt.Errorf("workspace %q must belong to this desktop account", w.ID)
		}
		for _, g := range w.Users {
			if g.UserID != owner && (g.Read || g.Tools) {
				seen[g.UserID] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	slices.Sort(out)
	return out, nil
}

// serve keeps single-channel call signature for focused tests.
func serve(ctx context.Context, a *account.Account, ca ed25519.PublicKey, url, name, path, dir string, sidecar bool, emitter *jsonEmitter, options accessOptions) error {
	slots := map[string]*officialSlotConfig{}
	if a != nil {
		ch := options.activeChannel
		if ch != "cn" && ch != "global" {
			ch = "cn"
		}
		slots[ch] = &officialSlotConfig{name: ch, account: a, ca: ca, signalURL: url}
		if options.relayEnabled && options.activeChannel == "" {
			options.activeChannel = ch
		}
		if options.token != "" {
			if options.tokens == nil {
				options.tokens = map[string]string{}
			}
			options.tokens[ch] = options.token
		}
	}
	return serveMulti(ctx, slots, name, path, dir, sidecar, emitter, options)
}

func serveMulti(ctx context.Context, slotConfigs map[string]*officialSlotConfig, name, path, dir string, sidecar bool, emitter *jsonEmitter, options accessOptions) error {
	cfg, err := desktop.LoadConfig(path)
	if err != nil {
		return err
	}
	if !sidecar && options.lanListen == "" && (options.activeChannel == "cn" || options.activeChannel == "global") {
		if slot := slotConfigs[options.activeChannel]; slot != nil && slot.account != nil && slot.account.UserID() != "" {
			if _, err := guests(cfg, slot.account.UserID()); err != nil {
				return err
			}
		}
	}
	service, err := desktop.New(cfg, filepath.Join(dir, "sessions"))
	if err != nil {
		return err
	}
	defer service.Close()
	if emitter != nil {
		service.SetObserver(emitter.Emit)
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()

	reloadNow := make(chan struct{}, 1)
	updates := make(chan struct{}, 1)
	fail := make(chan error, 1)
	var currentConfig atomic.Pointer[desktop.Config]
	currentConfig.Store(cfg)

	slots := make(map[string]*officialSlot, len(slotConfigs))
	for k, sc := range slotConfigs {
		if sc == nil || sc.account == nil {
			continue
		}
		slot := &officialSlot{
			name:        k,
			desktopName: name,
			account:     sc.account,
			ca:          sc.ca,
			url:         sc.signalURL,
		}
		if options.tokens != nil {
			slot.token = strings.TrimSpace(options.tokens[k])
		}
		slots[k] = slot
	}

	access := &accessManager{
		ctx:              ctx,
		slots:            slots,
		name:             name,
		service:          service,
		dir:              dir,
		emitter:          emitter,
		config:           currentConfig.Load,
		updates:          updates,
		retry:            make(chan struct{}, 1),
		requireHostToken: sidecar,
		selfStore:        options.selfStore,
		selfURL:          strings.TrimSpace(options.selfURL),
		selfToken:        strings.TrimSpace(options.selfToken),
	}
	access.initRemote()
	if options.relayEnabled && options.activeChannel != "" {
		access.activeChannel = options.activeChannel
	}
	if options.lanListen != "" {
		if err := access.listen(options.lanListen); err != nil {
			return err
		}
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var prev []byte
		for {
			select {
			case <-ctx.Done():
				return
			case <-reloadNow:
				prev = nil
			case <-ticker.C:
			}
			b, e := os.ReadFile(path)
			if e == nil && prev != nil && bytes.Equal(b, prev) {
				continue
			}
			var next *desktop.Config
			if e == nil {
				next, e = desktop.ParseConfig(b)
			}
			if e == nil {
				e = service.ReloadACL(next)
			}
			if e != nil {
				service.AuthorityLost()
				if emitter != nil {
					emitter.Emit(map[string]any{"type": "error", "error": e.Error()})
				}
				fail <- e
				cancel()
				return
			}
			prev = b
			currentConfig.Store(next)
			if emitter != nil {
				emitter.Emit(map[string]any{"type": "config.reloaded"})
			}
			select {
			case updates <- struct{}{}:
			default:
			}
		}
	}()

	if sidecar {
		ready := map[string]any{
			"type":           "ready",
			"active_channel": access.activeChannel,
			"user_id":        access.userID(),
			"device_id":      access.deviceID(),
			"name":           strings.TrimSpace(name),
		}
		emitter.Emit(ready)
	}
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 0, 4096), 64<<10)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var cmd accessCommand
			if json.Unmarshal([]byte(line), &cmd) != nil {
				continue
			}
			if !sidecar &&
				!strings.HasPrefix(cmd.Type, "access.relay.invite.") &&
				!strings.HasPrefix(cmd.Type, "access.relay.client") &&
				!strings.HasPrefix(cmd.Type, "access.network.") &&
				!strings.HasPrefix(cmd.Type, "access.invite.") &&
				cmd.Type != "access.client.access.set" &&
				!strings.HasPrefix(cmd.Type, "remote.") {
				continue
			}
			switch {
			case cmd.Type == "shutdown":
				cancel()
				return
			case cmd.Type == "reload":
				select {
				case reloadNow <- struct{}{}:
				default:
				}
			case cmd.Type == "status":
				emitter.Emit(map[string]any{
					"type":           "status",
					"active_channel": access.currentChannel(),
					"online":         access.isOnline(),
					"user_id":        access.userID(),
					"device_id":      access.deviceID(),
				})
			case strings.HasPrefix(cmd.Type, "remote."):
				go access.remoteCommand(cmd)
			default:
				access.command(cmd)
			}
		}
		if sidecar {
			cancel()
		}
	}()
	access.mu.Lock()
	_ = access.startActiveWANLocked()
	access.mu.Unlock()
	<-ctx.Done()
	access.close()
	if emitter != nil {
		emitter.Emit(map[string]any{"type": "shutdown"})
	}
	select {
	case err := <-fail:
		return err
	default:
		return nil
	}
}

func publish(ctx context.Context, s *transport.Client, name string, users []string) error {
	c, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	return s.Publish(c, strings.TrimSpace(name), users)
}
