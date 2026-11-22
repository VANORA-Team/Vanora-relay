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
	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
)

// Optional build-time defaults injected via -ldflags when embedding
// vanora-desktop as a sidecar inside Vanora.
var (
	defaultIdentityURL = ""
	defaultSignalURL   = ""
	defaultCAHex       = ""
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

func run(args []string) error {
	const usage = "usage: vanora-desktop login|serve|whoami|status|logout [-identity URL -ca PUBLIC_KEY_FILE|-ca-hex HEX -signal WSS_URL -lan-listen IP:PORT -relay=false -config FILE -name NAME -state-dir DIR -token TOKEN|-token-stdin -sidecar -json]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd := args[0]
	switch cmd {
	case "login", "serve", "whoami", "status", "logout":
	default:
		return errors.New(usage)
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	identityURL := fs.String("identity", envOrDefault("VANORA_RELAY_IDENTITY_URL", defaultIdentityURL), "identity authority URL")
	caFile := fs.String("ca", "", "pinned identity public key file")
	caHexFlag := fs.String("ca-hex", envOrDefault("VANORA_RELAY_CA_PUBLIC_KEY", defaultCAHex), "pinned identity public key (hex or base64)")
	root := fs.String("state-dir", "", "profile directory (defaults to user config)")
	signalURL := fs.String("signal", envOrDefault("VANORA_RELAY_SIGNAL_URL", defaultSignalURL), "full relay WebSocket URL")
	lanListen := fs.String("lan-listen", "", "listen for paired LAN clients on a private IP address and port")
	relayEnabled := fs.Bool("relay", true, "enable the configured official relay")
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
	*identityURL = strings.TrimSpace(*identityURL)
	*signalURL = strings.TrimSpace(*signalURL)
	hasCA := strings.TrimSpace(*caFile) != "" || strings.TrimSpace(*caHexFlag) != ""
	cloudConfigured := *identityURL != "" && hasCA
	if !cloudConfigured && (cmd != "serve" || *identityURL != "" || hasCA || *signalURL != "") {
		return errors.New("identity URL and pinned public key (-ca or -ca-hex) required")
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

	var a *account.Account
	var ca ed25519.PublicKey
	if cloudConfigured {
		pubRaw := []byte(strings.TrimSpace(*caHexFlag))
		if strings.TrimSpace(*caFile) != "" {
			pubRaw, err = os.ReadFile(*caFile)
			if err != nil {
				return err
			}
		}
		ca, err = identity.ParsePublicKey(pubRaw)
		if err != nil {
			return err
		}
		caHex := hex.EncodeToString(ca)
		a, err = account.New(*identityURL, caHex, openVault(dir, *identityURL, caHex))
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch cmd {
	case "whoami", "status":
		enrolled := a.UserID() != ""
		if emitter != nil {
			emitter.Emit(map[string]any{
				"type":      "status",
				"enrolled":  enrolled,
				"user_id":   a.UserID(),
				"device_id": a.DeviceID(),
				"state_dir": dir,
			})
			return nil
		}
		fmt.Printf("enrolled=%t\nuser_id=%s\ndevice_id=%s\n", enrolled, a.UserID(), a.DeviceID())
		return nil
	case "logout":
		if err := a.Reset(); err != nil {
			return err
		}
		if emitter != nil {
			emitter.Emit(map[string]any{"type": "logout.ok"})
			return nil
		}
		fmt.Println("logged out")
		return nil
	case "login":
		return login(ctx, a, loginOptions{
			token:      *tokenFlag,
			tokenStdin: *tokenStdin,
			in:         os.Stdin,
			emitter:    emitter,
		})
	case "serve":
		if *config == "" || (*lanListen == "" && !*sidecar && (*signalURL == "" || !*relayEnabled)) {
			return errors.New("serve requires -config and an enabled -signal, -lan-listen, or -sidecar")
		}
		if *tokenStdin && *sidecar {
			return errors.New("-token-stdin cannot be combined with -sidecar; send {\"type\":\"auth.token\",\"token\":\"...\"} on stdin or set VANORA_CLIENT_TOKEN")
		}
		tok := strings.TrimSpace(*tokenFlag)
		if *tokenStdin {
			tok, err = readTokenInput("", true, os.Stdin)
			if err != nil {
				return err
			}
		}
		if !*sidecar && *lanListen == "" && (a == nil || (a.UserID() == "" && tok == "")) {
			return errors.New("endpoint not enrolled; run vanora-desktop login or provide -token / VANORA_CLIENT_TOKEN")
		}
		if !*sidecar && *lanListen == "" && tok != "" {
			if a.UserID() == "" {
				enrollCtx, cancelEnroll := context.WithTimeout(ctx, 30*time.Second)
				err = a.Enroll(enrollCtx, tok)
				cancelEnroll()
			} else {
				err = a.UpdateToken(tok)
			}
			if err != nil {
				return err
			}
			tok = ""
		}
		return serve(ctx, a, ca, *signalURL, *name, *config, dir, *sidecar, emitter, accessOptions{
			lanListen: *lanListen, relayEnabled: *relayEnabled, token: tok,
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

func serve(ctx context.Context, a *account.Account, ca ed25519.PublicKey, url, name, path, dir string, sidecar bool, emitter *jsonEmitter, options accessOptions) error {
	cfg, err := desktop.LoadConfig(path)
	if err != nil {
		return err
	}
	if !sidecar && options.lanListen == "" && a != nil && a.UserID() != "" {
		if _, err := guests(cfg, a.UserID()); err != nil {
			return err
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
	access := &accessManager{
		ctx: ctx, account: a, ca: ca, url: url, name: name, service: service,
		dir: dir, emitter: emitter, config: currentConfig.Load, updates: updates,
		retry: make(chan struct{}, 1), relayEnabled: options.relayEnabled && url != "" && a != nil,
		token: options.token, requireHostToken: sidecar,
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
			"type": "ready", "user_id": access.userID(), "device_id": access.deviceID(),
			"name": strings.TrimSpace(name),
		}
		// Watch parent stdin: EOF shuts down the sidecar cleanly so parent exit
		// never leaves an orphaned process. JSONL control commands are also handled.
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
				switch cmd.Type {
				case "shutdown":
					cancel()
					return
				case "reload":
					select {
					case reloadNow <- struct{}{}:
					default:
					}
				case "status":
					emitter.Emit(map[string]any{
						"type": "status", "online": access.online.Load(),
						"user_id": access.userID(), "device_id": access.deviceID(),
					})
				default:
					access.command(cmd)
				}
			}
			cancel()
		}()
		emitter.Emit(ready)
	}
	access.mu.Lock()
	access.startRelay()
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
