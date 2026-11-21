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
	if len(args) == 0 {
		return errors.New("usage: vanora-desktop login|serve|whoami|status|logout [-identity URL -ca PUBLIC_KEY_FILE|-ca-hex HEX -signal WSS_URL -config FILE -name NAME -state-dir DIR -token TOKEN|-token-stdin -sidecar -json]")
	}
	cmd := args[0]
	switch cmd {
	case "login", "serve", "whoami", "status", "logout":
	default:
		return errors.New("usage: vanora-desktop login|serve|whoami|status|logout [-identity URL -ca PUBLIC_KEY_FILE|-ca-hex HEX -signal WSS_URL -config FILE -name NAME -state-dir DIR -token TOKEN|-token-stdin -sidecar -json]")
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	identityURL := fs.String("identity", envOrDefault("VANORA_RELAY_IDENTITY_URL", defaultIdentityURL), "identity authority URL")
	caFile := fs.String("ca", "", "pinned identity public key file")
	caHexFlag := fs.String("ca-hex", envOrDefault("VANORA_RELAY_CA_PUBLIC_KEY", defaultCAHex), "pinned identity public key (hex or base64)")
	root := fs.String("state-dir", "", "profile directory (defaults to user config)")
	signalURL := fs.String("signal", envOrDefault("VANORA_RELAY_SIGNAL_URL", defaultSignalURL), "full relay WebSocket URL")
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
	if fs.NArg() != 0 || strings.TrimSpace(*identityURL) == "" || (strings.TrimSpace(*caFile) == "" && strings.TrimSpace(*caHexFlag) == "") {
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

	var pubRaw []byte
	if strings.TrimSpace(*caFile) != "" {
		pubRaw, err = os.ReadFile(*caFile)
		if err != nil {
			return err
		}
	} else {
		pubRaw = []byte(strings.TrimSpace(*caHexFlag))
	}
	ca, err := identity.ParsePublicKey(pubRaw)
	if err != nil {
		return err
	}
	caHex := hex.EncodeToString(ca)
	a, err := account.New(*identityURL, caHex, openVault(dir, *identityURL, caHex))
	if err != nil {
		return err
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
		if *config == "" || strings.TrimSpace(*signalURL) == "" {
			return errors.New("serve requires -signal and -config")
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
		if tok != "" {
			if a.UserID() == "" {
				enrollCtx, cancelEnroll := context.WithTimeout(ctx, 30*time.Second)
				err = a.Enroll(enrollCtx, tok)
				cancelEnroll()
				if err != nil {
					return err
				}
			} else if err = a.UpdateToken(tok); err != nil {
				return err
			}
		}
		if a.UserID() == "" {
			return errors.New("endpoint not enrolled; run vanora-desktop login or provide -token / VANORA_CLIENT_TOKEN")
		}
		return serve(ctx, a, ca, strings.TrimSpace(*signalURL), *name, *config, dir, *sidecar, emitter)
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
		if s.Owner != owner {
			return nil, fmt.Errorf("session %q must belong to this desktop account", s.ID)
		}
		for _, g := range s.Users {
			if g.UserID != owner && (g.Read || g.Tools) {
				seen[g.UserID] = true
			}
		}
	}
	for _, w := range cfg.Workspaces {
		if w.Owner != owner {
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

func serve(ctx context.Context, a *account.Account, ca ed25519.PublicKey, url, name, path, dir string, sidecar bool, emitter *jsonEmitter) error {
	cfg, err := desktop.LoadConfig(path)
	if err != nil {
		return err
	}
	allowed, err := guests(cfg, a.UserID())
	if err != nil {
		return err
	}
	service, err := desktop.New(cfg, filepath.Join(dir, "sessions"))
	if err != nil {
		return err
	}
	defer service.Close()
	if emitter != nil {
		service.SetObserver(emitter.Emit)
	}
	source := &authority{account: a, adapter: service, ca: ca}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()

	var statusMu sync.Mutex
	onlineState := false
	setOnline := func(v bool, reason string) {
		statusMu.Lock()
		onlineState = v
		statusMu.Unlock()
		if emitter != nil {
			if v {
				emitter.Emit(map[string]any{
					"type":      "online",
					"device_id": a.DeviceID(),
					"user_id":   a.UserID(),
					"name":      strings.TrimSpace(name),
				})
			} else {
				emitter.Emit(map[string]any{
					"type":      "offline",
					"device_id": a.DeviceID(),
					"error":     reason,
				})
			}
		}
	}

	reloadNow := make(chan struct{}, 1)
	retryNow := make(chan struct{}, 1)
	// Keep checking local ACL independently of a stalled WebSocket, enrollment service or ICE path.
	updates := make(chan []string, 1)
	fail := make(chan error, 1)
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
			var list []string
			if e == nil {
				next, e = desktop.ParseConfig(b)
			}
			if e == nil {
				list, e = guests(next, a.UserID())
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
			if emitter != nil {
				emitter.Emit(map[string]any{"type": "config.reloaded"})
			}
			select {
			case <-updates:
			default:
			}
			select {
			case updates <- list:
			case <-ctx.Done():
				return
			}
		}
	}()

	if sidecar {
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
				var cmd struct {
					Type  string `json:"type"`
					Token string `json:"token"`
				}
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
				case "auth.token":
					if err := a.UpdateToken(cmd.Token); err != nil {
						emitter.Emit(map[string]any{"type": "auth.error", "error": err.Error()})
					} else {
						emitter.Emit(map[string]any{"type": "auth.ok"})
						select {
						case retryNow <- struct{}{}:
						default:
						}
					}
				case "status":
					statusMu.Lock()
					on := onlineState
					statusMu.Unlock()
					emitter.Emit(map[string]any{
						"type":      "status",
						"online":    on,
						"user_id":   a.UserID(),
						"device_id": a.DeviceID(),
					})
				}
			}
			cancel()
		}()
		emitter.Emit(map[string]any{
			"type":      "ready",
			"user_id":   a.UserID(),
			"device_id": a.DeviceID(),
			"name":      strings.TrimSpace(name),
		})
	}

	for delay := time.Second; ctx.Err() == nil; {
		s, e := transport.Dial(ctx, url, "desktop", source, service)
		if e == nil {
			select {
			case allowed = <-updates:
			default:
			}
			e = publish(ctx, s, name, allowed)
			if e == nil {
				delay = time.Second
				setOnline(true, "")
				if emitter == nil {
					log.Printf("desktop online: %s", a.DeviceID())
				}
			online:
				for {
					select {
					case <-ctx.Done():
						break online
					case <-s.Done():
						break online
					case allowed = <-updates:
						if e = publish(ctx, s, name, allowed); e != nil {
							break online
						}
					}
				}
			}
			s.Close()
		}
		if ctx.Err() != nil {
			break
		}
		reason := ""
		if e != nil {
			reason = e.Error()
		}
		setOnline(false, reason)
		if emitter != nil && e != nil && isAuthRequiredError(e) {
			emitter.Emit(map[string]any{"type": "auth.required", "error": reason})
		}
		if emitter == nil && e != nil {
			log.Printf("desktop offline: %v", e)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-retryNow:
			timer.Stop()
			delay = time.Second
		case <-timer.C:
			delay = min(delay*2, 10*time.Second)
		}
	}
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
