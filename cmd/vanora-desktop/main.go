package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
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

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 || args[0] != "serve" && args[0] != "login" {
		return errors.New("usage: vanora-desktop login|serve -identity URL -ca PUBLIC_KEY_FILE [-signal WSS_URL -config FILE -name NAME -state-dir DIR]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	identityURL := fs.String("identity", "", "identity authority URL")
	caFile := fs.String("ca", "", "pinned identity public key file")
	root := fs.String("state-dir", "", "profile directory (defaults to user config)")
	signalURL := fs.String("signal", "", "full relay WebSocket URL")
	config := fs.String("config", "", "local Vanora session and permission config")
	hostname, _ := os.Hostname()
	name := fs.String("name", hostname, "published desktop name")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *identityURL == "" || *caFile == "" {
		return errors.New("identity URL and pinned public key file required")
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
	pub, err := os.ReadFile(*caFile)
	if err != nil {
		return err
	}
	ca, err := identity.ParsePublicKey(pub)
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
	if args[0] == "login" {
		return login(ctx, a)
	}
	if *config == "" || *signalURL == "" {
		return errors.New("serve requires -signal and -config")
	}
	if a.UserID() == "" {
		return errors.New("run vanora-desktop login for this profile first")
	}
	return serve(ctx, a, ca, *signalURL, *name, *config, dir)
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
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	slices.Sort(out)
	return out, nil
}
func serve(ctx context.Context, a *account.Account, ca ed25519.PublicKey, url, name, path, dir string) error {
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
	source := &authority{account: a, adapter: service, ca: ca}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
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
				fail <- e
				cancel()
				return
			}
			prev = b
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
				log.Printf("desktop online: %s", a.DeviceID())
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
		if e != nil {
			log.Printf("desktop offline: %v", e)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		delay = min(delay*2, 10*time.Second)
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
