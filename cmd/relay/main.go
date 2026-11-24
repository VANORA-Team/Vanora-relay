package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/membership"
	relay "vanora-relay/internal/signal"
)

func run() error {
	key, err := identity.ParsePublicKey([]byte(strings.TrimSpace(os.Getenv("RELAY_IDENTITY_PUBLIC_KEY"))))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("RELAY_IDENTITY_PUBLIC_KEY must contain the Ed25519 public key (hex or base64) of the identity authority")
	}
	channel, err := relay.ParseChannel(os.Getenv("RELAY_CHANNEL"))
	if err != nil {
		return err
	}
	entitlement, err := entitlementVerifier(channel)
	if err != nil {
		return err
	}
	addr := os.Getenv("RELAY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8787"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	cert, keyfile := os.Getenv("RELAY_TLS_CERT"), os.Getenv("RELAY_TLS_KEY")
	if (cert == "") != (keyfile == "") {
		return errors.New("configure both TLS files")
	}
	if cert == "" && !net.ParseIP(host).IsLoopback() && !strings.EqualFold(host, "localhost") {
		return errors.New("use TLS on public listeners or a TLS reverse proxy to loopback")
	}
	network, err := ice.FromEnv()
	if err != nil {
		return fmt.Errorf("start STUN/TURN: %w", err)
	}
	defer network.Close()
	hub := relay.New(key, entitlement, network)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go hub.Run(ctx)
	mux := http.NewServeMux()
	mux.Handle("GET /v1/signal", hub)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})
	server := http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("Vanora signaling (%s channel) listening on %s", channel, addr)
	if cert != "" {
		err = server.ListenAndServeTLS(cert, keyfile)
	} else {
		err = server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// entitlementVerifier builds the entitlement check for an official channel.
// Each site's service is configured independently: accounts sign in on one site
// but may use a relay in either region, so the node checks every site it knows.
// A self-hosted node checks nothing.
func entitlementVerifier(channel relay.Channel) (relay.EntitlementVerifier, error) {
	if !channel.ChecksEntitlement() {
		return nil, nil
	}
	ownSite := "CN"
	if channel == relay.ChannelGlobal {
		ownSite = "GLOBAL"
	}
	legacyURL, legacyToken := os.Getenv("RELAY_MEMBERSHIP_URL"), os.Getenv("RELAY_MEMBERSHIP_TOKEN")
	if (legacyURL == "") != (legacyToken == "") {
		return nil, errors.New("configure both RELAY_MEMBERSHIP_URL and RELAY_MEMBERSHIP_TOKEN, or neither")
	}
	var sites membership.Sites
	seen := make(map[string]bool, 2)
	for _, site := range []struct{ name, urlVar, tokenVar string }{
		{"CN", "RELAY_CN_MEMBERSHIP_URL", "RELAY_CN_MEMBERSHIP_TOKEN"},
		{"GLOBAL", "RELAY_GLOBAL_MEMBERSHIP_URL", "RELAY_GLOBAL_MEMBERSHIP_TOKEN"},
	} {
		rawURL, token := os.Getenv(site.urlVar), os.Getenv(site.tokenVar)
		if rawURL == "" && token == "" && site.name == ownSite {
			rawURL, token = legacyURL, legacyToken
		}
		if rawURL == "" && token == "" {
			continue
		}
		if rawURL == "" || len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
			return nil, fmt.Errorf("%s and %s must both be set; the token needs at least 32 bytes without whitespace", site.urlVar, site.tokenVar)
		}
		if seen[rawURL] {
			continue
		}
		seen[rawURL] = true
		sites = append(sites, &membership.Client{URL: rawURL, Token: token})
	}
	if len(sites) == 0 {
		return nil, fmt.Errorf("RELAY_CHANNEL=%s requires RELAY_%s_MEMBERSHIP_URL and RELAY_%s_MEMBERSHIP_TOKEN (legacy RELAY_MEMBERSHIP_URL/RELAY_MEMBERSHIP_TOKEN also works)", channel, ownSite, ownSite)
	}
	return sites, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
