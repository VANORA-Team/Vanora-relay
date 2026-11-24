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
	channel, err := relay.ParseChannel(os.Getenv("RELAY_CHANNEL"))
	if err != nil {
		return err
	}
	var (
		key           ed25519.PublicKey
		allowedIssuer string
		entitlement   relay.EntitlementVerifier
		selfToken     string
	)
	if channel.IsSelfHosted() {
		if strings.TrimSpace(os.Getenv("RELAY_IDENTITY_PUBLIC_KEY")) != "" {
			return errors.New("RELAY_IDENTITY_PUBLIC_KEY must not be set with RELAY_CHANNEL=self (self-hosted nodes authenticate locally with RELAY_SELF_TOKEN and device pairing)")
		}
		if strings.TrimSpace(os.Getenv("RELAY_ALLOWED_ISSUER")) != "" {
			return errors.New("RELAY_ALLOWED_ISSUER must not be set with RELAY_CHANNEL=self")
		}
		if _, err := entitlementVerifier(channel); err != nil {
			return err
		}
		selfToken, err = selfAccessToken(channel)
		if err != nil {
			return err
		}
	} else {
		key, err = identity.ParsePublicKey([]byte(strings.TrimSpace(os.Getenv("RELAY_IDENTITY_PUBLIC_KEY"))))
		if err != nil || len(key) != ed25519.PublicKeySize {
			return errors.New("RELAY_IDENTITY_PUBLIC_KEY must contain the Ed25519 public key (hex or base64) of the site's identity authority")
		}
		allowedIssuer, err = allowedIssuerConfig(channel)
		if err != nil {
			return err
		}
		entitlement, err = entitlementVerifier(channel)
		if err != nil {
			return err
		}
		if _, err := selfAccessToken(channel); err != nil {
			return err
		}
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
	var hub *relay.Hub
	if channel.IsSelfHosted() {
		hub = relay.NewSelfHosted(selfToken, network)
	} else {
		hub = relay.New(key, entitlement, network)
		if allowedIssuer != "" {
			hub.RequireIssuer(allowedIssuer)
		}
	}
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

// selfAccessToken returns the bearer token required on /v1/signal for a
// self-hosted node. Official nodes must not configure one: their access is
// governed by site entitlement, not a shared secret.
func selfAccessToken(channel relay.Channel) (string, error) {
	token := os.Getenv("RELAY_SELF_TOKEN")
	if channel.ChecksEntitlement() {
		if token != "" {
			return "", errors.New("RELAY_SELF_TOKEN is only valid with RELAY_CHANNEL=self")
		}
		return "", nil
	}
	if len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("RELAY_CHANNEL=self requires RELAY_SELF_TOKEN (32-512 bytes without whitespace)")
	}
	return token, nil
}

// allowedIssuerConfig validates optional RELAY_ALLOWED_ISSUER on official
// channels to enforce defense-in-depth site isolation alongside per-site CA
// keys. Self-hosted nodes must not configure it.
func allowedIssuerConfig(channel relay.Channel) (string, error) {
	issuer := strings.TrimSpace(os.Getenv("RELAY_ALLOWED_ISSUER"))
	if issuer == "" {
		return "", nil
	}
	if channel.IsSelfHosted() {
		return "", errors.New("RELAY_ALLOWED_ISSUER must not be set with RELAY_CHANNEL=self")
	}
	if err := identity.ValidateIssuerURL(issuer); err != nil {
		return "", fmt.Errorf("invalid RELAY_ALLOWED_ISSUER: %w", err)
	}
	return issuer, nil
}

// entitlementVerifier builds the single-site entitlement check for an official
// channel. CN nodes consult only the CN membership service, GLOBAL nodes
// consult only the GLOBAL membership service, and cross-site membership
// variables fail fast at startup. Self-hosted nodes must not configure any
// membership variables.
func entitlementVerifier(channel relay.Channel) (relay.EntitlementVerifier, error) {
	cnURL, cnToken := os.Getenv("RELAY_CN_MEMBERSHIP_URL"), os.Getenv("RELAY_CN_MEMBERSHIP_TOKEN")
	globalURL, globalToken := os.Getenv("RELAY_GLOBAL_MEMBERSHIP_URL"), os.Getenv("RELAY_GLOBAL_MEMBERSHIP_TOKEN")
	legacyURL, legacyToken := os.Getenv("RELAY_MEMBERSHIP_URL"), os.Getenv("RELAY_MEMBERSHIP_TOKEN")

	if !channel.ChecksEntitlement() {
		if cnURL != "" || cnToken != "" || globalURL != "" || globalToken != "" || legacyURL != "" || legacyToken != "" {
			return nil, errors.New("membership variables must not be set with RELAY_CHANNEL=self")
		}
		return nil, nil
	}

	urlVar, tokenVar := "RELAY_CN_MEMBERSHIP_URL", "RELAY_CN_MEMBERSHIP_TOKEN"
	otherSite, otherURLVar, otherTokenVar := "GLOBAL", "RELAY_GLOBAL_MEMBERSHIP_URL", "RELAY_GLOBAL_MEMBERSHIP_TOKEN"
	rawURL, token := cnURL, cnToken
	otherURL, otherToken := globalURL, globalToken
	if channel == relay.ChannelGlobal {
		urlVar, tokenVar = "RELAY_GLOBAL_MEMBERSHIP_URL", "RELAY_GLOBAL_MEMBERSHIP_TOKEN"
		otherSite, otherURLVar, otherTokenVar = "CN", "RELAY_CN_MEMBERSHIP_URL", "RELAY_CN_MEMBERSHIP_TOKEN"
		rawURL, token = globalURL, globalToken
		otherURL, otherToken = cnURL, cnToken
	}

	if otherURL != "" || otherToken != "" {
		return nil, fmt.Errorf("RELAY_CHANNEL=%s must not configure %s membership variables (%s/%s); CN and GLOBAL entitlements are isolated", channel, otherSite, otherURLVar, otherTokenVar)
	}
	if (legacyURL == "") != (legacyToken == "") {
		return nil, errors.New("configure both RELAY_MEMBERSHIP_URL and RELAY_MEMBERSHIP_TOKEN, or neither")
	}
	if rawURL == "" && token == "" {
		rawURL, token = legacyURL, legacyToken
	}
	if rawURL == "" && token == "" {
		return nil, fmt.Errorf("RELAY_CHANNEL=%s requires %s and %s (legacy RELAY_MEMBERSHIP_URL/RELAY_MEMBERSHIP_TOKEN also works)", channel, urlVar, tokenVar)
	}
	if rawURL == "" || len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
		return nil, fmt.Errorf("%s and %s must both be set; the token needs at least 32 bytes without whitespace", urlVar, tokenVar)
	}
	return &membership.Client{URL: rawURL, Token: token}, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
