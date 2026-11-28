package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vanora-relay/internal/cftunnel"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/membership"
	relay "vanora-relay/internal/signal"
)

func run() error {
	channel, err := relay.ParseChannel(os.Getenv("RELAY_CHANNEL"))
	if err != nil {
		return err
	}
	tunnelCfg, err := cftunnel.ConfigFromEnv(cftunnel.Channel(channel), os.Getenv)
	if err != nil {
		return err
	}
	maxSlots, err := relayIntConfig("RELAY_MAX_SLOTS", 0, 0)
	if err != nil {
		return err
	}
	workers, err := relayIntConfig("RELAY_TUNNEL_WORKERS", defaultTunnelWorkers(tunnelCfg.Store), 16)
	if err != nil {
		return err
	}
	drainTimeout := 3 * time.Second
	if raw := strings.TrimSpace(os.Getenv("RELAY_SHUTDOWN_DRAIN")); raw != "" {
		drainTimeout, err = time.ParseDuration(raw)
		if err != nil || drainTimeout < 0 {
			return errors.New("RELAY_SHUTDOWN_DRAIN must be a nonnegative duration")
		}
	}
	var (
		key           ed25519.PublicKey
		keys          []ed25519.PublicKey
		allowedIssuer string
		entitlement   relay.EntitlementVerifier
		selfToken     string
	)
	if channel.IsSelfHosted() {
		if strings.TrimSpace(os.Getenv("RELAY_IDENTITY_PUBLIC_KEY")) != "" || strings.TrimSpace(os.Getenv("RELAY_IDENTITY_PUBLIC_KEYS")) != "" {
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
		keys, err = identityPublicKeysConfig()
		if err != nil {
			return err
		}
		key = keys[0]
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	member, _ := entitlement.(*membership.Client)
	handler, closeServer, err := buildServer(context.Background(), tunnelCfg, relayStartup{
		key: key, keys: keys, allowedIssuer: allowedIssuer, selfToken: selfToken, membership: member,
		pushURL: strings.TrimSpace(os.Getenv("RELAY_PUSH_WEBHOOK_URL")), pushToken: strings.TrimSpace(os.Getenv("RELAY_PUSH_WEBHOOK_TOKEN")),
		metricsToken: strings.TrimSpace(os.Getenv("RELAY_METRICS_TOKEN")), maxSlots: maxSlots, workers: workers, startupCtx: ctx,
	})
	if err != nil {
		return err
	}
	defer closeServer()
	server := http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	served := make(chan error, 1)
	slog.Info("Vanora signaling listening", "channel", channel, "addr", addr)
	go func() {
		if cert != "" {
			served <- server.ListenAndServeTLS(cert, keyfile)
		} else {
			served <- server.ListenAndServe()
		}
	}()
	select {
	case err = <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	drain, finishDrain := context.WithTimeout(context.Background(), drainTimeout)
	handler.drain(drain)
	finishDrain()
	handler.cancel()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		slog.Warn("HTTP server shutdown timed out", "error", err)
		_ = server.Close()
	}
	return nil
}

func relayIntConfig(name string, fallback, upper int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || upper > 0 && value > upper {
		if upper > 0 {
			return 0, fmt.Errorf("%s must be between 1 and %d", name, upper)
		}
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
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

const defaultMembershipCacheTTL = 15 * time.Second

func identityPublicKeysConfig() ([]ed25519.PublicKey, error) {
	rawMulti := strings.TrimSpace(os.Getenv("RELAY_IDENTITY_PUBLIC_KEYS"))
	rawSingle := strings.TrimSpace(os.Getenv("RELAY_IDENTITY_PUBLIC_KEY"))
	raw := rawMulti
	if raw == "" {
		raw = rawSingle
	} else if rawSingle != "" {
		raw = rawSingle + "," + rawMulti
	}
	keys, err := identity.ParsePublicKeys([]byte(raw))
	if err != nil || len(keys) == 0 {
		return nil, errors.New("RELAY_IDENTITY_PUBLIC_KEY (or RELAY_IDENTITY_PUBLIC_KEYS) must contain one or more Ed25519 public keys (hex or base64) of the site's identity authority")
	}
	return keys, nil
}

func membershipCacheTTLConfig() (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv("RELAY_MEMBERSHIP_CACHE_TTL"))
	if raw == "" {
		return defaultMembershipCacheTTL, nil
	}
	if raw == "0" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl < 0 || ttl > 5*time.Minute {
		return 0, errors.New("RELAY_MEMBERSHIP_CACHE_TTL must be 0 or a duration up to 5m")
	}
	return ttl, nil
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
	cacheTTL, err := membershipCacheTTLConfig()
	if err != nil {
		return nil, err
	}
	return &membership.Client{URL: rawURL, Token: token, CacheTTL: cacheTTL}, nil
}

func main() {
	if err := run(); err != nil {
		slog.Error("relay stopped", "error", err)
		os.Exit(1)
	}
}
