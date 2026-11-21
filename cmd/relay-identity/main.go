// Command relay-identity runs Vanora's independent endpoint certificate
// authority, or generates its Ed25519 signing key.
//
// The signing key is held only by this service. Clients and the relay only
// ever see the public key.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"vanora-relay/internal/identity"
)

const (
	defaultAddr   = "127.0.0.1:8090"
	shutdownGrace = 10 * time.Second
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "relay-identity:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError("missing subcommand")
	}
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:])
	case "serve":
		return runServe(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return nil
	default:
		return usageError(fmt.Sprintf("unknown subcommand %q", args[0]))
	}
}

const usage = `usage:
  relay-identity keygen [-out FILE] [-public-out FILE]
      Generate the Ed25519 signing key pair. The private key file holds a
      32-byte hex seed and must stay on the identity host.

  relay-identity serve
      Run the certificate authority. Configure it with the
      VANORA_IDENTITY_* environment variables documented in
      internal/identity/README.md.

  relay-identity -h
      Show this help.
`

func usageError(message string) error {
	return fmt.Errorf("%s\n\n%s", message, usage)
}

func runKeygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	out := flags.String("out", "identity-signing-key", "private key file to create")
	publicOut := flags.String("public-out", "identity-signing-key.pub", "public key file to create")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return usageError("keygen takes no positional arguments")
	}
	if *out == "" || *publicOut == "" {
		return usageError("key files cannot be empty paths")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	seed := privateKey.Seed()
	if err := writeNewFile(*out, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeNewFile(*publicOut, []byte(hex.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	fmt.Printf("private key: %s\npublic key:  %s\npublic key (hex): %s\n",
		*out, *publicOut, hex.EncodeToString(publicKey))
	return nil
}

func writeNewFile(path string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	return file.Close()
}

type serveConfig struct {
	addr           string
	keyFile        string
	issuer         string
	clientID       string
	clientSecret   string
	redirectURI    string
	redirectURIs   []string
	scopes         []string
	certTTL        time.Duration
	challengeTTL   time.Duration
	leaseTTL       time.Duration
	tlsCertFile    string
	tlsKeyFile     string
	allowPlain     bool
	disableRefresh bool
}

func runServe(args []string) error {
	if len(args) != 0 {
		return usageError("serve takes no arguments")
	}
	cfg, err := loadServeConfig()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	keyBytes, err := os.ReadFile(cfg.keyFile)
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}
	privateKey, err := identity.ParseSigningKey(keyBytes)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	signer, err := identity.NewSigner(privateKey, cfg.certTTL)
	if err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	server, err := identity.NewServer(identity.Config{
		OIDCIssuer:       cfg.issuer,
		OIDCClientID:     cfg.clientID,
		OIDCClientSecret: cfg.clientSecret,
		OIDCRedirectURI:  cfg.redirectURI,
		OIDCRedirectURIs: cfg.redirectURIs,
		OIDCScopes:       cfg.scopes,
		DisableRefresh:   cfg.disableRefresh,
		Signer:           signer,
		ChallengeTTL:     cfg.challengeTTL,
		LeaseTTL:         cfg.leaseTTL,
		Logger:           logger,
	})
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		var listenErr error
		if cfg.tlsCertFile != "" {
			httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			listenErr = httpServer.ListenAndServeTLS(cfg.tlsCertFile, cfg.tlsKeyFile)
		} else {
			listenErr = httpServer.ListenAndServe()
		}
		if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			errCh <- listenErr
		}
	}()

	logger.Info("identity authority listening",
		"addr", cfg.addr,
		"tls", cfg.tlsCertFile != "",
		"issuer", cfg.issuer,
		"key_id", signer.KeyID(),
		"public_key", hex.EncodeToString(signer.PublicKey()))

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("identity authority stopped")
	return nil
}

func loadServeConfig() (serveConfig, error) {
	var cfg serveConfig
	var errs []string

	cfg.addr = envOr("VANORA_IDENTITY_ADDR", defaultAddr)
	cfg.keyFile = os.Getenv("VANORA_IDENTITY_SIGNING_KEY_FILE")
	cfg.issuer = os.Getenv("VANORA_IDENTITY_OIDC_ISSUER")
	cfg.clientID = os.Getenv("VANORA_IDENTITY_OIDC_CLIENT_ID")
	cfg.clientSecret = os.Getenv("VANORA_IDENTITY_OIDC_CLIENT_SECRET")
	cfg.redirectURI = strings.TrimSpace(os.Getenv("VANORA_IDENTITY_OIDC_REDIRECT_URI"))
	cfg.redirectURIs = splitList(os.Getenv("VANORA_IDENTITY_OIDC_REDIRECT_URIS"))
	cfg.tlsCertFile = os.Getenv("VANORA_IDENTITY_TLS_CERT")
	cfg.tlsKeyFile = os.Getenv("VANORA_IDENTITY_TLS_KEY")
	cfg.scopes = splitList(os.Getenv("VANORA_IDENTITY_OIDC_SCOPES"))
	cfg.allowPlain = envBool(os.Getenv("VANORA_IDENTITY_ALLOW_PLAINTEXT"))
	cfg.disableRefresh = envBool(os.Getenv("VANORA_IDENTITY_DISABLE_REFRESH"))
	cfg.certTTL = envDuration("VANORA_IDENTITY_CERT_TTL")
	cfg.challengeTTL = envDuration("VANORA_IDENTITY_CHALLENGE_TTL")
	cfg.leaseTTL = envDuration("VANORA_IDENTITY_LEASE_TTL")

	if cfg.keyFile == "" {
		errs = append(errs, "VANORA_IDENTITY_SIGNING_KEY_FILE is required")
	}
	if cfg.issuer == "" {
		errs = append(errs, "VANORA_IDENTITY_OIDC_ISSUER is required")
	}
	if cfg.clientID == "" {
		errs = append(errs, "VANORA_IDENTITY_OIDC_CLIENT_ID is required")
	}
	if cfg.redirectURI == "" && len(cfg.redirectURIs) == 0 {
		errs = append(errs, "VANORA_IDENTITY_OIDC_REDIRECT_URI or VANORA_IDENTITY_OIDC_REDIRECT_URIS is required")
	}
	if (cfg.tlsCertFile == "") != (cfg.tlsKeyFile == "") {
		errs = append(errs, "VANORA_IDENTITY_TLS_CERT and VANORA_IDENTITY_TLS_KEY must be set together")
	}
	if cfg.tlsCertFile == "" && !cfg.allowPlain && !isLoopbackAddr(cfg.addr) {
		errs = append(errs, "refusing to listen without TLS on a non-loopback address; set TLS cert/key or VANORA_IDENTITY_ALLOW_PLAINTEXT=1 behind a trusted proxy")
	}
	if len(errs) > 0 {
		return cfg, errors.New(strings.Join(errs, "; "))
	}
	return cfg, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envDuration(key string) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return -1
	}
	return value
}

func splitList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			out = append(out, field)
		}
	}
	return out
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
