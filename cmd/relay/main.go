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
		return errors.New("RELAY_IDENTITY_PUBLIC_KEY must contain the hex Ed25519 public key from relay-identity keygen")
	}
	billing := &membership.Client{URL: os.Getenv("RELAY_MEMBERSHIP_URL"), Token: os.Getenv("RELAY_MEMBERSHIP_TOKEN")}
	if billing.URL == "" || len(billing.Token) < 32 {
		return errors.New("configure RELAY_MEMBERSHIP_URL and RELAY_MEMBERSHIP_TOKEN (at least 32 characters)")
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
	hub := relay.New(key, billing, network)
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
	log.Printf("Vanora signaling listening on %s", addr)
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
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
