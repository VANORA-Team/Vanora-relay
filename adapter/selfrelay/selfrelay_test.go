package selfrelay_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vanora-relay/adapter/selfrelay"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/ice"
	signalserver "vanora-relay/internal/signal"
)

type memStore struct {
	mu  sync.Mutex
	val string
}

func (m *memStore) Load() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.val, nil
}
func (m *memStore) Save(v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.val = v
	return nil
}

type echoHandler struct {
	mu     sync.Mutex
	opened chan transport.Peer
	inbox  chan []byte
	closed chan string
	echo   bool
}

func newEchoHandler(echo bool) *echoHandler {
	return &echoHandler{
		opened: make(chan transport.Peer, 8),
		inbox:  make(chan []byte, 16),
		closed: make(chan string, 8),
		echo:   echo,
	}
}
func (h *echoHandler) Open(p transport.Peer) { h.opened <- p }
func (h *echoHandler) Message(p transport.Peer, data []byte) {
	cp := append([]byte(nil), data...)
	h.inbox <- cp
	if h.echo {
		_ = p.Send(append([]byte("echo:"), cp...), true)
	}
}
func (h *echoHandler) Closed(p transport.Peer) { h.closed <- p.UserID() }

func TestTargetParseAndFormat(t *testing.T) {
	token := strings.Repeat("t", 40)
	key1, err := selfrelay.LoadClientKey(&memStore{})
	if err != nil {
		t.Fatal(err)
	}
	pair1, err := selfrelay.LoadClientKey(&memStore{})
	if err != nil {
		t.Fatal(err)
	}
	want := selfrelay.Target{
		SignalURL: "wss://relay.example.com/v1/signal",
		Pin:       key1,
		Pair:      pair1,
		Token:     token,
	}
	link := want.Link()
	if !strings.HasPrefix(link, "https://relay.example.com/v1/signal#") || strings.Contains(link, "?") {
		t.Fatalf("unexpected pairing link: %s", link)
	}
	got, err := selfrelay.ParseTarget(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ParseTarget = %+v, want %+v", got, want)
	}

	// Reject plain http on non-loopback host, query params, and wrong mode.
	for _, bad := range []string{
		"http://relay.example.com/v1/signal#mode=self&pin=" + key1,
		"https://relay.example.com/v1/signal?token=leak#mode=self&pin=" + key1,
		"https://relay.example.com/v1/signal#mode=lan&pin=" + key1,
		"https://relay.example.com/v1/signal#mode=self&pin=short",
	} {
		if _, err := selfrelay.ParseTarget(bad); err == nil {
			t.Fatalf("accepted invalid target %q", bad)
		}
	}
}

func TestSelfRelayPairingReconnectAndRevoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	network, err := ice.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()

	relayToken := strings.Repeat("self-secret-", 4)
	hub := signalserver.NewSelfHosted(relayToken, network)
	go hub.Run(ctx)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	signalURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	deskStore := &memStore{}
	deskHandler := newEchoHandler(true)
	server, err := selfrelay.OpenServer(deskStore, deskHandler)
	if err != nil {
		t.Fatal(err)
	}
	onlineCh := make(chan bool, 4)
	server.SetObserver(func(online bool, _ string) {
		select {
		case onlineCh <- online:
		default:
		}
	})
	if err := server.Connect(ctx, signalURL, relayToken, "HomeDesktop"); err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	select {
	case ok := <-onlineCh:
		if !ok {
			t.Fatal("desktop went offline before becoming online")
		}
	case <-ctx.Done():
		t.Fatal("desktop did not come online on self-hosted relay")
	}

	// Wrong relay token fails immediately with ErrUnauthorized.
	phoneAKey, err := selfrelay.LoadClientKey(&memStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := selfrelay.Dial(ctx, selfrelay.Target{
		SignalURL: signalURL,
		Pin:       server.Pin(),
		Token:     strings.Repeat("wrong-token-", 4),
	}, phoneAKey, "PhoneA", newEchoHandler(false)); !errors.Is(err, selfrelay.ErrUnauthorized) {
		t.Fatalf("wrong relay token: got %v, want ErrUnauthorized", err)
	}

	// Unpaired phone fails immediately with ErrUnpaired (not 20s timeout).
	if _, _, err := selfrelay.Dial(ctx, selfrelay.Target{
		SignalURL: signalURL,
		Pin:       server.Pin(),
		Token:     relayToken,
	}, phoneAKey, "PhoneA", newEchoHandler(false)); !errors.Is(err, selfrelay.ErrUnpaired) {
		t.Fatalf("unpaired phone: got %v, want ErrUnpaired", err)
	}

	// Create invitation, revoke it, ensure revoked invite fails.
	inv, revokedLink, err := server.Invite(selfrelay.Read, true)
	if err != nil {
		t.Fatal(err)
	}
	if !server.RevokeInvitation(inv.ID) || server.RevokeInvitation(inv.ID) {
		t.Fatal("unexpected invitation revocation result")
	}
	revokedTarget, err := selfrelay.ParseTarget(revokedLink)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := selfrelay.Dial(ctx, revokedTarget, phoneAKey, "PhoneA", newEchoHandler(false)); !errors.Is(err, selfrelay.ErrUnpaired) {
		t.Fatalf("revoked invite: got %v, want ErrUnpaired", err)
	}

	// Create active control invite and pair PhoneA.
	_, controlLink, err := server.Invite(selfrelay.Control, true)
	if err != nil {
		t.Fatal(err)
	}
	target, err := selfrelay.ParseTarget(controlLink)
	if err != nil {
		t.Fatal(err)
	}
	phoneAHandler := newEchoHandler(false)
	peerA, startA, err := selfrelay.Dial(ctx, target, phoneAKey, "PhoneA", phoneAHandler)
	if err != nil {
		t.Fatalf("PhoneA pairing failed: %v", err)
	}
	startA()
	if err := peerA.Send([]byte("hello-self"), true); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-phoneAHandler.inbox:
		if string(got) != "echo:hello-self" {
			t.Fatalf("unexpected echo %q", got)
		}
	case <-ctx.Done():
		t.Fatal("did not receive echo from desktop")
	}
	deskPeer := <-deskHandler.opened
	if selfrelay.Access(deskPeer.UserID()) != selfrelay.Control {
		t.Fatalf("unexpected desktop peer user id: %q", deskPeer.UserID())
	}

	// One-time invitation cannot be reused by PhoneB.
	phoneBKey, err := selfrelay.LoadClientKey(&memStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := selfrelay.Dial(ctx, target, phoneBKey, "PhoneB", newEchoHandler(false)); !errors.Is(err, selfrelay.ErrUnpaired) {
		t.Fatalf("reused pairing link by PhoneB: got %v, want ErrUnpaired", err)
	}

	// PhoneA disconnects and reconnects without pairing token.
	peerA.Close()
	<-deskHandler.closed
	target.Pair = ""
	phoneAHandler2 := newEchoHandler(false)
	peerA2, startA2, err := selfrelay.Dial(ctx, target, phoneAKey, "PhoneA", phoneAHandler2)
	if err != nil {
		t.Fatalf("PhoneA reconnect failed: %v", err)
	}
	startA2()
	defer peerA2.Close()
	if err := peerA2.Send([]byte("reconnect-ok"), true); err != nil {
		t.Fatal(err)
	}
	if got := string(<-phoneAHandler2.inbox); got != "echo:reconnect-ok" {
		t.Fatalf("unexpected reconnect echo %q", got)
	}

	// Revoke PhoneA on desktop: active peer closes and reconnect is rejected.
	clients := server.Status().Clients
	if len(clients) != 1 || clients[0].Name != "PhoneA" {
		t.Fatalf("unexpected clients: %+v", clients)
	}
	if err := server.RevokeClients(clients[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-phoneAHandler2.closed:
	case <-ctx.Done():
		t.Fatal("revoked peer did not close")
	}
	if _, _, err := selfrelay.Dial(ctx, target, phoneAKey, "PhoneA", newEchoHandler(false)); !errors.Is(err, selfrelay.ErrUnpaired) {
		t.Fatalf("revoked PhoneA reconnected: got %v, want ErrUnpaired", err)
	}
}
