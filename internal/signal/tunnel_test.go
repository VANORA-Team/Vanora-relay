package signal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

type signalTunnelController struct {
	denyRefresh bool
	mintGate    func(context.Context)
}

func (c *signalTunnelController) ScopeID() string { return "test-scope" }
func (c *signalTunnelController) RecordHostPresence(context.Context, identity.Principal, string, string, string, int64, int64, int64, bool) error {
	return nil
}
func (c *signalTunnelController) AuthorizeVisitor(context.Context, TunnelAccessRequest) (string, time.Time, error) {
	return "host.edge.example", time.Now().Add(time.Hour), nil
}
func (c *signalTunnelController) RefreshVisitorAccess(ctx context.Context, req TunnelAccessRequest) (string, time.Time, error) {
	if c.denyRefresh {
		return "", time.Time{}, errors.New("denied")
	}
	return c.AuthorizeVisitor(ctx, req)
}
func (c *signalTunnelController) MintEdgeTicket(ctx context.Context, _ identity.Principal, _, _ int64, _, _ string) (string, error) {
	if c.mintGate != nil {
		c.mintGate(ctx)
	}
	return "", nil
}
func (c *signalTunnelController) ReleasedForOwner(context.Context, identity.Principal, string) bool {
	return false
}

func newTunnelPeer(t *testing.T, h *Hub, role string) (*peer, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	dev := mustSelfDeviceID(t, pub)
	p := &peer{role: role, selfHosted: true, ctx: ctx, cancel: cancel, out: make(chan protocol.Message, 32),
		online: true, grants: make(map[string]bool), id: identity.Principal{DeviceID: dev, PublicKey: pub}}
	h.peers[dev] = p
	return p, priv
}

func TestTunnelPermitRefreshAndRuntimeFencing(t *testing.T) {
	h := NewSelfHosted("", nil)
	ctrl := new(signalTunnelController)
	h.ConfigureTunnel(ctrl)
	host, hostKey := newTunnelPeer(t, h, "desktop")
	visitor, visitorKey := newTunnelPeer(t, h, "mobile")
	host.grants[visitor.id.DeviceID] = true
	domain := tunnelDomain{Audience: tunnelAudience, Scope: ctrl.ScopeID()}
	binding := tunnelSessionBinding{Generation: 5, Incarnation: 2, RuntimeID: "runtime"}
	hostBody := tunnelHostBody{tunnelDomain: domain, SocketID: "socket", RuntimeID: binding.RuntimeID, Phase: "listening",
		Generation: binding.Generation, Incarnation: binding.Incarnation}
	send := func(p *peer, key ed25519.PrivateKey, m protocol.Message, body any) error {
		t.Helper()
		m.From = p.id.DeviceID
		if err := m.Sign(key, protocol.Encode(body)); err != nil {
			t.Fatal(err)
		}
		return h.handle(p, m)
	}
	next := func(p *peer, kind string) protocol.Message {
		t.Helper()
		select {
		case msg := <-p.out:
			if msg.Type != kind {
				t.Fatalf("got %s, want %s", msg.Type, kind)
			}
			return msg
		default:
			t.Fatalf("no %s record", kind)
			return protocol.Message{}
		}
	}
	if err := send(host, hostKey, protocol.Message{Type: "tunnel.host", Seq: 1}, hostBody); err != nil {
		t.Fatal(err)
	}
	next(host, "tunnel.host.ack")
	now := time.Now()
	if !h.HasActiveTunnelRuntime(host.id.DeviceID, tunnelKeyHash(host.id.PublicKey), "runtime", now) ||
		h.HasActiveTunnelRuntime(host.id.DeviceID, tunnelKeyHash(visitor.id.PublicKey), "runtime", now) ||
		h.HasActiveTunnelRuntime(host.id.DeviceID, tunnelKeyHash(host.id.PublicKey), "runtime", now.Add(time.Minute)) {
		t.Fatal("runtime binding or expiration failed")
	}
	if err := send(host, hostKey, protocol.Message{Type: "tunnel.host", Seq: 1}, hostBody); err == nil {
		t.Fatal("host sequence replay accepted")
	}
	id := protocol.NewID()
	connect := tunnelConnectBody{tunnelDomain: domain, ExpectedOwner: host.id.DeviceID, TargetPinHash: tunnelKeyHash(host.id.PublicKey), ClientNonce: "nonce"}
	connectRecord := protocol.Message{Type: "tunnel.connect", Connection: id, To: host.id.DeviceID, Seq: 1}
	if err := send(visitor, visitorKey, connectRecord, connect); err != nil {
		t.Fatal(err)
	}
	offer := next(host, "tunnel.offer")
	var wrapped struct {
		Connect     protocol.Message `json:"connect"`
		VisitorKey  string           `json:"visitor_public_key"`
		AccessUntil time.Time        `json:"access_until"`
	}
	if err := json.Unmarshal(offer.Data, &wrapped); err != nil || wrapped.VisitorKey == "" || wrapped.AccessUntil.After(time.Now().Add(time.Minute)) {
		t.Fatalf("invalid offer: %s (%v)", offer.Data, err)
	}
	if _, err := wrapped.Connect.Verify(visitor.id.PublicKey); err != nil {
		t.Fatal(err)
	}
	permit := tunnelPermitBody{tunnelDomain: domain, tunnelSessionBinding: binding, Hostname: "host.edge.example",
		JTI: "ticket", ClientNonce: "wrong", VisitorKeyHash: tunnelKeyHash(visitor.id.PublicKey), Path: tunnelPath,
		ExpiresAt: time.Now().Add(10 * time.Second)}
	permitRecord := protocol.Message{Type: "tunnel.permit", Connection: id, To: visitor.id.DeviceID, Seq: 1}
	if err := send(host, hostKey, permitRecord, permit); err == nil {
		t.Fatal("mismatched nonce accepted")
	}
	permit.ClientNonce = connect.ClientNonce
	if err := send(host, hostKey, permitRecord, permit); err != nil {
		t.Fatal(err)
	}
	next(visitor, "tunnel.target")
	refresh := tunnelRefreshBody{tunnelDomain: domain, tunnelSessionBinding: binding, JTI: permit.JTI}
	refreshRecord := protocol.Message{Type: "tunnel.refresh", Connection: id, To: host.id.DeviceID, Seq: 2}
	if err := send(visitor, visitorKey, refreshRecord, refresh); err == nil {
		t.Fatal("early refresh accepted")
	}
	h.tunnelSessions[id].lastRefresh = time.Now().Add(-time.Minute)
	if err := send(visitor, visitorKey, refreshRecord, refresh); err != nil {
		t.Fatal(err)
	}
	next(visitor, "tunnel.access")
	next(host, "tunnel.access")
	h.tunnelSessions[id].lastRefresh = time.Now().Add(-time.Minute)
	ctrl.denyRefresh = true
	refreshRecord.Seq++
	if err := send(visitor, visitorKey, refreshRecord, refresh); err != nil {
		t.Fatal(err)
	}
	next(visitor, "tunnel.close")
	next(host, "tunnel.close")
	if h.tunnelSessions[id] != nil {
		t.Fatal("revoked session remained active")
	}
	connectRecord.Connection = protocol.NewID()
	if err := send(visitor, visitorKey, connectRecord, connect); err != nil {
		t.Fatal(err)
	}
	next(host, "tunnel.offer")
	hostBody.Phase = "stopping"
	if err := send(host, hostKey, protocol.Message{Type: "tunnel.host", Seq: 2}, hostBody); err != nil {
		t.Fatal(err)
	}
	next(host, "tunnel.close")
	next(host, "tunnel.host.ack")
	next(visitor, "tunnel.close")
}

func TestTunnelConcurrentPermitRejected(t *testing.T) {
	h := NewSelfHosted("", nil)
	started := make(chan struct{})
	release := make(chan struct{})
	ctrl := &signalTunnelController{mintGate: func(ctx context.Context) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
		}
	}}
	h.ConfigureTunnel(ctrl)
	host, hostKey := newTunnelPeer(t, h, "desktop")
	visitor, visitorKey := newTunnelPeer(t, h, "mobile")
	host.grants[visitor.id.DeviceID] = true
	domain := tunnelDomain{Audience: tunnelAudience, Scope: ctrl.ScopeID()}
	binding := tunnelSessionBinding{Generation: 1, Incarnation: 1, RuntimeID: "runtime"}
	sign := func(p *peer, key ed25519.PrivateKey, m protocol.Message, body any) protocol.Message {
		m.From = p.id.DeviceID
		if err := m.Sign(key, protocol.Encode(body)); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if err := h.handle(host, sign(host, hostKey, protocol.Message{Type: "tunnel.host", Seq: 1}, tunnelHostBody{
		tunnelDomain: domain, SocketID: "socket", RuntimeID: "runtime", Phase: "listening", Generation: 1, Incarnation: 1,
	})); err != nil {
		t.Fatal(err)
	}
	<-host.out
	id := protocol.NewID()
	if err := h.handle(visitor, sign(visitor, visitorKey, protocol.Message{Type: "tunnel.connect", Connection: id, To: host.id.DeviceID, Seq: 1},
		tunnelConnectBody{tunnelDomain: domain, ExpectedOwner: host.id.DeviceID, TargetPinHash: tunnelKeyHash(host.id.PublicKey), ClientNonce: "nonce"})); err != nil {
		t.Fatal(err)
	}
	<-host.out
	permitBody := tunnelPermitBody{tunnelDomain: domain, tunnelSessionBinding: binding, Hostname: "host.edge.example",
		JTI: "ticket-1", ClientNonce: "nonce", VisitorKeyHash: tunnelKeyHash(visitor.id.PublicKey), Path: tunnelPath,
		ExpiresAt: time.Now().Add(10 * time.Second)}
	first := sign(host, hostKey, protocol.Message{Type: "tunnel.permit", Connection: id, To: visitor.id.DeviceID, Seq: 1}, permitBody)
	permitBody.JTI = "ticket-2"
	second := sign(host, hostKey, protocol.Message{Type: "tunnel.permit", Connection: id, To: visitor.id.DeviceID, Seq: 2}, permitBody)
	firstDone := make(chan error, 1)
	go func() { firstDone <- h.handle(host, first) }()
	<-started
	if err := h.handle(host, second); err == nil {
		t.Fatal("concurrent duplicate tunnel.permit was accepted")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if msg := <-visitor.out; msg.Type != "tunnel.target" {
		t.Fatalf("got %s, want tunnel.target", msg.Type)
	}
	select {
	case extra := <-visitor.out:
		t.Fatalf("unexpected extra message: %s", extra.Type)
	default:
	}
}
