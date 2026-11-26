package selfrelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

// selfRelayHarness drives the desktop server against a fake relay WS
// endpoint the test fully controls, mirroring the signal contract the
// production relay enforces.
type selfRelayHarness struct {
	ctx    context.Context
	cancel context.CancelFunc
	fake   *httptest.Server

	deskWSMu sync.Mutex
	deskWS   *websocket.Conn
	accepted chan protocol.Message
	closed   chan protocol.Message
}

func startSelfRelayHarness(t *testing.T) *selfRelayHarness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	h := &selfRelayHarness{
		ctx:      ctx,
		cancel:   cancel,
		accepted: make(chan protocol.Message, 16),
		closed:   make(chan protocol.Message, 16),
	}
	h.fake = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		nonce := protocol.NewID()
		_ = ws.Write(ctx, websocket.MessageText, protocol.Encode(protocol.Message{
			Type: "auth.challenge", Connection: nonce,
		}))
		_, loginRaw, err := ws.Read(ctx)
		if err != nil {
			return
		}
		var login protocol.Message
		if json.Unmarshal(loginRaw, &login) != nil {
			return
		}
		_ = ws.Write(ctx, websocket.MessageText, protocol.Encode(protocol.Message{
			Type: "auth.ok",
			Data: protocol.Encode(map[string]string{"device_id": login.From, "mode": "self"}),
		}))
		h.deskWSMu.Lock()
		h.deskWS = ws
		h.deskWSMu.Unlock()
		for {
			_, raw, err := ws.Read(ctx)
			if err != nil {
				return
			}
			var m protocol.Message
			if json.Unmarshal(raw, &m) != nil {
				continue
			}
			switch m.Type {
			case "device.online":
				_ = ws.Write(ctx, websocket.MessageText, protocol.Encode(protocol.Message{
					Type: "device.registered",
				}))
			case "connect.accept":
				select {
				case h.accepted <- m:
				default:
				}
			case "connect.close":
				select {
				case h.closed <- m:
				default:
				}
			}
		}
	}))
	t.Cleanup(func() {
		h.fake.Close()
		h.cancel()
	})
	return h
}

func (h *selfRelayHarness) signalURL() string {
	return "ws" + strings.TrimPrefix(h.fake.URL, "http")
}

func (h *selfRelayHarness) write(t *testing.T, m protocol.Message) {
	t.Helper()
	h.deskWSMu.Lock()
	ws := h.deskWS
	h.deskWSMu.Unlock()
	if ws == nil {
		t.Fatal("desktop websocket not connected")
	}
	if err := ws.Write(h.ctx, websocket.MessageText, protocol.Encode(m)); err != nil {
		t.Fatalf("write %s: %v", m.Type, err)
	}
}

func (h *selfRelayHarness) waitAccept(t *testing.T, connID string) {
	t.Helper()
	for {
		select {
		case m := <-h.accepted:
			if m.Connection == connID {
				return
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no connect.accept for %s", connID)
		case <-h.ctx.Done():
			t.Fatal("context expired waiting for accept")
		}
	}
}

// TestSelfRelayCapsConcurrentLinksPerClient guards the per-client
// concurrent link cap: one paired phone cannot fan out unbounded
// peerLink objects (each holding a WebRTC PeerConnection) by issuing
// a stream of distinct connect.request ids (LAN2 from the blue-team
// Phase 1 audit).
func TestSelfRelayCapsConcurrentLinksPerClient(t *testing.T) {
	h := startSelfRelayHarness(t)
	ctx := h.ctx

	server, err := OpenServer(&secMemStore{}, newSecEchoHandler())
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
	if err := server.Connect(ctx, h.signalURL(), strings.Repeat("lan2-relay-tok", 4), "Desk"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	select {
	case <-onlineCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not come online")
	}

	_, link, err := server.Invite(Control, true)
	if err != nil {
		t.Fatal(err)
	}
	target, err := ParseTarget(link)
	if err != nil {
		t.Fatal(err)
	}
	rawPair, err := base64.RawURLEncoding.Strict().DecodeString(target.Pair)
	if err != nil {
		t.Fatal(err)
	}
	deskPub, err := parsePublicKeyB64(target.Pin)
	if err != nil {
		t.Fatal(err)
	}
	seedA, err := LoadClientKey(&secMemStore{})
	if err != nil {
		t.Fatal(err)
	}
	privA, pubA, pubAB64, devA, err := parseKeySeed(seedA)
	if err != nil {
		t.Fatal(err)
	}

	// Pair the phone with a proof-carrying first connect.request.
	connID := protocol.NewID()
	proof, err := identity.SelfPairProof(rawPair, connID, pubA, deskPub)
	if err != nil {
		t.Fatal(err)
	}
	pairReq := protocol.Message{
		Type: "connect.request", Connection: connID,
		From: devA, To: server.DeviceID(), Seq: 1,
	}
	if err := pairReq.Sign(privA, protocol.Encode(connectRequestBody{
		PublicKey: pubAB64,
		Name:      "PhoneA",
		PairProof: base64.RawURLEncoding.EncodeToString(proof),
	})); err != nil {
		t.Fatal(err)
	}
	h.write(t, pairReq)
	h.waitAccept(t, connID)

	// Now issue fresh connection ids from the same (already paired)
	// client key until the cap must refuse further links.
	var rejected bool
	accepts := 0
	for i := 0; i < maxPeerLinksPerClient+2; i++ {
		id := protocol.NewID()
		req := protocol.Message{
			Type: "connect.request", Connection: id,
			From: devA, To: server.DeviceID(), Seq: 1,
		}
		if err := req.Sign(privA, protocol.Encode(connectRequestBody{
			PublicKey: pubAB64,
			Name:      "PhoneA",
		})); err != nil {
			t.Fatal(err)
		}
		h.write(t, req)
		select {
		case m := <-h.accepted:
			accepts++
			if m.Connection != id {
				t.Fatalf("unexpected accept %s", m.Connection)
			}
		case m := <-h.closed:
			if m.Connection != id {
				t.Fatalf("unexpected close %s", m.Connection)
			}
			rejected = true
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d: neither accepted nor rejected", i)
		}
	}
	if accepts < maxPeerLinksPerClient-1 {
		t.Fatalf("cap engaged too early: only %d extra links accepted before rejection", accepts)
	}
	if !rejected {
		t.Fatalf("paired client opened at least %d concurrent links without any rejection", maxPeerLinksPerClient+2)
	}
	server.mu.Lock()
	live := len(server.links)
	server.mu.Unlock()
	if live > maxPeerLinksPerClient {
		t.Fatalf("server holds %d live links, cap is %d", live, maxPeerLinksPerClient)
	}
}

// TestSelfRelaySeenConnWindowStaysBounded guards the replay-dedup
// window: after thousands of churned links the window must evict the
// oldest ids instead of resetting wholesale (LAN3), so an old captured
// connect.request cannot replay a second time after the window wraps.
func TestSelfRelaySeenConnWindowStaysBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("churn test skipped in -short mode")
	}
	h := startSelfRelayHarness(t)
	ctx := h.ctx

	server, err := OpenServer(&secMemStore{}, newSecEchoHandler())
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
	if err := server.Connect(ctx, h.signalURL(), strings.Repeat("lan3-relay-tok", 4), "Desk"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	select {
	case <-onlineCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not come online")
	}

	_, link, err := server.Invite(Control, true)
	if err != nil {
		t.Fatal(err)
	}
	target, err := ParseTarget(link)
	if err != nil {
		t.Fatal(err)
	}
	rawPair, err := base64.RawURLEncoding.Strict().DecodeString(target.Pair)
	if err != nil {
		t.Fatal(err)
	}
	deskPub, err := parsePublicKeyB64(target.Pin)
	if err != nil {
		t.Fatal(err)
	}
	seedA, err := LoadClientKey(&secMemStore{})
	if err != nil {
		t.Fatal(err)
	}
	privA, pubA, pubAB64, devA, err := parseKeySeed(seedA)
	if err != nil {
		t.Fatal(err)
	}

	// Pair once.
	firstID := protocol.NewID()
	proof, err := identity.SelfPairProof(rawPair, firstID, pubA, deskPub)
	if err != nil {
		t.Fatal(err)
	}
	pairReq := protocol.Message{
		Type: "connect.request", Connection: firstID,
		From: devA, To: server.DeviceID(), Seq: 1,
	}
	if err := pairReq.Sign(privA, protocol.Encode(connectRequestBody{
		PublicKey: pubAB64,
		Name:      "PhoneA",
		PairProof: base64.RawURLEncoding.EncodeToString(proof),
	})); err != nil {
		t.Fatal(err)
	}
	h.write(t, pairReq)
	h.waitAccept(t, firstID)

	// Churn links well past the dedup window, closing each one so the
	// per-client concurrent cap never triggers.
	total := maxSeenConns + 16
	for i := 0; i < total; i++ {
		id := protocol.NewID()
		req := protocol.Message{
			Type: "connect.request", Connection: id,
			From: devA, To: server.DeviceID(), Seq: 1,
		}
		if err := req.Sign(privA, protocol.Encode(connectRequestBody{
			PublicKey: pubAB64,
			Name:      "PhoneA",
		})); err != nil {
			t.Fatal(err)
		}
		h.write(t, req)
		h.waitAccept(t, id)
		if l := server.getLink(id); l != nil {
			l.close(nil, false)
		}
	}

	server.mu.Lock()
	entry := server.running
	var window int
	if entry != nil {
		window = len(entry.seenConns)
	}
	server.mu.Unlock()
	if entry == nil {
		t.Fatal("relay connection lost during churn")
	}
	if window > maxSeenConns {
		t.Fatalf("replay window grew to %d entries, cap is %d (wholesale reset defense broken)", window, maxSeenConns)
	}
}
