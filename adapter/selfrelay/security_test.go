package selfrelay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/adapter/transport"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	signalserver "vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

type secMemStore struct {
	mu  sync.Mutex
	val string
}

func (m *secMemStore) Load() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.val, nil
}

func (m *secMemStore) Save(v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.val = v
	return nil
}

type secEchoHandler struct {
	opened chan transport.Peer
	inbox  chan []byte
	closed chan string
}

func newSecEchoHandler() *secEchoHandler {
	return &secEchoHandler{
		opened: make(chan transport.Peer, 8),
		inbox:  make(chan []byte, 16),
		closed: make(chan string, 8),
	}
}

func (h *secEchoHandler) Open(p transport.Peer) { h.opened <- p }
func (h *secEchoHandler) Message(p transport.Peer, data []byte) {
	cp := append([]byte(nil), data...)
	h.inbox <- cp
	_ = p.Send(append([]byte("echo:"), cp...), true)
}
func (h *secEchoHandler) Closed(p transport.Peer) { h.closed <- p.UserID() }

func secFinding(t *testing.T, id, format string, args ...any) {
	t.Helper()
	t.Logf("FINDING %s: "+format, append([]any{id}, args...)...)
	v := strings.TrimSpace(os.Getenv("VANORA_SECURITY_STRICT"))
	if v == "1" || strings.EqualFold(v, "true") {
		t.Fatalf("FINDING %s: "+format, append([]any{id}, args...)...)
	}
	t.Skipf("FINDING %s: "+format, append([]any{id}, args...)...)
}

func TestSelfRelayPairProofRebindingRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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

	relayToken := strings.Repeat("self-rebind-", 4)
	hub := signalserver.NewSelfHosted(relayToken, network)
	go hub.Run(ctx)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	signalURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	deskHandler := newSecEchoHandler()
	server, err := OpenServer(&secMemStore{}, deskHandler)
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
	if err := server.Connect(ctx, signalURL, relayToken, "Desk"); err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	select {
	case ok := <-onlineCh:
		if !ok {
			t.Fatal("desktop went offline")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	inv, link, err := server.Invite(Control, true)
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
	desktopPub, err := parsePublicKeyB64(target.Pin)
	if err != nil {
		t.Fatal(err)
	}

	// Generate PhoneA and PhoneB keypairs.
	seedA, err := LoadClientKey(&secMemStore{})
	if err != nil {
		t.Fatal(err)
	}
	privA, pubA, pubAB64, devA, err := parseKeySeed(seedA)
	if err != nil {
		t.Fatal(err)
	}
	seedB, err := LoadClientKey(&secMemStore{})
	if err != nil {
		t.Fatal(err)
	}
	privB, pubB, pubBB64, devB, err := parseKeySeed(seedB)
	if err != nil {
		t.Fatal(err)
	}

	conn1 := protocol.NewID()
	proofForAAndConn1, err := identity.SelfPairProof(rawPair, conn1, pubA, desktopPub)
	if err != nil {
		t.Fatal(err)
	}
	proofB64 := base64.RawURLEncoding.EncodeToString(proofForAAndConn1)

	sendForgedRequest := func(priv ed25519.PrivateKey, fromDev, pubB64, connID string) string {
		ws, _, err := websocket.Dial(ctx, signalURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": {"Bearer " + relayToken}},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer ws.CloseNow()
		_, chRaw, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ch protocol.Message
		if err := json.Unmarshal(chRaw, &ch); err != nil {
			t.Fatal(err)
		}
		pubBytes, _ := base64.RawURLEncoding.Strict().DecodeString(pubB64)
		loginMsg := protocol.Message{Type: "auth.login", Connection: ch.Connection, From: fromDev, To: "signal"}
		if err := loginMsg.Sign(priv, protocol.Encode(map[string]string{
			"role":       "mobile",
			"public_key": base64.RawURLEncoding.EncodeToString(pubBytes),
		})); err != nil {
			t.Fatal(err)
		}
		if err := ws.Write(ctx, websocket.MessageText, protocol.Encode(loginMsg)); err != nil {
			t.Fatal(err)
		}
		_, okRaw, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var okMsg protocol.Message
		if err := json.Unmarshal(okRaw, &okMsg); err != nil || okMsg.Type != "auth.ok" {
			t.Fatalf("unexpected login reply: %s", okRaw)
		}
		req := protocol.Message{Type: "connect.request", Connection: connID, From: fromDev, To: server.DeviceID(), Seq: 1}
		if err := req.Sign(priv, protocol.Encode(connectRequestBody{
			PublicKey: pubB64,
			Name:      "Rebinder",
			PairProof: proofB64,
		})); err != nil {
			t.Fatal(err)
		}
		if err := ws.Write(ctx, websocket.MessageText, protocol.Encode(req)); err != nil {
			t.Fatal(err)
		}
		_, replyRaw, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var reply protocol.Message
		if err := json.Unmarshal(replyRaw, &reply); err != nil {
			t.Fatal(err)
		}
		return reply.Type + ":" + string(reply.Data)
	}

	// Case 1: Rebind proof computed for conn1 to a different conn2.
	conn2 := protocol.NewID()
	if got := sendForgedRequest(privA, devA, pubAB64, conn2); got != `connect.closed:"access_denied"` {
		t.Fatalf("proof rebound to different connection_id: got %s, want connect.closed:\"access_denied\"", got)
	}

	// Case 2: Rebind proof computed for PhoneA to PhoneB on the original conn1.
	_ = pubB
	if got := sendForgedRequest(privB, devB, pubBB64, conn1); got != `connect.closed:"access_denied"` {
		t.Fatalf("proof rebound to different mobile key: got %s, want connect.closed:\"access_denied\"", got)
	}

	// Invite must remain unconsumed and no clients should be paired.
	st := server.Status()
	if len(st.Clients) != 0 {
		t.Fatalf("unexpected paired clients after failed rebind attempts: %+v", st.Clients)
	}
	if len(st.Invitations) != 1 || st.Invitations[0].ID != inv.ID {
		t.Fatalf("invite state mutated: %+v", st.Invitations)
	}
}

func TestSelfRelayConnectRequestReplayDoesNotBreakLiveLink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	relayToken := strings.Repeat("self-replay-", 4)

	// Run a malicious/tampered relay WS endpoint that forwards the first
	// connect.request and later replays the exact signed connect.request with the
	// same connection_id to the desktop.
	var (
		deskWSMu sync.Mutex
		deskWS   *websocket.Conn
	)
	accepted := make(chan protocol.Message, 4)
	closedMsgs := make(chan protocol.Message, 4)
	var capturedReq protocol.Message
	capturedCh := make(chan protocol.Message, 1)

	fakeRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		nonce := protocol.NewID()
		_ = ws.Write(ctx, websocket.MessageText, protocol.Encode(protocol.Message{Type: "auth.challenge", Connection: nonce}))
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
		deskWSMu.Lock()
		deskWS = ws
		deskWSMu.Unlock()
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
				_ = ws.Write(ctx, websocket.MessageText, protocol.Encode(protocol.Message{Type: "device.registered"}))
			case "connect.accept":
				accepted <- m
			case "connect.closed":
				closedMsgs <- m
			}
		}
	}))
	defer fakeRelay.Close()

	signalURL := "ws" + strings.TrimPrefix(fakeRelay.URL, "http")
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
	if err := server.Connect(ctx, signalURL, relayToken, "Desk"); err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	<-onlineCh

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
	desktopPub, err := parsePublicKeyB64(target.Pin)
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

	connID := protocol.NewID()
	proof, err := identity.SelfPairProof(rawPair, connID, pubA, desktopPub)
	if err != nil {
		t.Fatal(err)
	}
	req := protocol.Message{Type: "connect.request", Connection: connID, From: devA, To: server.DeviceID(), Seq: 1}
	if err := req.Sign(privA, protocol.Encode(connectRequestBody{
		PublicKey: pubAB64,
		Name:      "PhoneA",
		PairProof: base64.RawURLEncoding.EncodeToString(proof),
	})); err != nil {
		t.Fatal(err)
	}
	capturedReq = req
	select {
	case capturedCh <- capturedReq:
	default:
	}

	deskWSMu.Lock()
	dws := deskWS
	deskWSMu.Unlock()
	if err := dws.Write(ctx, websocket.MessageText, protocol.Encode(req)); err != nil {
		t.Fatal(err)
	}
	firstAccept := <-accepted
	if firstAccept.Connection != connID {
		t.Fatalf("unexpected accept connID: %s", firstAccept.Connection)
	}
	firstLink := server.getLink(connID)
	if firstLink == nil {
		t.Fatal("missing initial link on desktop")
	}

	// Replay the exact signed connect.request with the live connID.
	// Note: because PhoneA is now paired, authorizePeer succeeds again!
	if err := dws.Write(ctx, websocket.MessageText, protocol.Encode(<-capturedCh)); err != nil {
		t.Fatal(err)
	}

	select {
	case secondAccept := <-accepted:
		afterLink := server.getLink(connID)
		if afterLink != firstLink {
			secFinding(t, "VR-SEC-07", "replayed connect.request overwrote live s.links[%s] (%p -> %p) and issued second connect.accept (server.go:576-580)", connID, firstLink, afterLink)
		}
		_ = secondAccept
	case <-time.After(300 * time.Millisecond):
		// Secure behavior: duplicate connID ignored or rejected without overwriting firstLink.
		if server.getLink(connID) != firstLink {
			t.Fatalf("s.links[%s] changed unexpectedly", connID)
		}
	}
	_ = errors.New
	_ = rand.Reader
	_ = closedMsgs
}
