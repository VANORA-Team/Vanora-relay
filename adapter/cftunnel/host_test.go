package cftunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

type connectorStub struct{ stops *atomic.Int32 }

func (c connectorStub) Stop() { c.stops.Add(1) }

func TestHostStartingListeningAndPairedOnlyOffers(t *testing.T) {
	pub, key, device := controlTestIdentity(t)
	visitorPub, visitorKey, visitor := controlTestIdentity(t)
	const scope = "test-scope"
	const hostname = "host.edge.test"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		switch action {
		case "challenge":
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": protocol.NewID(), "expires_at": time.Now().Add(time.Minute)})
		case "status", "origin":
			_ = json.NewEncoder(w).Encode(AllocationView{DeviceID: device, State: "ready", Generation: 2, Incarnation: 1, Hostname: hostname})
		case "token":
			_ = json.NewEncoder(w).Encode(ConnectorToken{Generation: 2, Incarnation: 1, Hostname: hostname,
				TunnelID: "tunnel-id", ConnectorToken: "fixture-connector-secret"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	var host *HostManager
	sent := make(chan protocol.Message, 32)
	connector := make(chan ConnectorOptions, 1)
	var authCalls, stops atomic.Int32
	opts := HostOptions{Channel: "self", Scope: scope, ControlOrigin: server.URL, DeviceID: device, OwnerID: device,
		PrivateKey: key, SelfToken: controlTestToken, PinnedConnector: true, Handler: &testHandler{},
		SendSignal: func(m protocol.Message) error {
			sent <- m
			if m.Type == "tunnel.host" {
				var payload signalBinding
				raw, _ := m.Verify(pub)
				_ = json.Unmarshal(raw, &payload)
				host.HandleSignal(protocol.Message{Type: "tunnel.host.ack", Data: protocol.Encode(map[string]any{
					"runtime_id": payload.RuntimeID, "expires_at": time.Now().Add(45 * time.Second).UTC(),
				})})
			}
			return nil
		},
		StartConnector: func(_ context.Context, opts ConnectorOptions) (ConnectorProcess, error) {
			connector <- opts
			return connectorStub{&stops}, nil
		},
		AuthorizeOffer: func(req OfferRequest) (OfferDecision, error) {
			authCalls.Add(1)
			if req.Principal.DeviceID != visitor || req.Role != "mobile" {
				t.Error("offer authorizer received a different authenticated identity")
			}
			return OfferDecision{UserID: "paired-user", Allows: func() bool { return true }}, nil
		}}
	var err error
	host, err = NewHostManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(host.Stop)
	read := func(kind string) protocol.Message {
		t.Helper()
		select {
		case msg := <-sent:
			if msg.Type != kind {
				t.Fatalf("got %s, want %s", msg.Type, kind)
			}
			return msg
		case <-time.After(3 * time.Second):
			t.Fatalf("did not receive %s", kind)
			return protocol.Message{}
		}
	}
	var starting struct {
		signalBinding
		Phase string `json:"phase"`
	}
	initial := read("tunnel.host")
	raw, _ := initial.Verify(pub)
	if json.Unmarshal(raw, &starting) != nil || !protocol.ValidID(starting.RuntimeID) || starting.Generation != 0 ||
		starting.Incarnation != 0 || starting.Phase != "starting" || initial.Seq != 1 {
		t.Fatal("invalid initial host announcement")
	}
	var process ConnectorOptions
	select {
	case process = <-connector:
	case <-time.After(3 * time.Second):
		t.Fatal("connector was not started")
	}
	if process.PinnedHostname != hostname || process.PinnedOrigin == "" || process.Token != "fixture-connector-secret" {
		t.Fatal("connector did not receive its in-memory credentials and pins")
	}
	process.Observe(ConnectorEvent{State: "ready"})
	listening := read("tunnel.host")
	if listening.Seq != 2 || !host.Status().ConnectorReady {
		t.Fatal("connector readiness was not announced")
	}
	offer := func(binding signalBinding, pairProof, owner string) string {
		t.Helper()
		connID := protocol.NewID()
		connect := protocol.Message{Type: "tunnel.connect", Connection: connID, From: visitor, To: device, Seq: 1}
		if err := connect.Sign(visitorKey, protocol.Encode(connectBody{signalDomain: signalDomain{tunnelAudience, scope},
			ExpectedOwner: owner, TargetPinHash: KeyHash(pub), ClientNonce: protocol.NewID(), PairProof: pairProof})); err != nil {
			t.Fatal(err)
		}
		host.HandleSignal(protocol.Message{Type: "tunnel.offer", Connection: connID, From: visitor, To: device,
			Data: protocol.Encode(struct {
				Connect          protocol.Message `json:"connect"`
				VisitorPublicKey string           `json:"visitor_public_key"`
				signalBinding
				AccessUntil time.Time `json:"access_until"`
			}{connect, base64.RawURLEncoding.EncodeToString(visitorPub), binding, time.Now().Add(9 * time.Second)})})
		return connID
	}
	offer(signalBinding{1, 1, starting.RuntimeID}, "", device)
	offer(signalBinding{2, 1, starting.RuntimeID}, "", "wrong-owner")
	offer(signalBinding{2, 1, starting.RuntimeID}, "invitation-proof", device)
	rejected := read("tunnel.close")
	var denied closeBody
	if !readSigned(rejected, pub, &denied) || denied.Reason != "access_denied" || authCalls.Load() != 0 {
		t.Fatal("replayed, misbound, or invitation-bearing offer reached pairing authorization")
	}
	connection := offer(signalBinding{2, 1, starting.RuntimeID}, "", device)
	msg := read("tunnel.permit")
	var permit permitBody
	if !readSigned(msg, pub, &permit) || msg.Connection != connection || msg.To != visitor ||
		permit.Path != tunnelPath || time.Until(permit.ExpiresAt) > 9*time.Second || authCalls.Load() != 1 {
		t.Fatal("valid paired visitor did not receive a correctly bounded permit")
	}
	process.Observe(ConnectorEvent{State: "exited", Line: "fixture-connector-secret"})
	if msg := read("tunnel.host"); msg.Seq != 3 || host.Status().ConnectorReady {
		t.Fatal("connector exit did not downgrade host")
	}
	host.listener.mu.Lock()
	pending := len(host.listener.pending)
	host.listener.mu.Unlock()
	if pending != 0 {
		t.Fatal("connector exit left pending permits")
	}
	host.Stop()
	stopping := read("tunnel.host")
	if stopping.Seq != 4 || stops.Load() != 1 {
		t.Fatal("host shutdown did not announce and stop its connector")
	}
	status := protocol.Encode(host.Status())
	if strings.Contains(string(status), "fixture-connector-secret") || strings.Contains(string(status), process.PinnedOrigin) {
		t.Fatal("host status exposed connector credentials or origin")
	}
}

func TestVisitorRejectsMisboundPermit(t *testing.T) {
	hostPub, hostKey, host := controlTestIdentity(t)
	visitorPub, _, visitor := controlTestIdentity(t)
	s := &visitorSession{hostID: host, hostKey: hostPub, local: identity.Principal{DeviceID: visitor, PublicKey: visitorPub}, channel: "self",
		domain: signalDomain{tunnelAudience, "scope"}, role: "mobile", connectionID: protocol.NewID(), nonce: protocol.NewID()}
	body := permitBody{signalDomain: s.domain, signalBinding: signalBinding{2, 1, "runtime"}, Hostname: "host.edge.test",
		JTI: protocol.NewID(), ClientNonce: s.nonce, VisitorKeyHash: KeyHash(visitorPub), Path: tunnelPath, ExpiresAt: time.Now().Add(10 * time.Second)}
	permit := protocol.Message{Type: "tunnel.permit", Connection: s.connectionID, From: host, To: visitor, Seq: 1}
	target := func() protocol.Message {
		t.Helper()
		if err := permit.Sign(hostKey, protocol.Encode(body)); err != nil {
			t.Fatal(err)
		}
		return protocol.Message{Type: "tunnel.target", From: host, To: visitor, Connection: s.connectionID,
			Data: protocol.Encode(map[string]any{"permit": permit, "edge_ticket": "edge", "access_until": time.Now().Add(time.Minute)})}
	}
	if _, err := s.targetOptions(target()); err != nil {
		t.Fatal(err)
	}
	body.ClientNonce = "wrong-nonce"
	if _, err := s.targetOptions(target()); err == nil {
		t.Fatal("valid signature authorized a mismatched nonce")
	}
}
