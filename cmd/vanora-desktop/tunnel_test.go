package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vanora-relay/adapter/cftunnel"
	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

type sidecarTunnelConnector struct{}

func (sidecarTunnelConnector) Stop() {}

func TestSidecarTunnelCommandsAndRedaction(t *testing.T) {
	const token = "connector-token-visible-only-in-test"
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := identity.SelfDeviceID(pub)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	emitter := &jsonEmitter{out: &output}
	manager := &accessManager{ctx: t.Context(), emitter: emitter, tunnelPinned: true}
	defer manager.close()
	var stateMu sync.Mutex
	allocation := cftunnel.AllocationView{DeviceID: device, State: "suspended", Generation: 1, Incarnation: 1,
		Hostname: "sidecar.edge.test", ManualResumeRequired: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		action := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if strings.Contains(r.URL.Path, "/operations/") {
			now := time.Now()
			_ = json.NewEncoder(w).Encode(cftunnel.OperationView{ID: action, Type: action,
				Generation: allocation.Generation, CreatedAt: now, CompletedAt: &now})
			return
		}
		switch action {
		case "challenge":
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": protocol.NewID(), "expires_at": time.Now().Add(time.Minute)})
		case "status":
			_ = json.NewEncoder(w).Encode(allocation)
		case "resume", "disconnect", "deprovision":
			allocation.Generation++
			switch action {
			case "resume":
				allocation.State, allocation.ManualResumeRequired = "ready", false
			case "disconnect":
				allocation.State, allocation.ManualResumeRequired = "suspended", true
			case "deprovision":
				allocation.State, allocation.ManualResumeRequired, allocation.Hostname = "disabled", false, ""
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(cftunnel.OperationView{ID: action, Type: action,
				Generation: allocation.Generation, CreatedAt: time.Now()})
		case "token":
			_ = json.NewEncoder(w).Encode(cftunnel.ConnectorToken{Generation: allocation.Generation, Incarnation: allocation.Incarnation,
				Hostname: allocation.Hostname, TunnelID: "tunnel-id", ConnectorToken: token})
		default:
			t.Errorf("unexpected management path %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	var origin string
	manager.setTunnelSession(&tunnelSession{ctx: t.Context(), channel: "self", options: func(context.Context) (cftunnel.HostOptions, error) {
		return cftunnel.HostOptions{Channel: "self", Scope: "test-scope", ControlOrigin: server.URL, DeviceID: device,
			OwnerID: device, PrivateKey: key, SelfToken: strings.Repeat("relay-fixture", 4), Handler: noopHandler{},
			SendSignal: func(m protocol.Message) error {
				var host struct {
					RuntimeID string `json:"runtime_id"`
				}
				raw, _ := m.Verify(pub)
				_ = json.Unmarshal(raw, &host)
				manager.selfTunnelSession().routeSignal(protocol.Message{Type: "tunnel.host.ack", Data: protocol.Encode(map[string]any{
					"runtime_id": host.RuntimeID, "expires_at": time.Now().Add(45 * time.Second),
				})})
				return nil
			},
			AuthorizeOffer: func(cftunnel.OfferRequest) (cftunnel.OfferDecision, error) { return cftunnel.OfferDecision{}, nil },
			StartConnector: func(_ context.Context, opts cftunnel.ConnectorOptions) (cftunnel.ConnectorProcess, error) {
				origin = opts.PinnedOrigin
				opts.Observe(cftunnel.ConnectorEvent{State: "ready", Line: token + " " + origin})
				return sidecarTunnelConnector{}, nil
			},
		}, nil
	}})
	enabled, disabled := true, false
	manager.command(accessCommand{Type: "access.tunnel.status", RequestID: "off"})
	manager.command(accessCommand{Type: "access.tunnel.set", RequestID: "enable", Enabled: &enabled})
	deadline := time.Now().Add(3 * time.Second)
	for {
		status := manager.tunnelStatus()
		if status.State == "suspended" && status.ManualResumeRequired && !status.ConnectorReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("suspended tunnel did not wait for explicit resume: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	manager.command(accessCommand{Type: "access.tunnel.resume", RequestID: "resume"})
	manager.command(accessCommand{Type: "access.tunnel.disconnect", RequestID: "disconnect"})
	manager.command(accessCommand{Type: "access.tunnel.deprovision", RequestID: "deprovision"})
	manager.command(accessCommand{Type: "access.tunnel.set", RequestID: "disable", Enabled: &disabled})
	if origin == "" {
		t.Fatal("test connector did not start with a pinned origin")
	}
	emitter.mu.Lock()
	raw := bytes.Clone(output.Bytes())
	emitter.mu.Unlock()
	for _, value := range []string{token, origin, "connector_token", "tunnel_secret", `"origin"`, `"certificate"`, `"lease"`} {
		if bytes.Contains(raw, []byte(value)) {
			t.Fatal("sidecar emitted a private tunnel field")
		}
	}
	expect := map[string]string{"off": "disabled", "enable": "", "resume": "ready", "disconnect": "suspended",
		"deprovision": "disabled", "disable": "disabled"}
	transitions, accessStatus := 0, 0
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		var event struct {
			Type      string              `json:"type"`
			RequestID string              `json:"request_id"`
			Tunnel    cftunnel.HostStatus `json:"tunnel"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Type == "tunnel.status" && event.RequestID == "" {
			transitions++
		}
		if event.Type == "access.status" && event.Tunnel.State != "" {
			accessStatus++
		}
		if want, ok := expect[event.RequestID]; ok {
			if event.Type == "access.error" || want != "" && event.Tunnel.State != want {
				t.Fatalf("command %s produced %s, state %s", event.RequestID, event.Type, event.Tunnel.State)
			}
			if event.RequestID == "resume" && !event.Tunnel.ConnectorReady ||
				event.RequestID == "disconnect" && !event.Tunnel.ManualResumeRequired {
				t.Fatalf("unexpected tunnel status after %s", event.RequestID)
			}
			delete(expect, event.RequestID)
		}
	}
	if len(expect) != 0 || transitions == 0 || accessStatus == 0 {
		t.Fatalf("missing command replies or transition events: %v", expect)
	}
}
