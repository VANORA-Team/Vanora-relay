package cftunnel

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vanora-relay/internal/membership"
)

func TestPreflightEdgeCanary(t *testing.T) {
	for _, status := range []int{101, 200, 302, 401, 403, 404, 500, 530} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
				if r.Method != http.MethodGet || r.URL.RequestURI() != edgeWebSocketPath || len(key) != 16 || err != nil ||
					r.Header.Get("Sec-WebSocket-Version") != "13" || r.Header.Get("Connection") != "Upgrade" ||
					r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Authorization") != "" || r.Header.Get("Vanora-Edge-Ticket") != "" {
					t.Error("unexpected canary request")
				}
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(status)
			}))
			defer server.Close()
			service := Service{cfg: Config{Mode: ModeManaged, EdgeCanaryHost: "canary.example.org"}, edgeCanaryOrigin: server.URL}
			err := service.PreflightEdgeCanary(t.Context(), server.Client())
			if (err == nil) != (status == 401 || status == 403) {
				t.Fatalf("canary status %d returned %v", status, err)
			}
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }))
	defer server.Close()
	service := Service{cfg: Config{Mode: ModeManaged, EdgeCanaryHost: "canary.example.org"}, edgeCanaryOrigin: server.URL}
	if err := service.PreflightEdgeCanary(t.Context(), nil); err == nil {
		t.Fatal("untrusted TLS canary passed")
	}
	service.cfg.Mode = ModeDrain
	if err := service.PreflightEdgeCanary(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestEntitlementWindowDualGrants(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	capUntil := now.Add(time.Minute)
	shortExp := now.Add(10 * time.Second).Unix()
	longExp := now.Add(45 * time.Second)
	yes := true

	// Free owner with unbounded TunnelAllowed and a soon-expiring RelayAllowed must not be prematurely cut at 10s.
	ownerEnt := membership.Entitlement{RelayAllowed: true, ValidUntil: now.Add(10 * time.Second), TunnelAllowed: &yes}
	if got := ownerEntitlementWindow(capUntil, now, ownerEnt); !got.Equal(capUntil) {
		t.Fatalf("owner unbounded tunnel grant clamped to %v, want %v", got, capUntil)
	}
	if got := visitorEntitlementWindow(capUntil, now, ownerEnt, true); !got.Equal(capUntil) {
		t.Fatalf("same-owner unbounded tunnel grant clamped to %v, want %v", got, capUntil)
	}

	// Paid guest with 45s relay validity and a shorter 10s TunnelValidUntil keeps the 45s relay window.
	paidGuest := membership.Entitlement{RelayAllowed: true, ValidUntil: longExp, TunnelValidUntil: &shortExp}
	if got := visitorEntitlementWindow(capUntil, now, paidGuest, false); !got.Equal(longExp) {
		t.Fatalf("paid guest window = %v, want %v", got, longExp)
	}

	// Explicit time-bounded tunnel-only owner is clamped to TunnelValidUntil.
	boundedOwner := membership.Entitlement{TunnelAllowed: &yes, TunnelValidUntil: &shortExp}
	if got := ownerEntitlementWindow(capUntil, now, boundedOwner); !got.Equal(time.Unix(shortExp, 0)) {
		t.Fatalf("bounded owner window = %v, want %v", got, time.Unix(shortExp, 0))
	}
}
