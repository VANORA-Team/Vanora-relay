package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClassifyAddressAndRank(t *testing.T) {
	cases := []struct {
		raw      string
		wantAddr string
		wantKind Kind
		wantErr  bool
	}{
		{raw: "127.0.0.1:8443", wantAddr: "127.0.0.1:8443", wantKind: KindLoopback},
		{raw: "[::1]:8443", wantAddr: "[::1]:8443", wantKind: KindLoopback},
		{raw: "192.168.1.42:9000", wantAddr: "192.168.1.42:9000", wantKind: KindLAN},
		{raw: "[fd12:3456::1]:9000", wantAddr: "[fd12:3456::1]:9000", wantKind: KindLAN},
		{raw: "100.64.0.1:9000", wantAddr: "100.64.0.1:9000", wantKind: KindTailnet},
		{raw: "100.100.100.100:9000", wantAddr: "100.100.100.100:9000", wantKind: KindTailnet},
		{raw: "100.127.255.254:9000", wantAddr: "100.127.255.254:9000", wantKind: KindTailnet},
		{raw: "100.128.0.1:9000", wantErr: true},
		{raw: "8.8.8.8:9000", wantErr: true},
		{raw: "0.0.0.0:9000", wantErr: true},
		{raw: "192.168.1.42:0", wantErr: true},
	}
	for _, tc := range cases {
		gotAddr, gotKind, err := ClassifyAddress(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ClassifyAddress(%q) unexpectedly succeeded (%q, %q)", tc.raw, gotAddr, gotKind)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ClassifyAddress(%q) error = %v", tc.raw, err)
		}
		if gotAddr != tc.wantAddr || gotKind != tc.wantKind {
			t.Fatalf("ClassifyAddress(%q) = (%q, %q), want (%q, %q)", tc.raw, gotAddr, gotKind, tc.wantAddr, tc.wantKind)
		}
	}

	if !(Rank(KindLoopback) < Rank(KindLAN) && Rank(KindLAN) < Rank(KindTailnet) && Rank(KindTailnet) < Rank(KindDirect) && Rank(KindDirect) < Rank(KindRelay)) {
		t.Fatal("unexpected route rank order")
	}
}

func TestMergeOrdered(t *testing.T) {
	entries := MergeOrdered(
		"100.90.1.2:8443",
		[]string{"192.168.1.10:8443", "8.8.8.8:8443", "100.90.1.2:8443"},
		"127.0.0.1:8443",
	)
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3: %+v", len(entries), entries)
	}
	if entries[0].Kind != KindLoopback || entries[1].Kind != KindLAN || entries[2].Kind != KindTailnet {
		t.Fatalf("unexpected priority order: %+v", entries)
	}
}

func TestTrackerBackoffCooldownAndTransportHint(t *testing.T) {
	tr := NewTracker()
	base := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	addr := "192.168.1.10:8443"

	if !tr.ShouldProbe(addr, base) {
		t.Fatal("expected initial probe allowed")
	}
	tr.RecordProbeMiss(addr, base)
	if tr.ShouldProbe(addr, base.Add(30*time.Second)) {
		t.Fatal("expected 60s backoff after first miss")
	}
	if !tr.ShouldProbe(addr, base.Add(61*time.Second)) {
		t.Fatal("expected probe allowed after 60s")
	}
	tr.RecordProbeMiss(addr, base.Add(61*time.Second))
	if tr.ShouldProbe(addr, base.Add(150*time.Second)) {
		t.Fatal("expected 120s backoff after second miss")
	}
	tr.Reset()
	if !tr.ShouldProbe(addr, base.Add(150*time.Second)) {
		t.Fatal("expected Reset to clear probe backoff")
	}

	tr.RecordSwitchFailure(addr, base)
	if !tr.InCooldown(addr, base.Add(4*time.Minute)) {
		t.Fatal("expected 5m anti-flap cooldown")
	}
	if tr.InCooldown(addr, base.Add(6*time.Minute)) {
		t.Fatal("expected cooldown expiry after 5m")
	}

	if got := tr.TransportHint(base); got != "direct_preferred" {
		t.Fatalf("initial hint = %q, want direct_preferred", got)
	}
	tr.RecordActivePath("relay", base)
	tr.RecordActivePath("relay", base.Add(30*time.Second))
	tr.RecordActivePath("relay", base.Add(45*time.Second))
	if got := tr.TransportHint(base.Add(time.Minute)); got != "relay_preferred" {
		t.Fatalf("hint after 3 relay fallbacks = %q, want relay_preferred", got)
	}
	tr.RecordActivePath("direct", base.Add(2*time.Minute))
	if got := tr.TransportHint(base.Add(2 * time.Minute)); got != "direct_preferred" {
		t.Fatalf("hint after direct recovery = %q, want direct_preferred", got)
	}
}

func TestProbeSignalHTTPNoRedirect(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("probe") != "1" {
			http.Error(w, "missing probe", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := ProbeSignalHTTP(ctx, srv.URL+"/v1/signal", "secret-token", time.Second); err != nil {
		t.Fatalf("ProbeSignalHTTP valid token error = %v", err)
	}
	if err := ProbeSignalHTTP(ctx, srv.URL+"/v1/signal", "wrong", time.Second); err == nil {
		t.Fatal("expected unauthorized probe error")
	}

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/v1/signal?probe=1", http.StatusFound)
	}))
	defer redirectSrv.Close()
	if err := ProbeSignalHTTP(ctx, redirectSrv.URL+"/v1/signal", "secret-token", time.Second); err == nil {
		t.Fatal("expected redirect to be rejected")
	}
}
