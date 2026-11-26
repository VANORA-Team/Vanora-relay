package cftunnel_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"vanora-relay/internal/cftunnel"
)

func TestAccountPausePersistsAndResumes(t *testing.T) {
	h := newHarness(t, cftunnel.ReaperOff)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "16")
			http.Error(w, "upstream rate limit", 429)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":{"id":"tunnel"}}`)
	}))
	defer server.Close()
	client := testCFClient(t, server, cftunnel.CFClientOptions{})
	clock := func() time.Time { return h.clock }
	rate := cftunnel.RateConfig{PerSecond: 100, Burst: 100, Concurrency: 4}
	metrics := new(cftunnel.Metrics)
	gate := cftunnel.NewGatedCloudflare(client, h.store, h.scope, rate, clock, metrics)
	_, err := gate.GetTunnel(t.Context(), "tunnel")
	if !errors.Is(err, cftunnel.ErrCFRateLimited) || requests.Load() != 1 {
		t.Fatalf("request count %d, rate error %v", requests.Load(), err)
	}
	until, err := h.store.LoadPause(t.Context(), h.scope.ID, h.scope.AccountID)
	check(t, err)
	if until.Sub(h.clock) != 16*time.Second {
		t.Fatalf("persisted pause = %v", until)
	}
	h.clock = h.clock.Add(time.Second)
	second := cftunnel.NewGatedCloudflare(client, h.store, h.scope, rate, clock, nil)
	for _, paused := range []*cftunnel.GatedCloudflare{gate, second} {
		_, err = paused.GetZone(t.Context())
		var rateErr cftunnel.CFRateLimitError
		if !errors.As(err, &rateErr) || rateErr.RetryAfter != 15*time.Second || requests.Load() != 1 {
			t.Fatalf("account pause did not cover DNS token: %+v, requests %d", rateErr, requests.Load())
		}
	}
	h.clock = until
	_, err = gate.GetTunnel(t.Context(), "tunnel")
	check(t, err)
	snapshot := metrics.Snapshot()
	if requests.Load() != 2 || snapshot.CFAPIPausedEventsTotal != 1 || !snapshot.CFAPIPausedUntil.Equal(until) ||
		snapshot.CFAPIRequestsTotal["get_tunnel"]["cf_rate_limited"] != 1 || snapshot.CFAPIRequestsTotal["get_tunnel"]["success"] != 1 ||
		len(snapshot.CFAPIRequestsTotal["get_zone"]) != 0 {
		t.Fatalf("metrics / final requests: %+v, %d", snapshot, requests.Load())
	}
}
