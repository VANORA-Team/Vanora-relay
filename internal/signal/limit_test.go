package signal

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestTokenLockoutRejectsCorrectToken(t *testing.T) {
	h := NewSelfHosted("correct-token", nil)
	h.ConfigureClientIP(func(r *http.Request) string { return r.Header.Get("X-Test-Client") })
	probe := func(ip, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/signal?probe=1", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Test-Client", ip)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, req)
		return response
	}
	for range tokenFailThreshold {
		probe("192.0.2.1", "incorrect-token")
	}
	if res := probe("192.0.2.1", "correct-token"); res.Code != http.StatusTooManyRequests || res.Header().Get("Retry-After") == "" {
		t.Fatalf("locked client got %d, Retry-After=%q", res.Code, res.Header().Get("Retry-After"))
	}
	if res := probe("192.0.2.2", "correct-token"); res.Code != http.StatusNoContent {
		t.Fatalf("unlocked client got %d", res.Code)
	}
}

func TestTokenLockoutBackoffCapsAndDoesNotWrap(t *testing.T) {
	gate := newUnauthGate()
	now := time.Now()
	ip := "192.0.2.1"
	for _, want := range []time.Duration{
		15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
		5 * time.Minute, 5 * time.Minute, 5 * time.Minute,
	} {
		for range tokenFailThreshold {
			gate.recordTokenFailure(ip, now)
		}
		if got := gate.lockRemaining(ip, now); got != want {
			t.Fatalf("lockout = %s, want %s", got, want)
		}
		now = now.Add(want)
	}
}

func TestUnauthGateEvictsOnlyLeastRecentlySeen(t *testing.T) {
	gate := newUnauthGate()
	now := time.Now()
	for index := range gateMaxEntries {
		gate.allowRequest(strconv.Itoa(index), now)
	}
	for range tokenFailThreshold {
		gate.recordTokenFailure("0", now)
	}
	gate.allowRequest("new", now)
	if len(gate.byIP) != gateMaxEntries || gate.byIP["1"] != nil || !gate.tokenLocked("0", now) {
		t.Fatal("full gate did not retain recently used entries while admitting a new IP")
	}
}
