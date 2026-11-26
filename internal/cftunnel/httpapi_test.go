package cftunnel_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vanora-relay/internal/cftunnel"
	"vanora-relay/internal/identity"
)

func bodyDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func TestSelfTunnelHTTPLifecycle(t *testing.T) {
	h := newHarness(t, cftunnel.ReaperOff)
	key, private, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	device, err := identity.SelfDeviceID(key)
	check(t, err)
	h.cfg.Channel = cftunnel.ChannelSelf
	h.cfg.SelfDevices = map[string]struct{}{device: {}}
	h.service, err = cftunnel.NewService(h.cfg, h.scope, h.store, h.cf, h.crypto, cftunnel.ServiceOptions{
		Clock: func() time.Time { return h.clock },
		RuntimeChecker: func(_ context.Context, actualDevice, keyHash, runtimeID string, _ time.Time) bool {
			return actualDevice == device && keyHash == bodyDigest(key) && runtimeID == "live"
		},
	})
	check(t, err)
	secret := strings.Repeat("s", 40)
	api := cftunnel.NewHTTPHandler(h.service, nil, secret)
	requestFor := func(action, body, idempotency string) *http.Request {
		t.Helper()
		challengeAction, _, _ := strings.Cut(action, "/")
		request := httptest.NewRequest(http.MethodPost, "/v1/tunnels/challenge",
			strings.NewReader(fmt.Sprintf(`{"action":%q,"device_id":%q}`, challengeAction, device)))
		request.Header.Set("Authorization", "Bearer "+secret)
		result := httptest.NewRecorder()
		api.ServeHTTP(result, request)
		if result.Code != http.StatusOK {
			t.Fatalf("challenge: %d %s", result.Code, result.Body)
		}
		var response struct{ Challenge string }
		check(t, json.Unmarshal(result.Body.Bytes(), &response))
		path := "/v1/tunnels/" + device + "/" + action
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Vanora-Public-Key", base64.RawURLEncoding.EncodeToString(key))
		req.Header.Set("Vanora-Challenge", response.Challenge)
		req.Header.Set("Vanora-Proof", cftunnel.SignHTTPProof(private, h.cfg.Channel, h.scope.ControlOrigin, path, device,
			response.Challenge, bodyDigest([]byte(body)), idempotency, bodyDigest(key)))
		if idempotency != "" {
			req.Header.Set("Idempotency-Key", idempotency)
		}
		return req
	}
	serve := func(req *http.Request, want int) *httptest.ResponseRecorder {
		t.Helper()
		result := httptest.NewRecorder()
		api.ServeHTTP(result, req)
		if result.Code != want || result.Header().Get("Cache-Control") != "no-store" || result.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s returned %d %s, want %d", req.URL.Path, result.Code, result.Body, want)
		}
		return result
	}
	register := `{"if_generation":0,"origin":"localhost:4482","runtime_id":"live"}`
	badRuntime := strings.Replace(register, `"live"`, `"inactive"`, 1)
	serve(requestFor("register", badRuntime, "stale"), 403)
	initial := requestFor("register", register, "register-initial")
	result := serve(initial, 202)
	var op cftunnel.OperationView
	check(t, json.Unmarshal(result.Body.Bytes(), &op))
	if op.ID == "" || op.Generation != 1 {
		t.Fatalf("invalid operation: %+v", op)
	}
	initial.Body = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(register)).Body
	if out := serve(initial, 409); !strings.Contains(out.Body.String(), "replay_detected") {
		t.Fatal(out.Body.String())
	}
	h.run(true)
	serve(requestFor("operations/"+op.ID, `{}`, ""), 200)
	status := serve(requestFor("status", `{}`, ""), 200)
	if strings.Contains(status.Body.String(), "4482") || strings.Contains(status.Body.String(), "device_key_hash") {
		t.Fatal("allocation view leaked endpoint details")
	}
	matching := strings.Replace(register, `"if_generation":0`, `"if_generation":1`, 1)
	serve(requestFor("register", matching, "register-ready"), 200)
	serve(requestFor("register", matching, "register-ready"), 200)
	if out := serve(requestFor("origin", matching, "register-ready"), 409); !strings.Contains(out.Body.String(), "idempotency_conflict") {
		t.Fatal(out.Body.String())
	}
	serve(requestFor("origin", matching, "origin-ready"), 200)
	serve(requestFor("recover", matching, "recover-ready"), 200)
	serve(requestFor("resume", matching, "resume-ready"), 200)
	token := serve(requestFor("token", matching, ""), 200)
	if !strings.Contains(token.Body.String(), "connector_token") {
		t.Fatal("missing connector token")
	}
	h.cf.errors["get_tunnel"] = []error{cftunnel.CFRateLimitError{RetryAfter: 1500 * time.Millisecond}}
	limited := serve(requestFor("token", matching, ""), 429)
	if limited.Header().Get("Retry-After") != "2" || !strings.Contains(limited.Body.String(), `"retry_after":2`) {
		t.Fatalf("inconsistent retry interval: %s", limited.Body)
	}
	serve(requestFor("disconnect", `{"if_generation":1}`, "disconnect"), 202)
	h.run(true)
	serve(requestFor("disconnect", `{"if_generation":2}`, "disconnect-noop"), 200)
	serve(requestFor("release", `{"if_generation":2}`, "release"), 202)
	h.run(true)
	serve(requestFor("release", `{"if_generation":3}`, "release-noop"), 200)
	serve(requestFor("deprovision", `{"if_generation":3}`, "deprovision"), 200)
	serve(requestFor("deprovision", `{"if_generation":4}`, "deprovision-noop"), 200)
	serve(requestFor("status", `{} {}`, ""), 400)
	serve(requestFor("status", `{"extra":true}`, ""), 400)
	serve(requestFor("register", `{"if_generation":0,"if_generation":1,"origin":"localhost:4482","runtime_id":"live"}`, "dup"), 400)
}

func TestTunnelChallengeLimitsAndBearerLockout(t *testing.T) {
	h := newHarness(t, cftunnel.ReaperOff)
	h.cfg.Channel = cftunnel.ChannelSelf
	h.service = h.withCloudflare(h.cf)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	device, err := identity.SelfDeviceID(public)
	check(t, err)
	const token = "test-bearer-for-a-local-fixture-only"
	api := cftunnel.NewHTTPHandler(h.service, nil, token)
	challenge := func(ip, bearer, forwarded string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/tunnels/challenge",
			strings.NewReader(fmt.Sprintf(`{"action":"status","device_id":%q}`, device)))
		req.RemoteAddr = ip
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Forwarded-For", forwarded)
		result := httptest.NewRecorder()
		api.ServeHTTP(result, req)
		return result
	}
	for attempt := range 33 {
		response := challenge("192.0.2.1:12345", token, fmt.Sprintf("198.51.100.%d", attempt+1))
		want := 200
		if attempt == 32 {
			want = 429
		}
		if response.Code != want {
			t.Fatalf("challenge %d returned %d, want %d", attempt, response.Code, want)
		}
	}
	for attempt := range 24 {
		response := challenge("192.0.2.2:12345", "wrong", "198.51.100.1")
		want := 401
		if attempt == 23 {
			want = 429
		}
		if response.Code != want {
			t.Fatalf("bearer failure %d returned %d, want %d", attempt, response.Code, want)
		}
	}
	locked := challenge("192.0.2.2:12345", token, "198.51.100.99")
	if locked.Code != 429 || locked.Header().Get("Retry-After") != "15" || !strings.Contains(locked.Body.String(), `"retry_after":15`) {
		t.Fatalf("locked bearer got %d %s", locked.Code, locked.Body)
	}
	h.clock = h.clock.Add(15 * time.Second)
	if unlocked := challenge("192.0.2.2:12345", token, "198.51.100.99"); unlocked.Code != 200 {
		t.Fatalf("bearer remained locked at %s: %d", h.clock, unlocked.Code)
	}
}
