package cftunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

const controlTestToken = "self-token-used-by-local-test-fixtures"

func TestControlOriginFromSignalURL(t *testing.T) {
	for given, want := range map[string]string{
		"wss://Relay.Example:8443/v1/signal": "https://relay.example:8443",
		"ws://127.0.0.1:9300/v1/signal":      "http://127.0.0.1:9300",
		"ws://[::1]:9300/v1/signal":          "http://[::1]:9300",
	} {
		got, err := ControlOriginFromSignalURL(given)
		if err != nil || got != want {
			t.Fatalf("%s resolved to %q, %v", given, got, err)
		}
	}
	for _, input := range []string{"ws://relay.example/v1/signal", "wss://me@relay.example/v1/signal",
		"wss://relay.example/v1/signal?", "wss://relay.example/v1/signal#",
		"wss://relay.example/v1/%73ignal", "wss://relay.example/v1/other", "wss://relay.example:65536/v1/signal"} {
		if _, err := ControlOriginFromSignalURL(input); err == nil {
			t.Fatalf("accepted unsafe control origin from %s", input)
		}
	}
}

func controlTestIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := identity.SelfDeviceID(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key, deviceID
}

func TestControlMutationProofAndRetry(t *testing.T) {
	pub, key, device := controlTestIdentity(t)
	var mu sync.Mutex
	challenges, used := map[string]bool{}, map[string]bool{}
	var body, idem string
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+controlTestToken {
			t.Error("missing authenticated POST")
		}
		if r.URL.Path == "/v1/tunnels/challenge" {
			var req struct {
				Action string `json:"action"`
				Device string `json:"device_id"`
			}
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.Device != device || req.Action != "register" {
				t.Error("challenge not bound to the action and actor")
			}
			nonce := protocol.NewID()
			challenges[nonce] = true
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": nonce, "expires_at": time.Now().Add(30 * time.Second)})
			return
		}
		requests++
		raw, _ := io.ReadAll(r.Body)
		idempotencyKey := r.Header.Get("Idempotency-Key")
		challenge := r.Header.Get("Vanora-Challenge")
		if !challenges[challenge] || used[challenge] || !protocol.ValidID(idempotencyKey) {
			t.Error("missing fresh challenge or idempotency key")
		}
		used[challenge] = true
		rawHash, credentialHash := sha256.Sum256(raw), sha256.Sum256(pub)
		fields := []string{"vanora/tunnel-http/v1", "self", "http://" + r.Host, "POST", r.URL.Path, device, challenge,
			hex.EncodeToString(rawHash[:]), idempotencyKey, hex.EncodeToString(credentialHash[:])}
		var framed bytes.Buffer
		for _, field := range fields {
			_ = binary.Write(&framed, binary.BigEndian, uint32(len(field)))
			_, _ = framed.WriteString(field)
		}
		signature, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("Vanora-Proof"))
		if !ed25519.Verify(pub, framed.Bytes(), signature) {
			t.Error("management PoP did not match canonical framing")
		}
		switch requests {
		case 1:
			body, idem = string(raw), idempotencyKey
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"temporarily_unavailable","request_id":"one"}`)
			return
		case 2:
			if idem != idempotencyKey || body != string(raw) {
				t.Error("transient retry changed the logical mutation")
			}
		case 3:
			if idem == idempotencyKey {
				t.Error("separate logical mutations reused an idempotency key")
			}
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(OperationView{ID: "op1", Type: "provision", Generation: 1, CreatedAt: time.Now()})
	}))
	defer server.Close()
	control, err := NewControlClient(ControlOptions{Channel: "self", ControlOrigin: server.URL, DeviceID: device,
		PrivateKey: key, SelfToken: controlTestToken})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		result, err := control.Register(t.Context(), device, "127.0.0.1:8123", "runtime", 0)
		if err != nil || result.Operation.ID != "op1" {
			t.Fatalf("Register returned %#v, %v", result, err)
		}
	}
}

func TestControlLimitsRedirectsAndErrors(t *testing.T) {
	_, key, device := controlTestIdentity(t)
	var recurse atomic.Bool
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		recurse.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()
	for _, tc := range []struct {
		name string
		code int
		body string
		want string
	}{
		{"redirect", http.StatusTemporaryRedirect, `{"error":"redirect","request_id":"request"}`, "redirect"},
		{"duplicate", http.StatusNotFound, `{"error":"not_found","request_id":"request","error":"retry"}`, "invalid_response"},
		{"unknown", http.StatusNotFound, `{"error":"not_found","request_id":"request","unknown":1}`, "invalid_response"},
		{"bounded", http.StatusOK, strings.Repeat("x", 65537), ""},
		{"retry-after", http.StatusTooManyRequests, `{"error":"rate_limited","request_id":"request","retry_after":3,"operation_id":"op"}`, "rate_limited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/tunnels/challenge" {
					_ = json.NewEncoder(w).Encode(map[string]any{"challenge": "nonce", "expires_at": time.Now().Add(time.Second)})
					return
				}
				w.Header().Set("Location", foreign.URL)
				if tc.name == "retry-after" {
					w.Header().Set("Retry-After", "5")
				}
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client, err := NewControlClient(ControlOptions{Channel: "self", ControlOrigin: server.URL, DeviceID: device,
				PrivateKey: key, SelfToken: controlTestToken})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Status(t.Context(), device)
			if tc.want == "" {
				if err == nil || !strings.Contains(err.Error(), "64 KiB") {
					t.Fatalf("oversized response produced %v", err)
				}
				return
			}
			var api *APIError
			if !errors.As(err, &api) || api.Code != tc.want || api.Status != tc.code {
				t.Fatalf("invalid API error: %v", err)
			}
			if tc.name == "retry-after" && (api.RetryAfter != 5*time.Second || api.OperationID != "op" || api.RequestID != "request") {
				t.Fatalf("retry metadata was lost: %+v", api)
			}
		})
	}
	if recurse.Load() {
		t.Fatal("management HTTP client followed a redirect")
	}
}
