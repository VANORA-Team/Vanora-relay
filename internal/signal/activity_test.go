package signal_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/adapter/selfrelay"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

func TestSignalProbeEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token := strings.Repeat("T", 40)
	h := signal.NewSelfHosted(token, nil)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/signal?probe=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated probe status = %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/signal?probe=1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNoContent {
		t.Fatalf("authenticated probe status = %d, want 204", resp2.StatusCode)
	}
}

func TestActivityPublishPollDeduplicationAndPushWebhook(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signer := identitytest.NewAuthority(10 * time.Minute)
	h := signal.New(signer.PublicKey(), nil, nil)

	// SSRF & scheme checks on ConfigurePushWebhook.
	if err := h.ConfigurePushWebhook("http://example.com/push", "", false); err == nil {
		t.Fatal("expected plain HTTP webhook rejection")
	}
	if err := h.ConfigurePushWebhook("https://127.0.0.1:8443/push", "", false); err == nil {
		t.Fatal("expected loopback webhook rejection when allowLocal=false")
	}

	var webhookMu sync.Mutex
	var delivered []signal.ActivityState
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer push-secret" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		var st signal.ActivityState
		if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		webhookMu.Lock()
		delivered = append(delivered, st)
		webhookMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhookSrv.Close()

	if err := h.ConfigurePushWebhook(webhookSrv.URL, "push-secret", true); err != nil {
		t.Fatalf("ConfigurePushWebhook local error = %v", err)
	}
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	issueEndpoint := func(subject string) *endpoint.Credentials {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		cert, err := signer.IssueWithKey("https://issuer.example", subject, pub, now)
		if err != nil {
			t.Fatal(err)
		}
		creds, err := endpoint.OpenCredentials(cert, priv, signer.PublicKey(), now)
		if err != nil {
			t.Fatal(err)
		}
		return creds
	}

	hostCreds := issueEndpoint("owner-1")
	ownerMobile := issueEndpoint("owner-1")
	guestMobile := issueEndpoint("guest-1")
	intruderMobile := issueEndpoint("intruder-9")

	now := time.Now()
	p, err := identity.VerifyCertificate(hostCreds.Certificate(), signer.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)
	lease, _, err := signer.IssueLease(p, hostCreds.Certificate(), base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ws, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	_, chRaw, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ch protocol.Message
	_ = json.Unmarshal(chRaw, &ch)
	login, err := hostCreds.Login(ch, "desktop", lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Write(ctx, websocket.MessageText, protocol.Encode(login)); err != nil {
		t.Fatal(err)
	}
	_, _, err = ws.Read(ctx) // auth.ok
	if err != nil {
		t.Fatal(err)
	}

	online, err := hostCreds.Online("workstation", []string{guestMobile.UserID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Write(ctx, websocket.MessageText, protocol.Encode(online)); err != nil {
		t.Fatal(err)
	}
	_, regRaw, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var regMsg protocol.Message
	_ = json.Unmarshal(regRaw, &regMsg)
	var regData struct {
		Ticket string `json:"pairing_ticket"`
	}
	_ = json.Unmarshal(regMsg.Data, &regData)
	if regData.Ticket == "" {
		t.Fatal("missing pairing_ticket")
	}

	postActivity := func(ticket, phase, uiID string) int {
		body, _ := json.Marshal(map[string]any{
			"session_id": "sess-1",
			"run_id":     "run-1",
			"phase":      phase,
			"ui_id":      uiID,
		})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/signal?activity=1", bytes.NewReader(body))
		req.Header.Set("Vanora-Desktop", hostCreds.DeviceID())
		req.Header.Set("Authorization", "Bearer "+ticket)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := postActivity("wrong-ticket", "running", ""); code != http.StatusUnauthorized {
		t.Fatalf("wrong ticket status = %d, want 401", code)
	}
	if code := postActivity(regData.Ticket, "running", ""); code != http.StatusNoContent {
		t.Fatalf("publish running status = %d, want 204", code)
	}
	// Duplicate publish must be deduplicated and not re-trigger push webhook.
	if code := postActivity(regData.Ticket, "running", ""); code != http.StatusNoContent {
		t.Fatalf("duplicate publish status = %d, want 204", code)
	}
	if code := postActivity(regData.Ticket, "awaiting_approval", "ui-7"); code != http.StatusNoContent {
		t.Fatalf("publish awaiting_approval status = %d, want 204", code)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		webhookMu.Lock()
		n := len(delivered)
		webhookMu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("webhook deliveries = %d, want 2", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
	webhookMu.Lock()
	if len(delivered) != 2 || delivered[0].Phase != "running" || delivered[1].Phase != "awaiting_approval" {
		t.Fatalf("unexpected webhook deliveries: %+v", delivered)
	}
	webhookMu.Unlock()

	poll := func(caller *endpoint.Credentials, ts time.Time) (*http.Response, []byte) {
		proof, err := caller.SignActivityPoll(hostCreds.DeviceID(), ts)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/signal?activity="+hostCreds.DeviceID(), nil)
		req.Header.Set("X-Vanora-Activity-Proof", proof)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		resp.Body.Close()
		return resp, buf.Bytes()
	}

	// Owner and explicitly granted guest succeed.
	for _, caller := range []*endpoint.Credentials{ownerMobile, guestMobile} {
		resp, raw := poll(caller, time.Now())
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorized poll status = %d (%s)", resp.StatusCode, string(raw))
		}
		var out struct {
			Activities []signal.ActivityState `json:"activities"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || len(out.Activities) != 1 || out.Activities[0].Phase != "awaiting_approval" {
			t.Fatalf("unexpected poll response: %s", string(raw))
		}
	}

	// Stale timestamp rejected.
	if resp, _ := poll(ownerMobile, time.Now().Add(-5*time.Minute)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale proof status = %d, want 401", resp.StatusCode)
	}

	// Unauthorized account gets 403 Forbidden (cross-account isolation).
	if resp, _ := poll(intruderMobile, time.Now()); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("intruder poll status = %d, want 403", resp.StatusCode)
	}
}

type memSelfStore struct{ v string }

func (m *memSelfStore) Load() (string, error) { return m.v, nil }
func (m *memSelfStore) Save(v string) error   { m.v = v; return nil }

func TestActivitySelfHostedEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token := strings.Repeat("S", 40)
	h := signal.NewSelfHosted(token, nil)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()

	seed, err := selfrelay.LoadClientKey(&memSelfStore{})
	if err != nil {
		t.Fatal(err)
	}
	targetPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	targetPin := base64.RawURLEncoding.EncodeToString(targetPub)
	pubB64, targetDevID, proofB64, err := selfrelay.SignActivityPoll(seed, targetPin, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/signal?activity="+targetDevID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Vanora-Public-Key", pubB64)
	req.Header.Set("X-Vanora-Activity-Proof", proofB64)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("self-hosted activity poll status = %d, want 200", resp.StatusCode)
	}
}
