package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"vanora-relay/adapter/account"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	signalserver "vanora-relay/internal/signal"
)

type memVault struct {
	mu  sync.Mutex
	val string
}

func (m *memVault) Load() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.val, nil
}
func (m *memVault) Save(v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.val = v
	return nil
}

func newTestTokenAuthority(t *testing.T, validTokens map[string]string) (*httptest.Server, *identitytest.Authority) {
	t.Helper()
	auth := identitytest.NewAuthority(10 * time.Minute)
	type chal struct {
		id, nonce string
		pub       ed25519.PublicKey
	}
	var mu sync.Mutex
	challenges := map[string]chal{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/identity/challenges", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Purpose   string `json:"purpose"`
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"body_invalid"}`, 400)
			return
		}
		pub, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			http.Error(w, `{"error":"public_key_invalid"}`, 400)
			return
		}
		var b1, b2 [16]byte
		_, _ = rand.Read(b1[:])
		_, _ = rand.Read(b2[:])
		id := base64.RawURLEncoding.EncodeToString(b1[:])
		nonce := base64.RawURLEncoding.EncodeToString(b2[:])
		mu.Lock()
		challenges[id] = chal{id: id, nonce: nonce, pub: ed25519.PublicKey(pub)}
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"challenge_id": id,
			"nonce":        nonce,
			"expires_at":   time.Now().Add(5 * time.Minute).Unix(),
		})
	})
	mux.HandleFunc("/v1/identity/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChallengeID string `json:"challenge_id"`
			Token       string `json:"token"`
			Signature   string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"body_invalid"}`, 400)
			return
		}
		mu.Lock()
		c, ok := challenges[req.ChallengeID]
		delete(challenges, req.ChallengeID)
		mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"challenge_invalid"}`, 400)
			return
		}
		sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
		if err != nil || !ed25519.Verify(c.pub, identity.ProofMessage(c.id, c.nonce, "enroll", c.pub), sig) {
			http.Error(w, `{"error":"proof_invalid"}`, 401)
			return
		}
		sub, ok := validTokens[req.Token]
		if !ok {
			http.Error(w, `{"error":"token_rejected"}`, 401)
			return
		}
		now := time.Now()
		cert, err := auth.IssueWithKey("https://auth.example.com/realms/vanora", sub, c.pub, now)
		if err != nil {
			http.Error(w, `{"error":"issue_failed"}`, 500)
			return
		}
		p, err := identity.VerifyCertificate(cert, auth.PublicKey(), now)
		if err != nil {
			http.Error(w, `{"error":"issue_failed"}`, 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificate":    cert,
			"device_id":      p.DeviceID,
			"remote_user_id": p.RemoteUserID(),
			"expires_at":     p.Expires.Unix(),
			"renewable":      false,
		})
	})
	mux.HandleFunc("/v1/identity/lease", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Certificate string `json:"certificate"`
			Nonce       string `json:"nonce"`
			Signature   string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"body_invalid"}`, 400)
			return
		}
		now := time.Now()
		p, err := identity.VerifyCertificate(req.Certificate, auth.PublicKey(), now)
		if err != nil {
			http.Error(w, `{"error":"certificate_invalid"}`, 400)
			return
		}
		sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
		if err != nil || !ed25519.Verify(p.PublicKey, identity.LeaseProofMessage(req.Nonce, req.Certificate), sig) {
			http.Error(w, `{"error":"proof_invalid"}`, 401)
			return
		}
		lease, exp, err := auth.IssueLease(p, req.Certificate, req.Nonce, now, 45*time.Second)
		if err != nil {
			http.Error(w, `{"error":"lease_failed"}`, 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"lease":          lease,
			"device_id":      p.DeviceID,
			"remote_user_id": p.RemoteUserID(),
			"issued_at":      now.Unix(),
			"expires_at":     exp.Unix(),
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, auth
}

func TestLoginWithTokenStdinJSONMode(t *testing.T) {
	authSrv, auth := newTestTokenAuthority(t, map[string]string{"valid-client-token": "sidecar-user"})
	caHex := hex.EncodeToString(auth.PublicKey())
	a, err := account.New(authSrv.URL, caHex, &memVault{})
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = login(context.Background(), a, loginOptions{
		tokenStdin: true,
		in:         strings.NewReader("valid-client-token\n"),
		emitter:    &jsonEmitter{out: &out},
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	var ev map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &ev); err != nil {
		t.Fatalf("invalid jsonl: %v (%s)", err, out.String())
	}
	if ev["type"] != "login.ok" || ev["user_id"] == "" || ev["device_id"] == "" {
		t.Fatalf("unexpected login.ok: %v", ev)
	}
}

func TestSidecarSubprocessExitsOnStdinEOF(t *testing.T) {
	authSrv, auth := newTestTokenAuthority(t, map[string]string{
		"sidecar-token-1": "sidecar-user",
		"sidecar-token-2": "sidecar-user",
	})
	caHex := hex.EncodeToString(auth.PublicKey())

	dir := t.TempDir()
	binName := "vanora-desktop-test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	bin := filepath.Join(dir, binName)
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build vanora-desktop: %v\n%s", err, out)
	}

	stateDir := filepath.Join(dir, "state")
	cmd := exec.Command(bin, "whoami", "-identity", authSrv.URL, "-ca-hex", caHex, "-state-dir", stateDir, "-json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("whoami failed: %v\n%s", err, out)
	}
	var status map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &status); err != nil {
		t.Fatalf("parse whoami json: %v (%s)", err, out)
	}
	if status["type"] != "status" || status["enrolled"] != false {
		t.Fatalf("unexpected whoami: %v", status)
	}

	// Enroll using in-memory vault and exercise serve -sidecar control loop.
	a, err := account.New(authSrv.URL, caHex, &memVault{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Enroll(context.Background(), "sidecar-token-1"); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "desktop.json")
	cfgRaw, _ := json.Marshal(map[string]any{"executable": bin})
	if err := os.WriteFile(cfgPath, cfgRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = inR
	defer func() { os.Stdin = oldStdin }()

	outR, outW := io.Pipe()
	defer outR.Close()
	defer inW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hub := signalserver.New(auth.PublicKey(), nil, nil)
	go hub.Run(ctx)
	relay := httptest.NewServer(hub)
	defer relay.Close()
	signalURL := "ws" + strings.TrimPrefix(relay.URL, "http")
	serveDone := make(chan error, 1)
	go func() {
		err := serve(ctx, a, auth.PublicKey(), signalURL, "SidecarHost", cfgPath, filepath.Join(dir, "sidecar-state"), true, &jsonEmitter{out: outW}, accessOptions{relayEnabled: true})
		_ = outW.Close()
		serveDone <- err
	}()

	var sawReady, sawGate, sawAuthOK, sawOnline, sawLogout, sawShutdown bool
	commands := json.NewEncoder(inW)
	outScanner := bufio.NewScanner(outR)
	for outScanner.Scan() {
		var ev map[string]any
		if json.Unmarshal(outScanner.Bytes(), &ev) != nil {
			continue
		}
		switch ev["type"] {
		case "ready":
			sawReady = true
			_ = commands.Encode(map[string]any{"type": "access.relay.set", "request_id": "signed-out", "enabled": true})
		case "access.error":
			if ev["request_id"] != "signed-out" {
				t.Fatalf("unexpected access error: %v", ev)
			}
			sawGate = true
			_ = commands.Encode(map[string]any{"type": "auth.token", "token": "sidecar-token-2"})
		case "auth.ok":
			sawAuthOK = true
		case "online":
			if !sawAuthOK {
				t.Fatalf("official relay came online before host authentication: %v", ev)
			}
			sawOnline = true
			_ = commands.Encode(map[string]any{"type": "auth.logout"})
		case "auth.logout.ok":
			sawLogout = true
		case "access.status":
			if sawLogout {
				if ev["relay_online"] != false || ev["relay_authorized"] != false || a.UserID() != "" {
					t.Fatalf("official access survived logout: %v", ev)
				}
				_ = inW.Close()
			}
		case "shutdown":
			sawShutdown = true
		}
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("sidecar serve failed: %v", err)
	}
	if !sawReady || !sawGate || !sawAuthOK || !sawOnline || !sawLogout || !sawShutdown {
		t.Fatalf("sidecar lifecycle incomplete: ready=%v gate=%v auth_ok=%v online=%v logout=%v shutdown=%v", sawReady, sawGate, sawAuthOK, sawOnline, sawLogout, sawShutdown)
	}
}

func TestSidecarDualSiteHotSwitchAndSelfRelay(t *testing.T) {
	cnAuthSrv, cnAuth := newTestTokenAuthority(t, map[string]string{"cn-token": "cn-user"})
	globalAuthSrv, globalAuth := newTestTokenAuthority(t, map[string]string{"global-token": "global-user"})

	cnAccount, err := account.New(cnAuthSrv.URL, hex.EncodeToString(cnAuth.PublicKey()), &memVault{})
	if err != nil {
		t.Fatal(err)
	}
	globalAccount, err := account.New(globalAuthSrv.URL, hex.EncodeToString(globalAuth.PublicKey()), &memVault{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cnHub := signalserver.New(cnAuth.PublicKey(), nil, nil)
	go cnHub.Run(ctx)
	cnRelay := httptest.NewServer(cnHub)
	defer cnRelay.Close()

	globalHub := signalserver.New(globalAuth.PublicKey(), nil, nil)
	go globalHub.Run(ctx)
	globalRelay := httptest.NewServer(globalHub)
	defer globalRelay.Close()

	selfToken := strings.Repeat("self-sidecar-", 4)
	selfHub := signalserver.NewSelfHosted(selfToken, nil)
	go selfHub.Run(ctx)
	selfRelay := httptest.NewServer(selfHub)
	defer selfRelay.Close()

	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "desktop.json")
	cfgRaw, _ := json.Marshal(map[string]any{"executable": exe})
	if err := os.WriteFile(cfgPath, cfgRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = inR
	defer func() { os.Stdin = oldStdin }()
	defer inW.Close()

	outR, outW := io.Pipe()
	defer outR.Close()

	slots := map[string]*officialSlotConfig{
		"cn":     {name: "cn", account: cnAccount, ca: cnAuth.PublicKey(), signalURL: "ws" + strings.TrimPrefix(cnRelay.URL, "http")},
		"global": {name: "global", account: globalAccount, ca: globalAuth.PublicKey(), signalURL: "ws" + strings.TrimPrefix(globalRelay.URL, "http")},
	}
	serveDone := make(chan error, 1)
	go func() {
		err := serveMulti(ctx, slots, "DualHost", cfgPath, filepath.Join(dir, "state"), true, &jsonEmitter{out: outW}, accessOptions{selfStore: &memVault{}})
		_ = outW.Close()
		serveDone <- err
	}()

	commands := json.NewEncoder(inW)
	scanner := bufio.NewScanner(outR)
	var seen []map[string]any
	nextEvent := func(desc string) map[string]any {
		t.Helper()
		for scanner.Scan() {
			var ev map[string]any
			if json.Unmarshal(scanner.Bytes(), &ev) == nil {
				seen = append(seen, ev)
				return ev
			}
		}
		t.Fatalf("sidecar stdout closed unexpectedly while waiting for %s; seen=%v", desc, seen)
		return nil
	}
	waitFor := func(match func(map[string]any) bool, desc string) map[string]any {
		t.Helper()
		for {
			ev := nextEvent(desc)
			if match(ev) {
				return ev
			}
		}
	}

	waitFor(func(ev map[string]any) bool { return ev["type"] == "ready" }, "ready")

	// 1. Enabling CN without CN login must fail.
	_ = commands.Encode(map[string]any{"type": "access.relay.set", "request_id": "cn-denied", "channel": "cn", "enabled": true})
	waitFor(func(ev map[string]any) bool { return ev["type"] == "access.error" && ev["request_id"] == "cn-denied" }, "cn denied")

	// 2. Inject CN token, enable CN -> CN comes online.
	_ = commands.Encode(map[string]any{"type": "auth.token", "channel": "cn", "token": "cn-token"})
	waitFor(func(ev map[string]any) bool { return ev["type"] == "auth.ok" && ev["channel"] == "cn" }, "cn token stored")
	_ = commands.Encode(map[string]any{"type": "access.relay.set", "request_id": "cn-on", "channel": "cn", "enabled": true})
	cnOnline := waitFor(func(ev map[string]any) bool { return ev["type"] == "online" && ev["channel"] == "cn" }, "cn online")
	cnDevID, _ := cnOnline["device_id"].(string)
	if cnDevID == "" {
		t.Fatalf("missing cn device_id: %v", cnOnline)
	}

	// 3. CN login must NOT allow switching to GLOBAL.
	_ = commands.Encode(map[string]any{"type": "access.relay.set", "request_id": "gl-denied", "channel": "global", "enabled": true})
	waitFor(func(ev map[string]any) bool { return ev["type"] == "access.error" && ev["request_id"] == "gl-denied" }, "global denied")

	// 4. Inject GLOBAL token and hot-switch to GLOBAL -> GLOBAL comes online without losing CN identity.
	_ = commands.Encode(map[string]any{"type": "auth.token", "channel": "global", "token": "global-token"})
	waitFor(func(ev map[string]any) bool { return ev["type"] == "auth.ok" && ev["channel"] == "global" }, "global token stored")
	_ = commands.Encode(map[string]any{"type": "access.relay.set", "request_id": "gl-on", "channel": "global", "enabled": true})
	waitFor(func(ev map[string]any) bool { return ev["type"] == "online" && ev["channel"] == "global" }, "global online")

	// 5. Hot-switch back to CN -> keeps same CN device_id!
	_ = commands.Encode(map[string]any{"type": "access.relay.set", "request_id": "cn-back", "channel": "cn", "enabled": true})
	cnOnlineAgain := waitFor(func(ev map[string]any) bool { return ev["type"] == "online" && ev["channel"] == "cn" }, "cn online again")
	if cnOnlineAgain["device_id"] != cnDevID {
		t.Fatalf("cn device_id changed after hot-switch: %v vs %v", cnOnlineAgain["device_id"], cnDevID)
	}

	// 6. Log out BOTH official accounts, then enable account-free self-hosted relay and create pairing link!
	_ = commands.Encode(map[string]any{"type": "auth.logout", "request_id": "out-cn", "channel": "cn"})
	waitFor(func(ev map[string]any) bool { return ev["type"] == "auth.logout.ok" && ev["channel"] == "cn" }, "cn logged out")
	_ = commands.Encode(map[string]any{"type": "auth.logout", "request_id": "out-gl", "channel": "global"})
	waitFor(func(ev map[string]any) bool { return ev["type"] == "auth.logout.ok" && ev["channel"] == "global" }, "global logged out")

	_ = commands.Encode(map[string]any{
		"type":         "access.relay.set",
		"request_id":   "self-on",
		"channel":      "self",
		"enabled":      true,
		"signal_url":   "ws" + strings.TrimPrefix(selfRelay.URL, "http"),
		"signal_token": selfToken,
	})
	waitFor(func(ev map[string]any) bool { return ev["type"] == "online" && ev["channel"] == "self" }, "self online")

	_ = commands.Encode(map[string]any{"type": "access.self.invite.create", "request_id": "self-inv", "access": "control"})
	invEv := waitFor(func(ev map[string]any) bool { return ev["type"] == "access.self.invite.created" && ev["request_id"] == "self-inv" }, "self invite")
	link, _ := invEv["link"].(string)
	if !strings.Contains(link, "#mode=self") || !strings.Contains(link, "pair=") {
		t.Fatalf("unexpected self pairing link: %q", link)
	}

	_ = inW.Close()
	waitFor(func(ev map[string]any) bool { return ev["type"] == "shutdown" }, "shutdown")
	for scanner.Scan() {
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("serveMulti failed: %v", err)
	}
}
