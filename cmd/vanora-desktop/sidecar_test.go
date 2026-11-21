package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func newLoopbackOIDC(t *testing.T) (*httptest.Server, *identity.Signer) {
	t.Helper()
	idpPub, idpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	codes := map[string]struct{ nonce, redirect, challenge string }{}
	var idp *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.URL,
			"authorization_endpoint":                idp.URL + "/authorize",
			"token_endpoint":                        idp.URL + "/token",
			"jwks_uri":                              idp.URL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"EdDSA"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
			"x": base64.RawURLEncoding.EncodeToString(idpPub),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-12345"
		mu.Lock()
		codes[code] = struct{ nonce, redirect, challenge string }{
			nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"), challenge: q.Get("code_challenge"),
		}
		mu.Unlock()
		redir, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		v := redir.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		redir.RawQuery = v.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.PostForm.Get("code")
		mu.Lock()
		entry, ok := codes[code]
		delete(codes, code)
		mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || r.PostForm.Get("redirect_uri") != entry.redirect ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != entry.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		now := time.Now()
		hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "k1", "typ": "JWT"})
		clm, _ := json.Marshal(map[string]any{
			"iss": idp.URL, "sub": "sidecar-user", "aud": []string{"vanora-native"},
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": entry.nonce,
		})
		in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(clm)
		sig := ed25519.Sign(idpPriv, []byte(in))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token": in + "." + base64.RawURLEncoding.EncodeToString(sig),
		})
	})
	idp = httptest.NewServer(mux)
	t.Cleanup(idp.Close)

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := identity.NewSigner(caPriv, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	idSvc, err := identity.NewServer(identity.Config{
		OIDCIssuer:       idp.URL,
		OIDCClientID:     "vanora-native",
		OIDCRedirectURI:  "com.vanora.app:/oauth/callback",
		OIDCRedirectURIs: []string{"http://127.0.0.1/oauth/callback"},
		Signer:           signer,
		HTTPClient:       idp.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	authSrv := httptest.NewServer(idSvc.Handler())
	t.Cleanup(authSrv.Close)
	return authSrv, signer
}

func TestLoginEphemeralLoopbackJSONMode(t *testing.T) {
	authSrv, signer := newLoopbackOIDC(t)
	caHex := hex.EncodeToString(signer.PublicKey())
	a, err := account.New(authSrv.URL, caHex, &memVault{})
	if err != nil {
		t.Fatal(err)
	}

	pr, pw := io.Pipe()
	emitter := &jsonEmitter{out: pw}
	done := make(chan error, 1)
	go func() {
		err := login(context.Background(), a, loginOptions{
			redirectURI: "http://127.0.0.1:0/oauth/callback",
			noBrowser:   true,
			emitter:     emitter,
		})
		_ = pw.Close()
		done <- err
	}()

	scanner := bufio.NewScanner(pr)
	var sawOK bool
	for scanner.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("invalid jsonl: %v", err)
		}
		switch ev["type"] {
		case "login.url":
			authURL, _ := ev["url"].(string)
			cb, _ := ev["callback"].(string)
			if !strings.HasPrefix(cb, "http://127.0.0.1:") || strings.HasPrefix(cb, "http://127.0.0.1:0/") {
				t.Fatalf("expected ephemeral bound loopback callback, got %q", cb)
			}
			// Simulate the browser completing OIDC and following redirect to loopback listener.
			resp, err := http.Get(authURL)
			if err != nil {
				t.Fatalf("follow auth url: %v", err)
			}
			resp.Body.Close()
		case "login.ok":
			if ev["user_id"] == "" || ev["device_id"] == "" {
				t.Fatalf("missing ids in login.ok: %v", ev)
			}
			sawOK = true
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if !sawOK {
		t.Fatal("missing login.ok event")
	}
}

func TestSidecarSubprocessExitsOnStdinEOF(t *testing.T) {
	if os.Getenv("VANORA_SIDECAR_TEST_HELPER") == "1" {
		if err := run(os.Args[1:]); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Build a tiny config with 0 sessions and test `whoami -json` with -ca-hex.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := identity.NewSigner(caPriv, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
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
	cmd := exec.Command(bin, "whoami", "-identity", "http://127.0.0.1:8090", "-ca-hex", hex.EncodeToString(signer.PublicKey()), "-state-dir", stateDir, "-json")
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

	// Verify serve -sidecar exits cleanly on stdin EOF after emitting ready + status.
	authSrv, signer2 := newLoopbackOIDC(t)
	caHex2 := hex.EncodeToString(signer2.PublicKey())
	a, err := account.New(authSrv.URL, caHex2, &memVault{})
	if err != nil {
		t.Fatal(err)
	}
	// Complete enrollment in-memory and test serve() directly with a synthetic config.
	pr, pw := io.Pipe()
	doneLogin := make(chan error, 1)
	go func() {
		err := login(context.Background(), a, loginOptions{
			redirectURI: "http://127.0.0.1:0/oauth/callback",
			noBrowser:   true,
			emitter:     &jsonEmitter{out: pw},
		})
		_ = pw.Close()
		doneLogin <- err
	}()
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		var ev map[string]any
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev["type"] == "login.url" {
			resp, err := http.Get(ev["url"].(string))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
	}
	if err := <-doneLogin; err != nil {
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
	serveDone := make(chan error, 1)
	go func() {
		err := serve(context.Background(), a, signer2.PublicKey(), "ws://127.0.0.1:1/v1/signal", "SidecarHost", cfgPath, filepath.Join(dir, "sidecar-state"), true, &jsonEmitter{out: outW})
		_ = outW.Close()
		serveDone <- err
	}()

	var sawReady, sawStatus, sawShutdown bool
	outScanner := bufio.NewScanner(outR)
	for outScanner.Scan() {
		var ev map[string]any
		if json.Unmarshal(outScanner.Bytes(), &ev) != nil {
			continue
		}
		switch ev["type"] {
		case "ready":
			sawReady = true
			_, _ = inW.Write([]byte("{\"type\":\"status\"}\n"))
		case "status":
			sawStatus = true
			_ = inW.Close() // Trigger stdin EOF shutdown.
		case "shutdown":
			sawShutdown = true
		}
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("sidecar serve failed: %v", err)
	}
	if !sawReady || !sawStatus || !sawShutdown {
		t.Fatalf("sidecar lifecycle incomplete: ready=%v status=%v shutdown=%v", sawReady, sawStatus, sawShutdown)
	}
}
