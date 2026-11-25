package security_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/endpoint"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/internal/membership"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
	"vanora-relay/test/security/internal/sectest"
)

type sigClient struct {
	ws    *websocket.Conn
	ctx   context.Context
	creds *endpoint.Credentials
	proof endpoint.LeaseProof
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (c *sigClient) send(t *testing.T, m protocol.Message) {
	t.Helper()
	mustOK(t, c.ws.Write(c.ctx, websocket.MessageText, protocol.Encode(m)))
}

func (c *sigClient) readAny(t *testing.T) protocol.Message {
	t.Helper()
	_, raw, err := c.ws.Read(c.ctx)
	mustOK(t, err)
	var m protocol.Message
	mustOK(t, json.Unmarshal(raw, &m))
	return m
}

func (c *sigClient) readExpect(t *testing.T, expect string) protocol.Message {
	t.Helper()
	m := c.readAny(t)
	if m.Type != expect {
		t.Fatalf("want %s, got %s %s", expect, m.Type, m.Data)
	}
	return m
}

func newLoopbackICE(t *testing.T) *ice.Server {
	t.Helper()
	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	srv, err := ice.FromEnv()
	mustOK(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func newEntitlementVerifier(t *testing.T, entitled bool) *membership.Client {
	t.Helper()
	tok := strings.Repeat("m", 40)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+tok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"relay_allowed": entitled,
				"valid_until":   time.Now().Add(time.Hour).Unix(),
			},
		})
	}))
	t.Cleanup(srv.Close)
	return &membership.Client{URL: srv.URL, Token: tok}
}

func loginOfficial(t *testing.T, ctx context.Context, url, role, issuer, subject string, signer *identitytest.Authority) *sigClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	now := time.Now()
	cert, err := signer.IssueWithKey(issuer, subject, pub, now)
	mustOK(t, err)
	p, err := identity.VerifyCertificate(cert, signer.PublicKey(), now)
	mustOK(t, err)
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)
	lease, _, err := signer.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	mustOK(t, err)
	creds, err := endpoint.OpenCredentials(cert, priv, signer.PublicKey(), now)
	mustOK(t, err)
	ws, _, err := websocket.Dial(ctx, url, nil)
	mustOK(t, err)
	t.Cleanup(func() { _ = ws.CloseNow() })
	c := &sigClient{ws: ws, ctx: ctx, creds: creds, proof: endpoint.LeaseProof{Certificate: cert, Lease: lease}}
	ch := c.readExpect(t, "auth.challenge")
	m, err := creds.Login(ch, role, lease)
	mustOK(t, err)
	c.send(t, m)
	c.readExpect(t, "auth.ok")
	return c
}

type selfClient struct {
	ws   *websocket.Conn
	ctx  context.Context
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   string
}

func dialSelfClient(t *testing.T, ctx context.Context, url, token, role string) *selfClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	devID, err := identity.SelfDeviceID(pub)
	mustOK(t, err)
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	mustOK(t, err)
	t.Cleanup(func() { _ = ws.CloseNow() })
	_, raw, err := ws.Read(ctx)
	mustOK(t, err)
	var ch protocol.Message
	mustOK(t, json.Unmarshal(raw, &ch))
	if ch.Type != "auth.challenge" {
		t.Fatalf("want auth.challenge, got %s", ch.Type)
	}
	loginMsg := protocol.Message{Type: "auth.login", Connection: ch.Connection, From: devID, To: "signal"}
	mustOK(t, loginMsg.Sign(priv, protocol.Encode(map[string]string{
		"role":       role,
		"public_key": base64.RawURLEncoding.EncodeToString(pub),
	})))
	mustOK(t, ws.Write(ctx, websocket.MessageText, protocol.Encode(loginMsg)))
	_, okRaw, err := ws.Read(ctx)
	mustOK(t, err)
	var okMsg protocol.Message
	mustOK(t, json.Unmarshal(okRaw, &okMsg))
	if okMsg.Type != "auth.ok" {
		t.Fatalf("want auth.ok, got %s %s", okMsg.Type, okMsg.Data)
	}
	return &selfClient{ws: ws, ctx: ctx, pub: pub, priv: priv, id: devID}
}

func (c *selfClient) send(t *testing.T, m protocol.Message) {
	t.Helper()
	mustOK(t, c.ws.Write(c.ctx, websocket.MessageText, protocol.Encode(m)))
}

func (c *selfClient) readExpect(t *testing.T, expect string) protocol.Message {
	t.Helper()
	_, raw, err := c.ws.Read(c.ctx)
	mustOK(t, err)
	var m protocol.Message
	mustOK(t, json.Unmarshal(raw, &m))
	if m.Type != expect {
		t.Fatalf("want %s, got %s %s", expect, m.Type, m.Data)
	}
	return m
}

func TestSignalSelfTokenGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token := strings.Repeat("S", 40)
	h := signal.NewSelfHosted(token, newLoopbackICE(t))
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	cases := []struct {
		name   string
		url    string
		header http.Header
	}{
		{"missing_header", wsURL, nil},
		{"wrong_bearer", wsURL, http.Header{"Authorization": {"Bearer " + strings.Repeat("W", 40)}}},
		{"query_string_token", wsURL + "?token=" + token + "&access_token=" + token, nil},
		{"non_bearer_scheme", wsURL, http.Header{"Authorization": {"Basic " + token}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws, resp, err := websocket.Dial(ctx, tc.url, &websocket.DialOptions{HTTPHeader: tc.header})
			if ws != nil {
				_ = ws.CloseNow()
			}
			if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: expected HTTP 401, got err=%v resp=%v", tc.name, err, resp)
			}
		})
	}

	// RFC 7235 case-insensitive auth scheme ("bearer <token>") is accepted by design (socket.go:50).
	t.Run("lowercase_bearer_scheme_allowed_by_design", func(t *testing.T) {
		ws, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Authorization": {"bearer " + token}},
		})
		if err != nil {
			t.Fatalf("lowercase bearer failed: err=%v resp=%v", err, resp)
		}
		defer ws.CloseNow()
		_, raw, err := ws.Read(ctx)
		mustOK(t, err)
		var ch protocol.Message
		mustOK(t, json.Unmarshal(raw, &ch))
		if ch.Type != "auth.challenge" {
			t.Fatalf("expected auth.challenge, got %s", ch.Type)
		}
	})
}

func TestSignalSelfLoginDeviceIDMismatchRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token := strings.Repeat("D", 40)
	h := signal.NewSelfHosted(token, newLoopbackICE(t))
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	otherID, err := identity.SelfDeviceID(otherPub)
	mustOK(t, err)

	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	mustOK(t, err)
	defer ws.CloseNow()

	_, raw, err := ws.Read(ctx)
	mustOK(t, err)
	var ch protocol.Message
	mustOK(t, json.Unmarshal(raw, &ch))

	// Sign with priv, present pub, but claim another device's sdev_ ID in From.
	loginMsg := protocol.Message{Type: "auth.login", Connection: ch.Connection, From: otherID, To: "signal"}
	mustOK(t, loginMsg.Sign(priv, protocol.Encode(map[string]string{
		"role":       "mobile",
		"public_key": base64.RawURLEncoding.EncodeToString(pub),
	})))
	mustOK(t, ws.Write(ctx, websocket.MessageText, protocol.Encode(loginMsg)))

	_, _, err = ws.Read(ctx)
	if err == nil || websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("expected policy violation close for mismatched From, got err=%v status=%v", err, websocket.CloseStatus(err))
	}
}

func TestSignalChallengeReplayRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signer := identitytest.NewAuthority(10 * time.Minute)
	h := signal.New(signer.PublicKey(), nil, nil)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	now := time.Now()
	cert, err := signer.IssueWithKey("https://issuer.example", "guest", pub, now)
	mustOK(t, err)
	p, err := identity.VerifyCertificate(cert, signer.PublicKey(), now)
	mustOK(t, err)
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)
	lease, _, err := signer.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	mustOK(t, err)
	creds, err := endpoint.OpenCredentials(cert, priv, signer.PublicKey(), now)
	mustOK(t, err)

	// Connection 1 captures signed auth.login bound to challenge 1, then drops.
	ws1, _, err := websocket.Dial(ctx, wsURL, nil)
	mustOK(t, err)
	_, raw1, err := ws1.Read(ctx)
	mustOK(t, err)
	var ch1 protocol.Message
	mustOK(t, json.Unmarshal(raw1, &ch1))
	capturedLogin, err := creds.Login(ch1, "mobile", lease)
	mustOK(t, err)
	_ = ws1.CloseNow()

	// Connection 2 replays the exact auth.login from connection 1 against a new challenge.
	ws2, _, err := websocket.Dial(ctx, wsURL, nil)
	mustOK(t, err)
	defer ws2.CloseNow()
	_, _, err = ws2.Read(ctx)
	mustOK(t, err)
	mustOK(t, ws2.Write(ctx, websocket.MessageText, protocol.Encode(capturedLogin)))

	_, _, err = ws2.Read(ctx)
	if err == nil || websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("expected policy violation close on replayed challenge response, got err=%v status=%v", err, websocket.CloseStatus(err))
	}
}

func TestSignalOfficialWrongCredentialsRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cnAuthority := identitytest.NewAuthority(10 * time.Minute)
	otherAuthority := identitytest.NewAuthority(10 * time.Minute)
	const allowedIssuer = "https://auth.cn.example/realms/vanora"

	h := signal.New(cnAuthority.PublicKey(), nil, nil)
	h.RequireIssuer(allowedIssuer)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	dialWithCreds := func(t *testing.T, auth *identitytest.Authority, issuer string, cert string, priv ed25519.PrivateKey, lease string) {
		t.Helper()
		ws, _, err := websocket.Dial(ctx, wsURL, nil)
		mustOK(t, err)
		defer ws.CloseNow()
		_, raw, err := ws.Read(ctx)
		mustOK(t, err)
		var ch protocol.Message
		mustOK(t, json.Unmarshal(raw, &ch))
		p, _ := identity.VerifyCertificate(cert, auth.PublicKey(), time.Now())
		devID := p.DeviceID
		if devID == "" {
			// Compute deterministic devID even if cert is expired/future-dated.
			pub := priv.Public().(ed25519.PublicKey)
			devID, err = auth.DeviceID(issuer, "user-1", pub)
			mustOK(t, err)
		}
		m := protocol.Message{
			Type:        "auth.login",
			Connection:  ch.Connection,
			From:        devID,
			To:          "signal",
			Certificate: cert,
		}
		mustOK(t, m.Sign(priv, protocol.Encode(map[string]string{"role": "mobile", "lease": lease})))
		mustOK(t, ws.Write(ctx, websocket.MessageText, protocol.Encode(m)))

		_, replyRaw, err := ws.Read(ctx)
		if err == nil {
			t.Fatalf("expected close, but server replied: %s", replyRaw)
		}
		if status := websocket.CloseStatus(err); status != websocket.StatusPolicyViolation {
			t.Fatalf("expected StatusPolicyViolation (1008), got %v (%v)", status, err)
		}
	}

	makeValid := func(auth *identitytest.Authority, issuer string, iat, exp time.Time) (string, ed25519.PrivateKey, identity.Principal) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		mustOK(t, err)
		devID, err := auth.DeviceID(issuer, "user-1", pub)
		mustOK(t, err)
		header := map[string]string{"alg": "EdDSA", "typ": "vanc+v1", "kid": auth.KeyID()}
		claims := map[string]any{
			"v":   1,
			"iss": issuer,
			"sub": "user-1",
			"dev": devID,
			"pk":  base64.RawURLEncoding.EncodeToString(pub),
			"aud": identity.CertificateAudience,
			"iat": iat.Unix(),
			"exp": exp.Unix(),
		}
		cert, err := auth.SignRaw(identity.CertificatePrefix, header, claims)
		mustOK(t, err)
		return cert, priv, identity.Principal{
			Issuer:    issuer,
			Subject:   "user-1",
			DeviceID:  devID,
			PublicKey: pub,
			Expires:   exp,
		}
	}

	makeLease := func(auth *identitytest.Authority, p identity.Principal, cert string, iat, exp time.Time) string {
		nonceBytes := make([]byte, 24)
		_, _ = rand.Read(nonceBytes)
		certHash := func(c string) string {
			// Reuse IssueLease when within valid range; use SignRaw for >60s.
			l, _, err := auth.IssueLease(p, c, base64.RawURLEncoding.EncodeToString(nonceBytes), iat, exp.Sub(iat))
			if err == nil {
				return l
			}
			rawHash, _ := auth.SignRaw(identity.LeasePrefix,
				map[string]string{"alg": "EdDSA", "typ": "vanl+v1", "kid": auth.KeyID()},
				map[string]any{
					"v":   1,
					"aud": identity.CertificateAudience,
					"uid": p.RemoteUserID(),
					"dev": p.DeviceID,
					"ch":  base64.RawURLEncoding.EncodeToString(sha256Sum([]byte(c))),
					"n":   base64.RawURLEncoding.EncodeToString(nonceBytes),
					"iat": iat.Unix(),
					"exp": exp.Unix(),
				},
			)
			return rawHash
		}
		return certHash(cert)
	}

	now := time.Now().UTC()

	t.Run("wrong_authority", func(t *testing.T) {
		cert, priv, p := makeValid(otherAuthority, allowedIssuer, now, now.Add(10*time.Minute))
		lease := makeLease(otherAuthority, p, cert, now, now.Add(60*time.Second))
		dialWithCreds(t, otherAuthority, allowedIssuer, cert, priv, lease)
	})

	t.Run("wrong_issuer", func(t *testing.T) {
		const wrongIss = "https://auth.global.example/realms/vanora"
		cert, priv, p := makeValid(cnAuthority, wrongIss, now, now.Add(10*time.Minute))
		lease := makeLease(cnAuthority, p, cert, now, now.Add(60*time.Second))
		dialWithCreds(t, cnAuthority, wrongIss, cert, priv, lease)
	})

	t.Run("expired_cert", func(t *testing.T) {
		cert, priv, p := makeValid(cnAuthority, allowedIssuer, now.Add(-12*time.Minute), now.Add(-2*time.Minute))
		lease := makeLease(cnAuthority, p, cert, now.Add(-3*time.Minute), now.Add(30*time.Second))
		// IssueLease caps at cert expiry, so mint lease via SignRaw directly.
		nonce := make([]byte, 24)
		_, _ = rand.Read(nonce)
		lease, err := cnAuthority.SignRaw(identity.LeasePrefix,
			map[string]string{"alg": "EdDSA", "typ": "vanl+v1", "kid": cnAuthority.KeyID()},
			map[string]any{
				"v":   1,
				"aud": identity.CertificateAudience,
				"uid": p.RemoteUserID(),
				"dev": p.DeviceID,
				"ch":  base64.RawURLEncoding.EncodeToString(sha256Sum([]byte(cert))),
				"n":   base64.RawURLEncoding.EncodeToString(nonce),
				"iat": now.Unix(),
				"exp": now.Add(30 * time.Second).Unix(),
			},
		)
		mustOK(t, err)
		dialWithCreds(t, cnAuthority, allowedIssuer, cert, priv, lease)
	})

	t.Run("lease_bound_to_different_cert", func(t *testing.T) {
		certA, privA, pA := makeValid(cnAuthority, allowedIssuer, now, now.Add(10*time.Minute))
		certB, _, _ := makeValid(cnAuthority, allowedIssuer, now.Add(-time.Second), now.Add(10*time.Minute))
		leaseForB := makeLease(cnAuthority, pA, certB, now, now.Add(60*time.Second))
		dialWithCreds(t, cnAuthority, allowedIssuer, certA, privA, leaseForB)
	})

	t.Run("lease_lifetime_over_60s", func(t *testing.T) {
		cert, priv, p := makeValid(cnAuthority, allowedIssuer, now, now.Add(10*time.Minute))
		lease := makeLease(cnAuthority, p, cert, now, now.Add(120*time.Second))
		dialWithCreds(t, cnAuthority, allowedIssuer, cert, priv, lease)
	})

	t.Run("cert_iat_over_30s_in_future", func(t *testing.T) {
		cert, priv, p := makeValid(cnAuthority, allowedIssuer, now.Add(2*time.Minute), now.Add(12*time.Minute))
		lease := makeLease(cnAuthority, p, cert, now, now.Add(60*time.Second))
		dialWithCreds(t, cnAuthority, allowedIssuer, cert, priv, lease)
	})
}

func TestSignalDuplicateDeviceIDAndStaleReconnectWindow(t *testing.T) {
	t.Run("duplicate_rejected_first_stays_alive", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		signer := identitytest.NewAuthority(10 * time.Minute)
		h := signal.New(signer.PublicKey(), nil, nil)
		go h.Run(ctx)
		srv := httptest.NewServer(h)
		defer srv.Close()
		wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		mustOK(t, err)
		now := time.Now()
		cert, err := signer.IssueWithKey("https://issuer.example", "owner", pub, now)
		mustOK(t, err)
		p, err := identity.VerifyCertificate(cert, signer.PublicKey(), now)
		mustOK(t, err)
		nonce := make([]byte, 24)
		_, _ = rand.Read(nonce)
		lease, _, err := signer.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
		mustOK(t, err)
		creds, err := endpoint.OpenCredentials(cert, priv, signer.PublicKey(), now)
		mustOK(t, err)

		ws1, _, err := websocket.Dial(ctx, wsURL, nil)
		mustOK(t, err)
		defer ws1.CloseNow()
		_, chRaw1, err := ws1.Read(ctx)
		mustOK(t, err)
		var ch1 protocol.Message
		mustOK(t, json.Unmarshal(chRaw1, &ch1))
		login1, err := creds.Login(ch1, "desktop", lease)
		mustOK(t, err)
		mustOK(t, ws1.Write(ctx, websocket.MessageText, protocol.Encode(login1)))
		_, okRaw1, err := ws1.Read(ctx)
		mustOK(t, err)
		var ok1 protocol.Message
		mustOK(t, json.Unmarshal(okRaw1, &ok1))
		if ok1.Type != "auth.ok" {
			t.Fatalf("first login got %s", ok1.Type)
		}

		// Second login with same key/device_id must be rejected.
		ws2, _, err := websocket.Dial(ctx, wsURL, nil)
		mustOK(t, err)
		defer ws2.CloseNow()
		_, chRaw2, err := ws2.Read(ctx)
		mustOK(t, err)
		var ch2 protocol.Message
		mustOK(t, json.Unmarshal(chRaw2, &ch2))
		login2, err := creds.Login(ch2, "desktop", lease)
		mustOK(t, err)
		mustOK(t, ws2.Write(ctx, websocket.MessageText, protocol.Encode(login2)))
		if _, _, err := ws2.Read(ctx); err == nil || websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("expected duplicate login policy violation, got err=%v status=%v", err, websocket.CloseStatus(err))
		}

		// First connection must still function (device.online succeeds).
		online, err := creds.Online("workstation", nil)
		mustOK(t, err)
		mustOK(t, ws1.Write(ctx, websocket.MessageText, protocol.Encode(online)))
		_, regRaw, err := ws1.Read(ctx)
		mustOK(t, err)
		var reg protocol.Message
		mustOK(t, json.Unmarshal(regRaw, &reg))
		if reg.Type != "device.registered" {
			t.Fatalf("first connection impaired after duplicate attempt: got %s", reg.Type)
		}
	})

	t.Run("stale_socket_silent_drop_reconnect_window", func(t *testing.T) {
		// Measures how long a legitimate client is locked out if its old TCP
		// connection vanishes silently without FIN/RST (half-open blackhole).
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()

		token := strings.Repeat("W", 40)
		h := signal.NewSelfHosted(token, nil)
		go h.Run(ctx)
		srv := httptest.NewServer(h)
		defer srv.Close()

		srvAddr := strings.TrimPrefix(srv.URL, "http://")
		proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
		mustOK(t, err)
		defer proxyLn.Close()

		var dropMu sync.Mutex
		blackhole := false
		var heldServerConns []net.Conn
		t.Cleanup(func() {
			dropMu.Lock()
			for _, c := range heldServerConns {
				_ = c.Close()
			}
			dropMu.Unlock()
		})

		go func() {
			for {
				cliConn, err := proxyLn.Accept()
				if err != nil {
					return
				}
				srvConn, err := net.Dial("tcp", srvAddr)
				if err != nil {
					_ = cliConn.Close()
					continue
				}
				dropMu.Lock()
				heldServerConns = append(heldServerConns, srvConn)
				dropMu.Unlock()
				go func() {
					_, _ = io.Copy(srvConn, cliConn)
					// When blackholed, intentionally keep srvConn open so the server sees no EOF.
					dropMu.Lock()
					bh := blackhole
					dropMu.Unlock()
					if !bh {
						_ = srvConn.Close()
					}
				}()
				go func() {
					buf := make([]byte, 4096)
					for {
						n, err := srvConn.Read(buf)
						if err != nil {
							_ = cliConn.Close()
							return
						}
						dropMu.Lock()
						bh := blackhole
						dropMu.Unlock()
						if bh {
							// Silently swallow server PING frames without answering or closing srvConn.
							continue
						}
						if _, err := cliConn.Write(buf[:n]); err != nil {
							return
						}
					}
				}()
			}
		}()

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		mustOK(t, err)
		devID, err := identity.SelfDeviceID(pub)
		mustOK(t, err)
		proxyWSURL := "ws://" + proxyLn.Addr().String()
		directWSURL := "ws" + strings.TrimPrefix(srv.URL, "http")

		tryLogin := func(targetURL string) (*websocket.Conn, error) {
			ws, _, err := websocket.Dial(ctx, targetURL, &websocket.DialOptions{
				HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
			})
			if err != nil {
				return nil, err
			}
			_, raw, err := ws.Read(ctx)
			if err != nil {
				_ = ws.CloseNow()
				return nil, err
			}
			var ch protocol.Message
			if err := json.Unmarshal(raw, &ch); err != nil {
				_ = ws.CloseNow()
				return nil, err
			}
			m := protocol.Message{Type: "auth.login", Connection: ch.Connection, From: devID, To: "signal"}
			if err := m.Sign(priv, protocol.Encode(map[string]string{
				"role":       "desktop",
				"public_key": base64.RawURLEncoding.EncodeToString(pub),
			})); err != nil {
				_ = ws.CloseNow()
				return nil, err
			}
			if err := ws.Write(ctx, websocket.MessageText, protocol.Encode(m)); err != nil {
				_ = ws.CloseNow()
				return nil, err
			}
			_, okRaw, err := ws.Read(ctx)
			if err != nil {
				_ = ws.CloseNow()
				return nil, err
			}
			var reply protocol.Message
			if err := json.Unmarshal(okRaw, &reply); err != nil || reply.Type != "auth.ok" {
				_ = ws.CloseNow()
				return nil, errors.New("not auth.ok")
			}
			return ws, nil
		}

		ws1, err := tryLogin(proxyWSURL)
		mustOK(t, err)
		dropMu.Lock()
		blackhole = true
		dropMu.Unlock()
		_ = ws1.CloseNow() // closes client->proxy only; proxy keeps srvConn silent.

		start := time.Now()
		var blockedFor time.Duration
		for {
			if time.Since(start) > 25*time.Second {
				t.Fatalf("reconnect still blocked after %s", time.Since(start))
			}
			ws2, err := tryLogin(directWSURL)
			if err == nil {
				_ = ws2.CloseNow()
				blockedFor = time.Since(start)
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Logf("stale half-open socket blocked legitimate reconnect for %s (fast duplicate-login liveness probe)", blockedFor.Round(100*time.Millisecond))
		if blockedFor > 5*time.Second {
			sectest.Finding(t, "VR-SEC-08", "stale socket blocked reconnect for %s (>5s) (socket.go:151-160,191-208)", blockedFor.Round(100*time.Millisecond))
		}
	})
}

func TestSignalCrossLinkInjectionAndSequenceReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	signer := identitytest.NewAuthority(10 * time.Minute)
	h := signal.New(signer.PublicKey(), newEntitlementVerifier(t, false), newLoopbackICE(t))
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	host := loginOfficial(t, ctx, wsURL, "desktop", "https://issuer.example", "owner", signer)
	guest := loginOfficial(t, ctx, wsURL, "mobile", "https://issuer.example", "guest", signer)
	attacker := loginOfficial(t, ctx, wsURL, "mobile", "https://issuer.example", "attacker", signer)

	// Host only authorizes guest, NOT attacker.
	online, err := host.creds.Online("workstation", []string{guest.creds.UserID()})
	mustOK(t, err)
	host.send(t, online)
	host.readExpect(t, "device.registered")

	// Unauthorized connect.request on official channel must return generic device_unavailable.
	_, unauthReq, err := attacker.creds.Request(host.creds.DeviceID(), host.creds.UserID())
	mustOK(t, err)
	attacker.send(t, unauthReq)
	if got := string(attacker.readExpect(t, "error").Data); got != `"device_unavailable"` {
		t.Fatalf("unauthorized connect.request got %s, want \"device_unavailable\"", got)
	}
	// Nonexistent target must return the exact same generic error (anti-enumeration).
	_, ghostReq, err := attacker.creds.Request("dev_aaaaaaaaaaaaaaaaaaaaaaaaaa", host.creds.UserID())
	mustOK(t, err)
	attacker.send(t, ghostReq)
	if got := string(attacker.readExpect(t, "error").Data); got != `"device_unavailable"` {
		t.Fatalf("nonexistent target got %s, want \"device_unavailable\"", got)
	}

	// Establish authorized link between guest and host.
	phoneSess, req, err := guest.creds.Request(host.creds.DeviceID(), host.creds.UserID())
	mustOK(t, err)
	guest.send(t, req)
	gotReq := host.readExpect(t, "connect.request")
	deskSess, accept, err := host.creds.Accept(gotReq, func(id string) bool { return id == guest.creds.UserID() }, time.Now())
	mustOK(t, err)
	host.send(t, accept)
	mustOK(t, phoneSess.Accepted(guest.readExpect(t, "connect.accept"), time.Now()))
	guest.readExpect(t, "ice.config")
	host.readExpect(t, "ice.config")

	connID := phoneSess.ID()

	// Guest sends valid round 1 offer (seq=2), then replays seq=2 and tries skipping round.
	offer1, err := phoneSess.Seal("rtc.offer", []byte(`{"type":"offer","sdp":"v=0"}`))
	mustOK(t, err)
	guest.send(t, offer1)
	forwardedOffer := host.readExpect(t, "rtc.offer")
	if _, err := deskSess.Open(forwardedOffer, time.Now()); err != nil {
		t.Fatalf("host open valid offer: %v", err)
	}

	// Seq replay (same seq=2, round=1).
	guest.send(t, offer1)
	if got := string(guest.readExpect(t, "error").Data); got != `"invalid_peer_or_sequence"` {
		t.Fatalf("seq replay got %s, want \"invalid_peer_or_sequence\"", got)
	}

	// Round skip: endpoint.Session refuses offer round=2 before host answers round=1.
	if _, err := phoneSess.Seal("rtc.offer", []byte(`{"type":"offer","sdp":"v=0"}`)); err == nil {
		t.Fatalf("endpoint.Session allowed offer round skip before answer")
	}

	// ice.refresh before 10s interval must fail with refresh_unavailable.
	guest.send(t, protocol.Message{Type: "ice.refresh", Connection: connID})
	if got := string(guest.readExpect(t, "error").Data); got != `"refresh_unavailable"` {
		t.Fatalf("early ice.refresh got %s, want \"refresh_unavailable\"", got)
	}

	// Host cannot call ice.refresh.
	host.send(t, protocol.Message{Type: "ice.refresh", Connection: connID})
	if got := string(host.readExpect(t, "error").Data); got != `"refresh_unavailable"` {
		t.Fatalf("host ice.refresh got %s, want \"refresh_unavailable\"", got)
	}

	// Verify host receives no unexpected attacker traffic.
	readTimeoutCtx, readCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer readCancel()
	if _, raw, err := host.ws.Read(readTimeoutCtx); err == nil {
		t.Fatalf("host unexpectedly received injected message: %s", raw)
	}
}

func TestSignalCrossLinkInjectionRawSigned(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token := strings.Repeat("X", 40)
	h := signal.NewSelfHosted(token, newLoopbackICE(t))
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	desk := dialSelfClient(t, ctx, wsURL, token, "desktop")
	phone := dialSelfClient(t, ctx, wsURL, token, "mobile")
	attacker := dialSelfClient(t, ctx, wsURL, token, "mobile")

	card := protocol.Message{Type: "device.card", From: desk.id, To: "self"}
	mustOK(t, card.Sign(desk.priv, []byte("Workstation")))
	desk.send(t, protocol.Message{Type: "device.online", Data: protocol.Encode(map[string]any{"card": card})})
	desk.readExpect(t, "device.registered")

	// Start pending link; test ice.refresh before accept.
	connID := protocol.NewID()
	req := protocol.Message{Type: "connect.request", Connection: connID, From: phone.id, To: desk.id, Seq: 1}
	mustOK(t, req.Sign(phone.priv, []byte(`{"name":"Phone"}`)))
	phone.send(t, req)
	desk.readExpect(t, "connect.request")

	phone.send(t, protocol.Message{Type: "ice.refresh", Connection: connID})
	if got := string(phone.readExpect(t, "error").Data); got != `"refresh_unavailable"` {
		t.Fatalf("pre-accept ice.refresh got %s, want \"refresh_unavailable\"", got)
	}

	// Attacker tries to accept or inject offer into pending link.
	attAccept := protocol.Message{Type: "connect.accept", Connection: connID, From: attacker.id, To: phone.id, Seq: 1}
	mustOK(t, attAccept.Sign(attacker.priv, []byte(`{"nonce":"`+protocol.NewID()+`"}`)))
	attacker.send(t, attAccept)
	if got := string(attacker.readExpect(t, "error").Data); got != `"invalid_accept"` {
		t.Fatalf("attacker connect.accept got %s, want \"invalid_accept\"", got)
	}

	// Accept real link.
	accept := protocol.Message{Type: "connect.accept", Connection: connID, From: desk.id, To: phone.id, Seq: 1}
	mustOK(t, accept.Sign(desk.priv, []byte(`{"nonce":"`+protocol.NewID()+`"}`)))
	desk.send(t, accept)
	phone.readExpect(t, "connect.accept")
	phone.readExpect(t, "ice.config")
	desk.readExpect(t, "ice.config")

	// Attacker tries signed rtc.offer and rtc.candidate on victim connID.
	for _, typ := range []string{"rtc.offer", "rtc.candidate"} {
		inj := protocol.Message{Type: typ, Connection: connID, From: attacker.id, To: desk.id, Round: 1, Seq: 1}
		mustOK(t, inj.Sign(attacker.priv, []byte(`{"evil":1}`)))
		attacker.send(t, inj)
		if got := string(attacker.readExpect(t, "error").Data); got != `"unknown_connection"` {
			t.Fatalf("attacker %s on victim connID got %s, want \"unknown_connection\"", typ, got)
		}
	}

	// Phone sends offer with wrong `to` (attacker instead of desk).
	badTo := protocol.Message{Type: "rtc.offer", Connection: connID, From: phone.id, To: attacker.id, Round: 1, Seq: 2}
	mustOK(t, badTo.Sign(phone.priv, []byte(`{"sdp":"v=0"}`)))
	phone.send(t, badTo)
	if got := string(phone.readExpect(t, "error").Data); got != `"invalid_peer_or_sequence"` {
		t.Fatalf("wrong To got %s, want \"invalid_peer_or_sequence\"", got)
	}

	// Phone sends offer round=2 (skipping round=1).
	skipRound := protocol.Message{Type: "rtc.offer", Connection: connID, From: phone.id, To: desk.id, Round: 2, Seq: 2}
	mustOK(t, skipRound.Sign(phone.priv, []byte(`{"sdp":"v=0"}`)))
	phone.send(t, skipRound)
	if got := string(phone.readExpect(t, "error").Data); got != `"invalid_round"` {
		t.Fatalf("round skip got %s, want \"invalid_round\"", got)
	}

	// Valid round 1 offer (seq=2), then replay seq=2.
	goodOffer := protocol.Message{Type: "rtc.offer", Connection: connID, From: phone.id, To: desk.id, Round: 1, Seq: 2}
	mustOK(t, goodOffer.Sign(phone.priv, []byte(`{"sdp":"v=0"}`)))
	phone.send(t, goodOffer)
	desk.readExpect(t, "rtc.offer")

	phone.send(t, goodOffer)
	if got := string(phone.readExpect(t, "error").Data); got != `"invalid_peer_or_sequence"` {
		t.Fatalf("seq replay got %s, want \"invalid_peer_or_sequence\"", got)
	}

	// Attacker and desktop must not receive leaked frames.
	quietCtx, quietCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer quietCancel()
	if _, raw, err := attacker.ws.Read(quietCtx); err == nil {
		t.Fatalf("attacker unexpectedly received frame: %s", raw)
	}
	if _, raw, err := desk.ws.Read(quietCtx); err == nil {
		t.Fatalf("desktop unexpectedly received injected frame: %s", raw)
	}
}

func TestSignalFrameAndRateLimits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token := strings.Repeat("F", 40)
	h := signal.NewSelfHosted(token, nil)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	t.Run("oversized_frame_closed_1009", func(t *testing.T) {
		c := dialSelfClient(t, ctx, wsURL, token, "mobile")
		big := make([]byte, 200*1024)
		for i := range big {
			big[i] = 'a'
		}
		// Write may succeed locally before server's Read catches the 192 KiB limit and closes.
		_ = c.ws.Write(ctx, websocket.MessageText, big)
		_, _, err := c.ws.Read(ctx)
		if err == nil {
			t.Fatal("expected oversized frame to close connection")
		}
		if st := websocket.CloseStatus(err); st != -1 && st != websocket.StatusMessageTooBig && st != websocket.StatusAbnormalClosure {
			t.Logf("oversized frame close status=%v err=%v", st, err)
		}
	})

	t.Run("binary_frame_closed", func(t *testing.T) {
		c := dialSelfClient(t, ctx, wsURL, token, "mobile")
		mustOK(t, c.ws.Write(ctx, websocket.MessageBinary, []byte{0x01, 0x02, 0x03}))
		if _, _, err := c.ws.Read(ctx); err == nil {
			t.Fatal("expected binary frame to close connection")
		}
	})

	t.Run("rate_limit_over_120_msg_per_sec_closed", func(t *testing.T) {
		c := dialSelfClient(t, ctx, wsURL, token, "mobile")
		bad := protocol.Encode(protocol.Message{Type: "devices.list"})
		var closed bool
		for i := 0; i < 140; i++ {
			if err := c.ws.Write(ctx, websocket.MessageText, bad); err != nil {
				closed = true
				break
			}
		}
		if !closed {
			// Drain replies until the server closes the connection.
			readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
			defer readCancel()
			for {
				if _, _, err := c.ws.Read(readCtx); err != nil {
					closed = true
					break
				}
			}
		}
		if !closed {
			t.Fatal("expected >120 msg/s flood to close connection")
		}
	})
}

func TestSignalPreAuthSlotExhaustion(t *testing.T) {
	sectest.RequireHeavy(t)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	signer := identitytest.NewAuthority(10 * time.Minute)
	h := signal.New(signer.PublicKey(), nil, nil)
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	conns := make([]*websocket.Conn, 0, 1024)
	defer func() {
		for _, ws := range conns {
			_ = ws.CloseNow()
		}
	}()

	// Open up to 1024 unauthenticated WebSockets from 127.0.0.1 and leave challenges unanswered.
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i := 0; i < 1024; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ws, _, err := websocket.Dial(ctx, wsURL, nil)
			if err == nil {
				mu.Lock()
				conns = append(conns, ws)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	t.Logf("single-IP unauthenticated attacker held %d/1024 pre-auth sockets", len(conns))

	// Legitimate client from a distinct source IP must still be able to connect
	// and complete full official authentication despite the single-source flood.
	legitHTTP := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")},
			}).DialContext,
		},
	}
	wsLegit, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: legitHTTP})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusServiceUnavailable {
			sectest.Finding(t, "VR-SEC-02", "%d unauthenticated sockets exhausted global hub slots and denied legitimate client with HTTP 503 (socket.go:67, hub.go:79)", len(conns))
		}
		t.Fatalf("unexpected error for legitimate client: err=%v resp=%v", err, resp)
	}
	defer wsLegit.CloseNow()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	now := time.Now()
	cert, err := signer.IssueWithKey("https://issuer.example", "legit-user", pub, now)
	mustOK(t, err)
	p, err := identity.VerifyCertificate(cert, signer.PublicKey(), now)
	mustOK(t, err)
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)
	lease, _, err := signer.IssueLease(p, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	mustOK(t, err)
	creds, err := endpoint.OpenCredentials(cert, priv, signer.PublicKey(), now)
	mustOK(t, err)
	_, chRaw, err := wsLegit.Read(ctx)
	mustOK(t, err)
	var ch protocol.Message
	mustOK(t, json.Unmarshal(chRaw, &ch))
	loginMsg, err := creds.Login(ch, "mobile", lease)
	mustOK(t, err)
	mustOK(t, wsLegit.Write(ctx, websocket.MessageText, protocol.Encode(loginMsg)))
	_, okRaw, err := wsLegit.Read(ctx)
	mustOK(t, err)
	var okMsg protocol.Message
	mustOK(t, json.Unmarshal(okRaw, &okMsg))
	if okMsg.Type != "auth.ok" {
		t.Fatalf("legitimate client login got %s %s, want auth.ok", okMsg.Type, okMsg.Data)
	}
	if len(conns) >= 1024 {
		sectest.Finding(t, "VR-SEC-02", "single source IP opened %d pre-auth sockets without per-IP cap", len(conns))
	}
}

func TestSignalSelfHostLinkSlotPressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token := strings.Repeat("L", 40)
	h := signal.NewSelfHosted(token, newLoopbackICE(t))
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	desk := dialSelfClient(t, ctx, wsURL, token, "desktop")
	card := protocol.Message{Type: "device.card", From: desk.id, To: "self"}
	mustOK(t, card.Sign(desk.priv, []byte("TargetPC")))
	desk.send(t, protocol.Message{Type: "device.online", Data: protocol.Encode(map[string]any{"card": card})})
	desk.readExpect(t, "device.registered")

	// Record incoming connect.request on desktop so we can verify legit phone gets routed.
	legitConnID := protocol.NewID()
	legitRouted := make(chan struct{}, 1)
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			_, raw, err := desk.ws.Read(ctx)
			if err != nil {
				return
			}
			var m protocol.Message
			if json.Unmarshal(raw, &m) == nil && m.Type == "connect.request" && m.Connection == legitConnID {
				select {
				case legitRouted <- struct{}{}:
				default:
				}
			}
		}
	}()

	// 4 unpaired attacker mobile identities (8 links each = 32 pending links) attempt to saturate host's 32-link cap.
	for a := 0; a < 4; a++ {
		attacker := dialSelfClient(t, ctx, wsURL, token, "mobile")
		for j := 0; j < 8; j++ {
			req := protocol.Message{
				Type:       "connect.request",
				Connection: protocol.NewID(),
				From:       attacker.id,
				To:         desk.id,
				Seq:        uint64(j + 1),
			}
			mustOK(t, req.Sign(attacker.priv, []byte(`{"name":"Attacker"}`)))
			attacker.send(t, req)
		}
	}

	// Give the hub a brief moment to process attacker requests before victim dials.
	time.Sleep(150 * time.Millisecond)

	legit := dialSelfClient(t, ctx, wsURL, token, "mobile")
	req := protocol.Message{
		Type:       "connect.request",
		Connection: legitConnID,
		From:       legit.id,
		To:         desk.id,
		Seq:        1,
	}
	mustOK(t, req.Sign(legit.priv, []byte(`{"name":"PairedPhone"}`)))
	legit.send(t, req)

	select {
	case <-legitRouted:
	case <-time.After(1 * time.Second):
		readCtx, readCancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer readCancel()
		_, raw, err := legit.ws.Read(readCtx)
		if err == nil {
			var m protocol.Message
			mustOK(t, json.Unmarshal(raw, &m))
			if m.Type == "error" && string(m.Data) == `"connection_limit"` {
				sectest.Finding(t, "VR-SEC-03", "4 unpaired mobile keys exhausted host's 32 link slots and blocked paired phone with connection_limit (hub.go:130-131,324)")
			}
			t.Fatalf("unexpected reply to legit phone: %s %s", m.Type, m.Data)
		}
		t.Fatal("legitimate phone connect.request was not routed to desktop")
	}
	cancel()
	<-drainDone
}

func TestSignalSelfHostOutBufferOverflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token := strings.Repeat("O", 40)
	h := signal.NewSelfHosted(token, newLoopbackICE(t))
	go h.Run(ctx)
	srv := httptest.NewServer(h)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	desk := dialSelfClient(t, ctx, wsURL, token, "desktop")
	card := protocol.Message{Type: "device.card", From: desk.id, To: "self"}
	mustOK(t, card.Sign(desk.priv, []byte("VictimPC")))
	desk.send(t, protocol.Message{Type: "device.online", Data: protocol.Encode(map[string]any{"card": card})})
	desk.readExpect(t, "device.registered")

	deskClosed := make(chan error, 1)
	go func() {
		for {
			_, _, err := desk.ws.Read(ctx)
			if err != nil {
				deskClosed <- err
				return
			}
		}
	}()

	attacker := dialSelfClient(t, ctx, wsURL, token, "mobile")
	// Loop connect.request -> connect.close at ~100 msg/s (50 pairs/s) for 5s (just under 120 msg/s limit).
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	end := time.Now().Add(5 * time.Second)
	var seq uint64 = 1
	for time.Now().Before(end) {
		select {
		case <-deskClosed:
			sectest.Finding(t, "VR-SEC-09", "connect.request/connect.close flood under 120 msg/s overflowed host out-buffer and disconnected desktop (hub.go:117-124)")
		case <-ticker.C:
		}
		cid := protocol.NewID()
		req := protocol.Message{Type: "connect.request", Connection: cid, From: attacker.id, To: desk.id, Seq: seq}
		seq++
		mustOK(t, req.Sign(attacker.priv, []byte(`{"name":"Flood"}`)))
		attacker.send(t, req)

		cls := protocol.Message{Type: "connect.close", Connection: cid, From: attacker.id, To: desk.id, Seq: seq}
		seq++
		mustOK(t, cls.Sign(attacker.priv, nil))
		attacker.send(t, cls)
	}

	select {
	case err := <-deskClosed:
		sectest.Finding(t, "VR-SEC-09", "desktop disconnected during under-limit flood: %v", err)
	default:
	}

	// Verify desktop is still responsive by re-registering online.
	deskAlive := dialSelfClient(t, ctx, wsURL, token, "mobile")
	probe := protocol.Message{Type: "connect.request", Connection: protocol.NewID(), From: deskAlive.id, To: desk.id, Seq: 1}
	mustOK(t, probe.Sign(deskAlive.priv, []byte(`{"name":"Probe"}`)))
	deskAlive.send(t, probe)

	select {
	case err := <-deskClosed:
		sectest.Finding(t, "VR-SEC-09", "desktop disconnected shortly after flood: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
}

func sha256Sum(b []byte) []byte {
	_ = bytes.Clone(b)
	sum := sha256.Sum256(b)
	return sum[:]
}
