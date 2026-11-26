package security_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/endpoint"
	"vanora-relay/internal/cftunnel"
	"vanora-relay/internal/cftunnel/sqlstore"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/internal/membership"
	"vanora-relay/internal/signal"
	"vanora-relay/protocol"
)

const tunnelIssuer = "https://authority.example"

type tunnelLookup func(context.Context, string, string) (membership.Entitlement, error)

func (lookup tunnelLookup) Lookup(ctx context.Context, issuer, subject string) (membership.Entitlement, error) {
	return lookup(ctx, issuer, subject)
}

type tunnelSecurityController struct{ *cftunnel.Service }

func (ctrl tunnelSecurityController) AuthorizeVisitor(ctx context.Context, r signal.TunnelAccessRequest) (string, time.Time, error) {
	return ctrl.Service.AuthorizeVisitor(ctx, cftunnel.VisitorRequest{Host: r.Host, Visitor: r.Visitor, HostLease: r.HostLease,
		VisitorLease: r.VisitorLease, Generation: r.Generation, Incarnation: r.Incarnation, Paired: true})
}

func (ctrl tunnelSecurityController) RefreshVisitorAccess(ctx context.Context, r signal.TunnelAccessRequest) (string, time.Time, error) {
	return ctrl.AuthorizeVisitor(ctx, r)
}

type tunnelSecurityRig struct {
	authority *identitytest.Authority
	scope     cftunnel.Scope
	crypto    *cftunnel.Crypto
	service   *cftunnel.Service
	store     *sqlstore.Store
	api       http.Handler
	hub       *signal.Hub
}

func newTunnelSecurityRig(t *testing.T, lookup tunnelLookup) tunnelSecurityRig {
	t.Helper()
	authority := identitytest.NewAuthority(0)
	cfg := cftunnel.Config{Channel: cftunnel.ChannelCN, Mode: cftunnel.ModeManaged, AccountCap: 8, FreeSlots: 1,
		PaidDefaultSlots: 3, BaseDomain: "edge.example", ControlOrigin: "https://relay.example",
		AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), Namespace: "security",
		MasterKey: bytes.Repeat([]byte{7}, 32), EdgeGate: cftunnel.EdgeWorkerHMAC, EdgeKey: bytes.Repeat([]byte{8}, 32)}
	cfg.SiteManifest = &cftunnel.SiteManifest{Channel: cfg.Channel, CAPublicKeySHA256: tunnelDigest(authority.PublicKey()),
		AllowedIssuer: tunnelIssuer, MembershipOrigin: "https://membership.example", ControlOrigin: cfg.ControlOrigin,
		AccountID: cfg.AccountID, ZoneID: cfg.ZoneID, BaseDomain: cfg.BaseDomain, Namespace: cfg.Namespace}
	scope, err := cfg.BuildScope(authority.PublicKey(), tunnelIssuer, "https://membership.example")
	mustOK(t, err)
	store, err := sqlstore.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "security.db"), sqlstore.Options{})
	mustOK(t, err)
	t.Cleanup(func() { mustOK(t, store.Close()) })
	mustOK(t, store.EnsureScope(t.Context(), scope))
	crypto, err := cftunnel.NewCrypto(cfg.MasterKey, cfg.EdgeKey, nil)
	mustOK(t, err)
	hub := signal.New(authority.PublicKey(), nil, nil)
	hub.RequireIssuer(tunnelIssuer)
	var noCloudflare struct{ cftunnel.Cloudflare }
	service, err := cftunnel.NewService(cfg, scope, store, noCloudflare, crypto, cftunnel.ServiceOptions{
		Membership: lookup,
		RuntimeChecker: func(_ context.Context, device, keyHash, runtimeID string, now time.Time) bool {
			return hub.HasActiveTunnelRuntime(device, keyHash, runtimeID, now)
		},
	})
	mustOK(t, err)
	hub.ConfigureTunnel(tunnelSecurityController{service})
	return tunnelSecurityRig{authority, scope, crypto, service, store, cftunnel.NewHTTPHandler(service, authority.PublicKey(), ""), hub}
}

func tunnelDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

type tunnelCredentials struct {
	principal   identity.Principal
	cert, lease string
	key         ed25519.PrivateKey
	ca          ed25519.PublicKey
}

func tunnelIdentity(t *testing.T, ca *identitytest.Authority, issuer, subject string) tunnelCredentials {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	mustOK(t, err)
	now := time.Now()
	cert, err := ca.IssueWithKey(issuer, subject, pub, now)
	mustOK(t, err)
	p, err := identity.VerifyCertificate(cert, ca.PublicKey(), now)
	mustOK(t, err)
	lease, _, err := ca.IssueLease(p, cert, "MDEyMzQ1Njc4OWFiY2RlZg", now, time.Minute)
	mustOK(t, err)
	return tunnelCredentials{p, cert, lease, priv, ca.PublicKey()}
}

func (rig tunnelSecurityRig) ready(t *testing.T, host tunnelCredentials) cftunnel.Allocation {
	t.Helper()
	owner, device := host.principal.RemoteUserID(), host.principal.DeviceID
	key := cftunnel.AllocationKey{ScopeID: rig.scope.ID, DeviceID: device}
	label, hostname := rig.crypto.DeriveHostname(rig.scope.ID, owner, device, rig.scope.BaseDomain)
	_, err := rig.store.Claim(t.Context(), cftunnel.ClaimCommand{AllocationKey: key, OwnerID: owner,
		DeviceKeyHash: tunnelDigest(host.principal.PublicKey), Type: cftunnel.OpProvision, Origin: "127.0.0.1:43210",
		Hostname: hostname, TunnelName: rig.crypto.DeriveTunnelName(rig.scope.Namespace, label, 1), Now: time.Now()},
		cftunnel.ClaimPolicy{OwnerSlots: 1, AccountCap: 8})
	mustOK(t, err)
	rig.complete(t, cftunnel.StateReady)
	allocation, err := rig.store.Get(t.Context(), key)
	mustOK(t, err)
	return allocation
}

func (rig tunnelSecurityRig) complete(t *testing.T, state cftunnel.AllocationState) {
	t.Helper()
	now := time.Now()
	op, err := rig.store.AcquireWork(t.Context(), rig.scope.ID, "test-worker", now, time.Minute)
	mustOK(t, err)
	const step = "test_complete"
	_, err = rig.store.BeginStep(t.Context(), op.Fence(), step, now)
	mustOK(t, err)
	result := cftunnel.FinishStepCommand{Fence: op.Fence(), Name: step, Now: now, FinalState: state}
	if state == cftunnel.StateReady {
		result.Resources = &cftunnel.Resources{TunnelID: "tunnel-" + op.ID, DNSRecordID: "dns-" + op.ID}
	}
	mustOK(t, rig.store.FinishStep(t.Context(), result))
}

func tunnelHTTP(t *testing.T, rig tunnelSecurityRig, actor tunnelCredentials, device, action, body, idem, scope string) *http.Request {
	t.Helper()
	challengeAction, _, _ := strings.Cut(action, "/")
	challenge, _, err := rig.crypto.MintChallenge(scope, challengeAction, actor.principal.DeviceID, time.Now())
	mustOK(t, err)
	path := "/v1/tunnels/" + device + "/" + action
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Vanora-Certificate", actor.cert)
	request.Header.Set("Vanora-Lease", actor.lease)
	request.Header.Set("Vanora-Challenge", challenge)
	request.Header.Set("Vanora-Proof", cftunnel.SignHTTPProof(actor.key, cftunnel.ChannelCN, rig.scope.ControlOrigin,
		path, actor.principal.DeviceID, challenge, tunnelDigest([]byte(body)), idem, tunnelDigest([]byte(actor.cert+"\x00"+actor.lease))))
	if idem != "" {
		request.Header.Set("Idempotency-Key", idem)
	}
	return request
}

func expectTunnelHTTP(t *testing.T, api http.Handler, req *http.Request, status int, code string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRecorder()
	api.ServeHTTP(r, req)
	if r.Code != status || code != "" && !strings.Contains(r.Body.String(), `"error":"`+code+`"`) {
		t.Fatalf("%s %s got %d %s, want %d %q", req.Method, req.URL.Path, r.Code, r.Body, status, code)
	}
	return r
}

func TestManagedTunnelHTTPIsolationAndPoP(t *testing.T) {
	rig := newTunnelSecurityRig(t, func(context.Context, string, string) (membership.Entitlement, error) {
		return membership.Entitlement{}, errors.New("private upstream payload")
	})
	host := tunnelIdentity(t, rig.authority, tunnelIssuer, "owner")
	owner := tunnelIdentity(t, rig.authority, tunnelIssuer, "owner")
	other := tunnelIdentity(t, rig.authority, tunnelIssuer, "other")
	wrongCA := tunnelIdentity(t, identitytest.NewAuthority(0), tunnelIssuer, "owner")
	wrongIssuer := tunnelIdentity(t, rig.authority, "https://other-issuer.example", "owner")
	a := rig.ready(t, host)
	request := func(actor tunnelCredentials, device, action, body, key string) *http.Request {
		t.Helper()
		return tunnelHTTP(t, rig, actor, device, action, body, key, rig.scope.ID)
	}
	expectTunnelHTTP(t, rig.api, request(owner, a.DeviceID, "status", `{}`, ""), 200, "")
	for _, actor := range []tunnelCredentials{wrongCA, wrongIssuer} {
		expectTunnelHTTP(t, rig.api, request(actor, a.DeviceID, "status", `{}`, ""), 401, "invalid_proof")
	}
	expectTunnelHTTP(t, rig.api, tunnelHTTP(t, rig, owner, a.DeviceID, "status", `{}`, "", "other-scope"), 401, "invalid_proof")
	for _, device := range []string{a.DeviceID, "missing"} {
		expectTunnelHTTP(t, rig.api, request(other, device, "status", `{}`, ""), 404, "not_found")
		for _, action := range []string{"disconnect", "deprovision"} {
			expectTunnelHTTP(t, rig.api, request(other, device, action, `{"if_generation":1}`, "other"), 404, "not_found")
		}
	}
	const originBody = `{"origin":"localhost:43210","runtime_id":"runtime","if_generation":1}`
	for _, actor := range []tunnelCredentials{owner, other} {
		for _, action := range []string{"register", "origin", "recover", "resume", "token", "release"} {
			expectTunnelHTTP(t, rig.api, request(actor, a.DeviceID, action, originBody, "cross-device"), 403, "device_binding_mismatch")
		}
	}
	for name, mutate := range map[string]func(*http.Request){
		"path": func(req *http.Request) { req.URL.Path = strings.Replace(req.URL.Path, a.DeviceID, "another-device", 1) },
		"body": func(req *http.Request) { req.Body = io.NopCloser(strings.NewReader(originBody + "\n")) },
		"origin": func(req *http.Request) {
			req.Body = io.NopCloser(strings.NewReader(strings.Replace(originBody, "43210", "1234", 1)))
		},
		"idempotency key": func(req *http.Request) { req.Header.Set("Idempotency-Key", "changed") },
		"challenge": func(req *http.Request) {
			req.Header.Set("Vanora-Challenge", request(host, a.DeviceID, "origin", originBody, "idem").Header.Get("Vanora-Challenge"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := request(host, a.DeviceID, "origin", originBody, "idem")
			mutate(req)
			expectTunnelHTTP(t, rig.api, req, 401, "invalid_proof")
		})
	}
	method := request(host, a.DeviceID, "origin", originBody, "idem")
	method.Method = http.MethodGet
	if r := expectTunnelHTTP(t, rig.api, method, 405, "method_not_allowed"); r.Header().Get("Allow") != http.MethodPost {
		t.Fatal("missing Allow: POST")
	}
	headers := request(host, a.DeviceID, "status", `{}`, "")
	headers.Header.Add("Vanora-Proof", headers.Header.Get("Vanora-Proof"))
	expectTunnelHTTP(t, rig.api, headers, 400, "invalid_headers")
	expectTunnelHTTP(t, rig.api, request(host, a.DeviceID, "release", `{"if_generation":1,"if_generation":1}`, "duplicate"), 400, "invalid_claim")
	replay := request(host, a.DeviceID, "status", `{}`, "")
	expectTunnelHTTP(t, rig.api, replay, 200, "")
	replay.Body = io.NopCloser(strings.NewReader(`{}`))
	expectTunnelHTTP(t, rig.api, replay, 409, "replay_detected")
	retry := expectTunnelHTTP(t, rig.api, request(host, a.DeviceID, "origin", originBody, "outage"), 503, "membership_unavailable")
	if retry.Header().Get("Retry-After") != "1" || !strings.Contains(retry.Body.String(), `"retry_after":1`) || strings.Contains(retry.Body.String(), "private") {
		t.Fatalf("unexpected failure response: %s", retry.Body.String())
	}
	disconnect := expectTunnelHTTP(t, rig.api, request(owner, a.DeviceID, "disconnect", `{"if_generation":1}`, "stop"), 202, "")
	var op cftunnel.OperationView
	mustOK(t, json.Unmarshal(disconnect.Body.Bytes(), &op))
	expectTunnelHTTP(t, rig.api, request(owner, a.DeviceID, "operations/"+op.ID, `{}`, ""), 200, "")
	rig.complete(t, cftunnel.StateSuspended)
	expectTunnelHTTP(t, rig.api, request(owner, a.DeviceID, "deprovision", `{"if_generation":2}`, "remove"), 202, "")
}

func TestManagedTunnelProxySpoofing(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/tunnels/challenge", nil)
	req.RemoteAddr = "203.0.113.17:54321"
	req.Header.Set("X-Forwarded-For", "192.0.2.99, 198.51.100.23, 10.0.0.2")
	cfg := cftunnel.Config{}
	if ip := cfg.ClientIP(req); ip != "203.0.113.17" {
		t.Fatalf("unconfigured proxy header was trusted: %s", ip)
	}
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if ip := cfg.ClientIP(req); ip != "203.0.113.17" {
		t.Fatalf("untrusted remote selected forwarded address: %s", ip)
	}
	req.RemoteAddr = "10.0.0.1:54321"
	if ip := cfg.ClientIP(req); ip != "198.51.100.23" {
		t.Fatalf("trusted proxy selected wrong hop: %s", ip)
	}
	req.Header.Set("X-Forwarded-For", "spoofed-left")
	req.Header.Add("X-Forwarded-For", "198.51.100.23, 10.0.0.2")
	if ip := cfg.ClientIP(req); ip != "198.51.100.23" {
		t.Fatalf("untrusted prefix changed the rate limit source to %s", ip)
	}
	req.Header.Add("X-Forwarded-For", "malformed")
	if ip := cfg.ClientIP(req); ip != "10.0.0.1" {
		t.Fatalf("malformed chain selected %s", ip)
	}
}

func tunnelWSSLogin(t *testing.T, ctx context.Context, url, role string, actor tunnelCredentials, allowed bool) *sigClient {
	t.Helper()
	creds, err := endpoint.OpenCredentials(actor.cert, actor.key, actor.ca, time.Now())
	mustOK(t, err)
	ws, _, err := websocket.Dial(ctx, url, nil)
	mustOK(t, err)
	t.Cleanup(func() { _ = ws.CloseNow() })
	client := &sigClient{ws: ws, ctx: ctx, creds: creds}
	challenge := client.readExpect(t, "auth.challenge")
	login, err := creds.Login(challenge, role, actor.lease)
	mustOK(t, err)
	client.send(t, login)
	if allowed {
		client.readExpect(t, "auth.ok")
	} else {
		_, _, err := ws.Read(ctx)
		if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("foreign WSS credential was accepted: %v", err)
		}
	}
	return client
}

func TestManagedTunnelWSSPolicyAndConcurrency(t *testing.T) {
	type lookupGate struct {
		started chan struct{}
		release chan struct{}
		denied  bool
	}
	var lookupControl atomic.Pointer[lookupGate]
	var paidExpiry = time.Now().Add(35 * time.Second).Truncate(time.Second)
	rig := newTunnelSecurityRig(t, func(ctx context.Context, _, subject string) (membership.Entitlement, error) {
		if subject == "paid-guest" {
			if gate := lookupControl.Swap(nil); gate != nil {
				close(gate.started)
				select {
				case <-ctx.Done():
					return membership.Entitlement{}, ctx.Err()
				case <-gate.release:
				}
				if gate.denied {
					return membership.Entitlement{}, nil
				}
			}
			return membership.Entitlement{RelayAllowed: true, ValidUntil: paidExpiry}, nil
		}
		if subject == "owner" {
			allowed := true
			return membership.Entitlement{TunnelAllowed: &allowed}, nil
		}
		return membership.Entitlement{}, nil
	})
	server := httptest.NewServer(rig.hub)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	t.Cleanup(cancel)
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	for _, actor := range []tunnelCredentials{
		tunnelIdentity(t, identitytest.NewAuthority(0), tunnelIssuer, "owner"),
		tunnelIdentity(t, rig.authority, "https://other-issuer.example", "owner"),
	} {
		tunnelWSSLogin(t, ctx, url, "mobile", actor, false)
	}
	host := tunnelIdentity(t, rig.authority, tunnelIssuer, "owner")
	owner := tunnelIdentity(t, rig.authority, tunnelIssuer, "owner")
	free := tunnelIdentity(t, rig.authority, tunnelIssuer, "free-guest")
	paid := tunnelIdentity(t, rig.authority, tunnelIssuer, "paid-guest")
	a := rig.ready(t, host)
	desktop := tunnelWSSLogin(t, ctx, url, "desktop", host, true)
	ownerConn := tunnelWSSLogin(t, ctx, url, "mobile", owner, true)
	freeConn := tunnelWSSLogin(t, ctx, url, "mobile", free, true)
	paidConn := tunnelWSSLogin(t, ctx, url, "mobile", paid, true)
	online, err := desktop.creds.Online("Test desktop", []string{free.principal.RemoteUserID(), paid.principal.RemoteUserID()})
	mustOK(t, err)
	desktop.send(t, online)
	desktop.readExpect(t, "device.registered")
	send := func(client *sigClient, actor tunnelCredentials, kind, connection, to string, seq uint64, body map[string]any) {
		t.Helper()
		body["aud"] = "tunnel-v1"
		if _, exists := body["scope"]; !exists {
			body["scope"] = rig.scope.ID
		}
		msg := protocol.Message{Type: kind, Connection: connection, From: actor.principal.DeviceID, To: to, Seq: seq}
		mustOK(t, msg.Sign(actor.key, protocol.Encode(body)))
		client.send(t, msg)
	}
	send(desktop, host, "tunnel.host", "", "signal", 1, map[string]any{"scope": "another", "runtime_id": "runtime",
		"socket_id": "socket", "phase": "listening", "generation": a.Generation, "incarnation": a.Incarnation})
	if invalid := desktop.readExpect(t, "error"); string(invalid.Data) != `"invalid_tunnel_record"` {
		t.Fatal(string(invalid.Data))
	}
	send(desktop, host, "tunnel.host", "", "signal", 1, map[string]any{"runtime_id": "runtime", "socket_id": "socket",
		"phase": "listening", "generation": a.Generation, "incarnation": a.Incarnation})
	desktop.readExpect(t, "tunnel.host.ack")
	connect := func(client *sigClient, actor tunnelCredentials) string {
		t.Helper()
		id := protocol.NewID()
		send(client, actor, "tunnel.connect", id, a.DeviceID, 1, map[string]any{
			"client_nonce": "client-nonce", "expected_owner": a.OwnerID, "target_pin_hash": a.DeviceKeyHash})
		return id
	}
	ownerID := connect(ownerConn, owner)
	if offer := desktop.readExpect(t, "tunnel.offer"); offer.Connection != ownerID {
		t.Fatal("free same-owner access was denied")
	}
	connect(freeConn, free)
	if denial := freeConn.readExpect(t, "error"); string(denial.Data) != `"device_unavailable"` {
		t.Fatal(string(denial.Data))
	}
	runWhileLookupBlocked := func(gate *lookupGate, trigger func()) {
		t.Helper()
		lookupControl.Store(gate)
		defer close(gate.release)
		trigger()
		select {
		case <-gate.started:
		case <-ctx.Done():
			t.Fatal("membership lookup never started")
		}
		freeConn.send(t, protocol.Message{Type: "devices.list"})
		checkCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_, raw, err := freeConn.ws.Read(checkCtx)
		mustOK(t, err)
		var msg protocol.Message
		mustOK(t, json.Unmarshal(raw, &msg))
		if msg.Type != "devices.list" {
			t.Fatalf("independent peer got %s", msg.Type)
		}
	}
	var paidID string
	runWhileLookupBlocked(&lookupGate{started: make(chan struct{}), release: make(chan struct{})}, func() {
		paidID = connect(paidConn, paid)
	})
	if offer := desktop.readExpect(t, "tunnel.offer"); offer.Connection != paidID {
		t.Fatal("paid guest did not receive an offer")
	}
	send(desktop, host, "tunnel.permit", paidID, paid.principal.DeviceID, 1, map[string]any{
		"generation": a.Generation, "incarnation": a.Incarnation, "runtime_id": "runtime", "hostname": a.Hostname,
		"jti": "paid-ticket", "client_nonce": "client-nonce", "visitor_key_hash": tunnelDigest(paid.principal.PublicKey),
		"path": "/v1/tunnel/ws", "expires_at": time.Now().Add(10 * time.Second).UTC(),
	})
	target := paidConn.readExpect(t, "tunnel.target")
	var access struct {
		Permit protocol.Message `json:"permit"`
		Ticket string           `json:"edge_ticket"`
		Until  time.Time        `json:"access_until"`
	}
	mustOK(t, json.Unmarshal(target.Data, &access))
	if access.Permit.Certificate != host.cert || !rig.crypto.VerifyEdgeTicket(access.Ticket, a.Hostname, "/v1/tunnel/ws", "paid-ticket", time.Now()) ||
		!access.Until.Equal(paidExpiry) {
		t.Fatalf("incorrect signed target or entitlement window: expiry %v, expected %v", access.Until, paidExpiry)
	}
	timer := time.NewTimer(10*time.Second + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatalf("refresh wait: %v", ctx.Err())
	}
	runWhileLookupBlocked(&lookupGate{started: make(chan struct{}), release: make(chan struct{}), denied: true}, func() {
		send(paidConn, paid, "tunnel.refresh", paidID, a.DeviceID, 2, map[string]any{
			"generation": a.Generation, "incarnation": a.Incarnation, "runtime_id": "runtime", "jti": "paid-ticket"})
	})
	for _, client := range []*sigClient{desktop, paidConn} {
		closed := client.readExpect(t, "tunnel.close")
		if closed.Connection != paidID || !strings.Contains(string(closed.Data), `"reason":"access_revoked"`) {
			t.Fatalf("revoked tunnel remained available: %s", closed.Data)
		}
	}
}
