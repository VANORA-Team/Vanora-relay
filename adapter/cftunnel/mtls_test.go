package cftunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/identity/identitytest"
	"vanora-relay/protocol"
)

type testHandler struct {
	opened, closed chan *Peer
	messages       chan []byte
}

func newTestHandler() *testHandler {
	return &testHandler{opened: make(chan *Peer, 32), closed: make(chan *Peer, 32), messages: make(chan []byte, 32)}
}

func (h *testHandler) Open(peer transport.Peer)                 { h.opened <- peer.(*Peer) }
func (h *testHandler) Message(_ transport.Peer, payload []byte) { h.messages <- payload }
func (h *testHandler) Closed(peer transport.Peer)               { h.closed <- peer.(*Peer) }

func await[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for event")
		var zero T
		return zero
	}
}

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func publicKey(key ed25519.PrivateKey) ed25519.PublicKey { return key.Public().(ed25519.PublicKey) }

func newTestListener(t *testing.T, opts ListenerOptions) (*Listener, *testHandler) {
	t.Helper()
	handler := newTestHandler()
	opts.PrivateKey, opts.Handler = newKey(t), handler
	listener, err := NewListener(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, handler
}

func tunnelOptions(listener *Listener, visitor ed25519.PrivateKey) (Permit, DialOptions) {
	host := publicKey(listener.opts.PrivateKey)
	binding := ConnectionContext{
		Channel: "self", Scope: "test-scope", ConnectionID: protocol.NewID(), Hostname: "peer.example",
		Generation: 1, Incarnation: 2, RuntimeID: protocol.NewID(), JTI: protocol.NewID(),
		HostDeviceID: "host-device", HostKeyHash: KeyHash(host),
		VisitorDeviceID: KeyHash(publicKey(visitor)), VisitorKeyHash: KeyHash(publicKey(visitor)), VisitorRole: "mobile",
	}
	until := time.Now().Add(time.Minute)
	allowed := func() bool { return true }
	return Permit{
			ConnectionContext: binding, VisitorPublicKey: publicKey(visitor), UserID: "visitor-user",
			ExpiresAt: until, AccessUntil: until, Allows: allowed,
		}, DialOptions{
			ConnectionContext: binding, PrivateKey: visitor, HostPublicKey: host, UserID: "host-user",
			AccessUntil: until, Allows: allowed, DialURL: "ws://" + listener.Origin(), Handler: newTestHandler(),
		}
}

func register(t *testing.T, listener *Listener, permit Permit) {
	t.Helper()
	if err := listener.RegisterPermit(permit); err != nil {
		t.Fatal(err)
	}
}

func dialPeer(t *testing.T, opts DialOptions) *Peer {
	t.Helper()
	peer, err := Dial(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	return peer.(*Peer)
}

func TestDialDeferredAttachesBeforeCallbacks(t *testing.T) {
	listener, host := newTestListener(t, ListenerOptions{})
	for _, startPeer := range []bool{false, true} {
		permit, opts := tunnelOptions(listener, newKey(t))
		register(t, listener, permit)
		peer, start, err := DialDeferred(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(peer.Close)
		visitor := opts.Handler.(*testHandler)
		hostPeer := await(t, host.opened)
		if err := hostPeer.Send([]byte("queued"), false); err != nil {
			t.Fatal(err)
		}
		if len(visitor.opened)+len(visitor.messages)+len(visitor.closed) != 0 {
			t.Fatal("deferred peer delivered callbacks before attachment")
		}
		if startPeer {
			start()
			start()
			if await(t, visitor.opened) != peer || string(await(t, visitor.messages)) != "queued" {
				t.Fatal("authenticated peer did not deliver its queued message")
			}
		}
		peer.Close()
		if !startPeer {
			start()
		}
		await(t, host.closed)
		if startPeer {
			await(t, visitor.closed)
		}
		if len(visitor.opened)+len(visitor.messages)+len(visitor.closed) != 0 {
			t.Fatal("unexpected visitor callbacks")
		}
	}
}

type observingProxy struct {
	url    string
	tamper atomic.Bool
	mu     sync.Mutex
	frames [2][][]byte
}

func newObservingProxy(t *testing.T, origin string) *observingProxy {
	t.Helper()
	proxy := &observingProxy{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		originWS, _, err := websocket.Dial(ctx, "ws://"+origin+r.URL.Path, &websocket.DialOptions{
			Host: r.Host, Subprotocols: []string{Subprotocol},
			HTTPHeader: http.Header{
				http.CanonicalHeaderKey(ticketHeader): r.Header.Values(ticketHeader),
				http.CanonicalHeaderKey(proofHeader):  r.Header.Values(proofHeader),
			},
		})
		if err != nil {
			http.Error(w, "proxy origin failed", http.StatusBadGateway)
			return
		}
		defer originWS.CloseNow()
		clientWS, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
		if err != nil {
			return
		}
		defer clientWS.CloseNow()
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			proxy.forward(ctx, clientWS, originWS, 0)
		}()
		proxy.forward(ctx, originWS, clientWS, 1)
		_ = clientWS.CloseNow()
		_ = originWS.CloseNow()
		<-finished
	}))
	t.Cleanup(server.Close)
	proxy.url = "ws" + strings.TrimPrefix(server.URL, "http")
	return proxy
}

func (p *observingProxy) forward(ctx context.Context, from, to *websocket.Conn, direction int) {
	defer to.CloseNow()
	from.SetReadLimit(64 << 10)
	for {
		kind, data, err := from.Read(ctx)
		if err != nil {
			return
		}
		if kind != websocket.MessageBinary {
			return
		}
		p.mu.Lock()
		p.frames[direction] = append(p.frames[direction], bytes.Clone(data))
		p.mu.Unlock()
		if direction == 0 && p.tamper.Swap(false) {
			data[len(data)-1] ^= 1
		}
		if to.Write(ctx, kind, data) != nil {
			return
		}
	}
}

func TestSelfTunnelOverObservingProxy(t *testing.T) {
	listener, hostHandler := newTestListener(t, ListenerOptions{})
	proxy := newObservingProxy(t, listener.Origin())
	permit, opts := tunnelOptions(listener, newKey(t))
	opts.DialURL = proxy.url
	register(t, listener, permit)
	visitor := dialPeer(t, opts)
	host := await(t, hostHandler.opened)
	visitorHandler := opts.Handler.(*testHandler)
	if await(t, visitorHandler.opened) != visitor || visitor.Path() != "cf_tunnel" ||
		host.UserID() != permit.UserID || visitor.UserID() != opts.UserID {
		t.Fatal("wrong peer metadata")
	}
	request := []byte(`{"method":"run.start","prompt":"first-private-vanora-request"}`)
	response := []byte(`{"type":"event","text":"second-private-vanora-result"}`)
	large := bytes.Repeat(response, 2000)
	if err := visitor.Send(request, true); err != nil {
		t.Fatal(err)
	}
	if got := await(t, hostHandler.messages); !bytes.Equal(got, request) {
		t.Fatal("visitor message changed")
	}
	if err := host.Send(large, false); err != nil {
		t.Fatal(err)
	}
	if got := await(t, visitorHandler.messages); !bytes.Equal(got, large) {
		t.Fatal("chunked host message changed")
	}
	if err := visitor.Send(make([]byte, transport.MaxFrameSize+1), false); !errors.Is(err, transport.ErrFrameTooLarge) {
		t.Fatalf("oversized frame returned %v", err)
	}
	proxy.mu.Lock()
	for direction, frames := range proxy.frames {
		wire := bytes.Join(frames, nil)
		if len(frames) < 3 || len(wire) == 0 || bytes.Contains(wire, request) || bytes.Contains(wire, response) ||
			bytes.Contains(wire, []byte("private-vanora")) {
			proxy.mu.Unlock()
			t.Fatalf("direction %d had incomplete capture or exposed plaintext", direction)
		}
	}
	proxy.mu.Unlock()

	proxy.tamper.Store(true)
	_ = visitor.Send([]byte(`{"type":"tampered"}`), false)
	if await(t, hostHandler.closed) != host || await(t, visitorHandler.closed) != visitor {
		t.Fatal("TLS tampering did not close both ends")
	}
	select {
	case <-hostHandler.messages:
		t.Fatal("delivered unauthenticated message")
	default:
	}
}

func TestTunnelRejectsMismatchedProofContextAndHostPin(t *testing.T) {
	listener, handler := newTestListener(t, ListenerOptions{})
	for _, test := range []string{"role", "hostname key"} {
		t.Run(test, func(t *testing.T) {
			permit, opts := tunnelOptions(listener, newKey(t))
			register(t, listener, permit)
			switch test {
			case "role":
				opts.VisitorRole = "desktop"
			case "hostname key":
				opts.HostPublicKey = publicKey(newKey(t))
				opts.HostKeyHash = KeyHash(opts.HostPublicKey)
			}
			if peer, err := Dial(t.Context(), opts); err == nil {
				peer.Close()
				t.Fatal("mismatched tunnel was accepted")
			}
			select {
			case <-handler.opened:
				t.Fatal("handler opened an unauthenticated peer")
			default:
			}
		})
	}
}

func TestDialRejectsUntrustedOuterTLS(t *testing.T) {
	listener, _ := newTestListener(t, ListenerOptions{})
	var reached atomic.Bool
	outer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer outer.Close()
	_, opts := tunnelOptions(listener, newKey(t))
	opts.DialURL = "wss" + strings.TrimPrefix(outer.URL, "https")
	peer, err := Dial(t.Context(), opts)
	if peer != nil {
		peer.Close()
	}
	if err == nil || reached.Load() {
		t.Fatalf("dial accepted an untrusted outer TLS certificate: %v", err)
	}
}

func TestInnerALPNIsMandatoryOnBothSides(t *testing.T) {
	hostKey, visitorKey := newKey(t), newKey(t)
	for _, omitServer := range []bool{false, true} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		to, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		from, err := listener.Accept()
		_ = listener.Close()
		if err != nil {
			_ = to.Close()
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		server, err := tlsConfig(hostKey, publicKey(visitorKey), true)
		if err != nil {
			t.Fatal(err)
		}
		client, err := tlsConfig(visitorKey, publicKey(hostKey), false)
		if err != nil {
			t.Fatal(err)
		}
		if omitServer {
			server.NextProtos, server.VerifyConnection = nil, nil
		} else {
			client.NextProtos, client.VerifyConnection = nil, nil
		}
		honest, other := tls.Server(from, server), tls.Client(to, client)
		if omitServer {
			honest, other = other, honest
		}
		done := make(chan error, 1)
		go func() { done <- other.HandshakeContext(ctx) }()
		err = honest.HandshakeContext(ctx)
		cancel()
		_ = from.Close()
		_ = to.Close()
		await(t, done)
		if err == nil || !strings.Contains(err.Error(), "invalid inner TLS session") {
			t.Fatalf("honest endpoint did not reject missing ALPN: %v", err)
		}
	}
}

func officialOptions(t *testing.T, listener *Listener) (Permit, DialOptions, endpoint.LeaseProof, endpoint.LeaseProof, time.Time) {
	t.Helper()
	permit, opts := tunnelOptions(listener, newKey(t))
	authority := identitytest.NewAuthority(0)
	now := time.Now().Truncate(time.Second)
	host, hostCert := officialIdentity(t, authority, publicKey(listener.opts.PrivateKey), "host", now)
	visitor, visitorCert := officialIdentity(t, authority, permit.VisitorPublicKey, "visitor", now)
	hostProof := officialProof(t, authority, host, hostCert, now, 15*time.Second)
	visitorProof := officialProof(t, authority, visitor, visitorCert, now, time.Minute)
	renewal := officialProof(t, authority, host, hostCert, now, time.Minute)
	permit.Channel, permit.HostDeviceID, permit.VisitorDeviceID = "global", host.DeviceID, visitor.DeviceID
	opts.ConnectionContext = permit.ConnectionContext
	permit.CA, opts.CA = authority.PublicKey(), authority.PublicKey()
	permit.LocalPrincipal, permit.RemotePrincipal = host, visitor
	opts.LocalPrincipal, opts.RemotePrincipal = visitor, host
	permit.UserID, opts.UserID = visitor.RemoteUserID(), host.RemoteUserID()
	permit.LocalLeaseProvider = func(context.Context) (endpoint.LeaseProof, error) { return hostProof, nil }
	opts.LocalLeaseProvider = func(context.Context) (endpoint.LeaseProof, error) { return visitorProof, nil }
	return permit, opts, hostProof, renewal, now.Add(15 * time.Second)
}

func officialIdentity(t *testing.T, authority *identitytest.Authority, key ed25519.PublicKey, subject string, now time.Time) (identity.Principal, string) {
	t.Helper()
	cert, err := authority.IssueWithKey("https://issuer.example", subject, key, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.VerifyCertificate(cert, authority.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	return principal, cert
}

func officialProof(t *testing.T, authority *identitytest.Authority, principal identity.Principal, cert string, now time.Time, ttl time.Duration) endpoint.LeaseProof {
	t.Helper()
	lease, _, err := authority.IssueLease(principal, cert, protocol.NewID(), now, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint.LeaseProof{Certificate: cert, Lease: lease}
}

func TestOfficialLeaseRenewalAuthorityLossAndAccessExpiry(t *testing.T) {
	listener, handler := newTestListener(t, ListenerOptions{})
	permit, opts, _, renewal, initialExpiry := officialOptions(t, listener)
	proxy := newObservingProxy(t, listener.Origin())
	opts.DialURL = proxy.url
	register(t, listener, permit)
	visitor := dialPeer(t, opts)
	host := await(t, handler.opened)
	visitorHandler := opts.Handler.(*testHandler)
	if !host.Allows(true) || !visitor.Allows(true) {
		t.Fatal("initial leases did not grant access")
	}
	allowsAfterInitialExpiry := func() bool {
		visitor.stateMu.Lock()
		defer visitor.stateMu.Unlock()
		return visitor.access.Allows(initialExpiry, true, true)
	}
	if allowsAfterInitialExpiry() {
		t.Fatal("initial lease was accepted at expiry")
	}
	if err := listener.UpdateLocalLease(renewal); err != nil {
		t.Fatal(err)
	}
	eventually(t, allowsAfterInitialExpiry)
	listener.AuthorityLost()
	if host.Allows(true) || !host.Allows(false) {
		t.Fatal("authority loss did not preserve only read-only access")
	}
	if err := host.Send([]byte(`{"type":"tool"}`), true); !errors.Is(err, transport.ErrUnauthorized) {
		t.Fatalf("authority loss online send returned %v", err)
	}
	payload := []byte(`{"type":"read-only-official-secret"}`)
	if err := host.Send(payload, false); err != nil {
		t.Fatal(err)
	}
	if got := await(t, visitorHandler.messages); !bytes.Equal(got, payload) {
		t.Fatal("read-only delivery failed")
	}
	proxy.mu.Lock()
	for _, frames := range proxy.frames {
		wire := bytes.Join(frames, nil)
		if bytes.Contains(wire, payload) || bytes.Contains(wire, []byte(renewal.Lease)) {
			proxy.mu.Unlock()
			t.Fatal("official payload or lease visible at proxy")
		}
	}
	proxy.mu.Unlock()
	listener.UpdateAccessUntil(permit.ConnectionID, time.Now().Add(-time.Second))
	if host.Allows(false) {
		t.Fatal("expired access remained usable")
	}
	await(t, handler.closed)
	await(t, visitorHandler.closed)
}

func TestOfficialRejectsWrongLocalLease(t *testing.T) {
	listener, handler := newTestListener(t, ListenerOptions{})
	permit, opts, hostProof, _, _ := officialOptions(t, listener)
	opts.LocalLeaseProvider = func(context.Context) (endpoint.LeaseProof, error) { return hostProof, nil }
	register(t, listener, permit)
	if peer, err := Dial(t.Context(), opts); err == nil {
		peer.Close()
		t.Fatal("accepted lease for wrong endpoint")
	}
	select {
	case <-handler.opened:
		t.Fatal("opened a peer without a valid lease")
	default:
	}
}
