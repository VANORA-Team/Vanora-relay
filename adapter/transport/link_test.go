package transport

import (
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
	"github.com/pion/webrtc/v4"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

func webrtcCandidate() webrtc.ICECandidateInit {
	mid := "0"
	index := uint16(0)
	return webrtc.ICECandidateInit{
		Candidate:     "candidate:1 1 udp 1 127.0.0.1 1234 typ host",
		SDPMid:        &mid,
		SDPMLineIndex: &index,
	}
}

// candidateLink returns an accepted mobile session with an offer already
// sealed, which is the state in which ICE candidates are emitted.
func candidateLink(t *testing.T, c *Client) *link {
	t.Helper()
	now := time.Now()
	_, ca, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := identity.NewSigner(ca, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(subject string) *endpoint.Credentials {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := signer.Issue("https://issuer.example", subject, pub, now)
		if err != nil {
			t.Fatal(err)
		}
		creds, err := endpoint.OpenCredentials(cert, key, signer.PublicKey(), now)
		if err != nil {
			t.Fatal(err)
		}
		return creds
	}
	phone, desktop := issue("phone"), issue("desktop")
	session, request, err := phone.Request(desktop.DeviceID(), desktop.UserID())
	if err != nil {
		t.Fatal(err)
	}
	// The relay stamps the authenticated peer's certificate onto forwarded
	// connect records; reproduce that here.
	request.Certificate = phone.Certificate()
	_, reply, err := desktop.Accept(request, func(user string) bool { return user == phone.UserID() }, now)
	if err != nil {
		t.Fatal(err)
	}
	reply.Certificate = desktop.Certificate()
	if err := session.Accepted(reply, now); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Seal("rtc.offer", json.RawMessage(`{"type":"offer","sdp":"v=0"}`)); err != nil {
		t.Fatal(err)
	}
	l := newLink(c, session.ID(), session, false, true)
	return l
}

// A fast remote may send its lease before the local OnOpen callback has
// finished sending ours. Exposing the peer then can put RPC before the proof.
func TestPeerWaitsForOutgoingProof(t *testing.T) {
	l := newLink(&Client{}, "link", nil, false, true)
	l.dcOpen, l.remoteVerified = true, true
	if err := l.maybeOpen(); err != nil || l.opened.Load() {
		t.Fatalf("peer did not wait for its outgoing lease: opened=%t err=%v", l.opened.Load(), err)
	}
}

func TestICERefreshFollowsLeaseAndAge(t *testing.T) {
	msgs := make(chan protocol.Message, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var m protocol.Message
			if json.Unmarshal(data, &m) != nil {
				return
			}
			msgs <- m
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	creds, proof := testLeaseIdentity(t)
	c := &Client{
		role:   "mobile",
		source: fixedIdentity{creds: creds, proof: proof},
		ctx:    ctx,
		cancel: cancel,
		ws:     ws,
		done:   make(chan struct{}),
	}
	defer c.Close()

	now := time.Now()
	old := candidateLink(t, c)
	old.id = "old"
	old.acceptedAt = now.Add(-30 * time.Second)
	fresh := candidateLink(t, c)
	fresh.id = "fresh"
	fresh.acceptedAt = now.Add(-5 * time.Second)
	host := newLink(c, "host", nil, true, false)
	c.links = map[string]*link{"old": old, "fresh": fresh, "host": host}

	if err := c.renew(ctx, now); err != nil {
		t.Fatal(err)
	}
	next := func() protocol.Message {
		t.Helper()
		select {
		case m := <-msgs:
			return m
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for signaling message")
			return protocol.Message{}
		}
	}
	if m := next(); m.Type != "auth.lease" {
		t.Fatalf("first message is %q, want auth.lease", m.Type)
	}
	m := next()
	if m.Type != "ice.refresh" || m.Connection != "old" {
		t.Fatalf("refresh message is %q for %q, want ice.refresh for old", m.Type, m.Connection)
	}
	select {
	case extra := <-msgs:
		t.Fatalf("unexpected extra message %q for %q", extra.Type, extra.Connection)
	case <-time.After(100 * time.Millisecond):
	}
	// A second renewal inside the interval refreshes the lease but not ICE.
	if err := c.renew(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if m := next(); m.Type != "auth.lease" {
		t.Fatalf("second renewal message is %q, want auth.lease", m.Type)
	}
	select {
	case extra := <-msgs:
		t.Fatalf("unexpected early ICE refresh %q", extra.Type)
	case <-time.After(100 * time.Millisecond):
	}
	// A relay rejection of a redundant refresh must not tear down the link.
	err = old.handleSignal(protocol.Message{Type: "error", Data: protocol.Encode("refresh_unavailable")})
	if err != nil {
		t.Fatalf("refresh_unavailable closed the link: %v", err)
	}
	if old.isClosed() {
		t.Fatal("refresh_unavailable closed the link")
	}
}

type fixedIdentity struct {
	creds *endpoint.Credentials
	proof endpoint.LeaseProof
}

func (f fixedIdentity) Current(context.Context) (*endpoint.Credentials, endpoint.LeaseProof, error) {
	return f.creds, f.proof, nil
}

func testLeaseIdentity(t *testing.T) (*endpoint.Credentials, endpoint.LeaseProof) {
	t.Helper()
	now := time.Now()
	_, ca, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := identity.NewSigner(ca, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := signer.Issue("https://issuer.example", "phone", pub, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := identity.VerifyCertificate(cert, signer.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	lease, _, err := signer.IssueLease(principal, cert, base64.RawURLEncoding.EncodeToString(nonce), now, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := endpoint.OpenCredentials(cert, key, signer.PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	return creds, endpoint.LeaseProof{Certificate: cert, Lease: lease}
}

func TestCandidateOrderingAcrossFlush(t *testing.T) {
	const buffered, late = 128, 24
	seqs := make(chan uint64, buffered+late)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var m protocol.Message
			if json.Unmarshal(data, &m) != nil {
				return
			}
			seqs <- m.Seq
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{ctx: ctx, cancel: cancel, ws: ws, done: make(chan struct{})}
	defer c.Close()
	l := candidateLink(t, c)

	init := webrtcCandidate()
	for i := 0; i < buffered; i++ {
		l.queueCandidate(init)
	}
	var wg sync.WaitGroup
	wg.Add(late + 1)
	go func() {
		defer wg.Done()
		l.flushCandidates()
	}()
	for i := 0; i < late; i++ {
		go func() {
			defer wg.Done()
			l.queueCandidate(init)
		}()
	}
	wg.Wait()

	// The connect request and offer consumed sequences 1 and 2; every
	// candidate must follow in the exact order in which it was sealed.
	want := uint64(3)
	for i := 0; i < buffered+late; i++ {
		select {
		case got := <-seqs:
			if got != want {
				t.Fatalf("candidate %d has sequence %d, want %d", i, got, want)
			}
			want++
		case <-time.After(5 * time.Second):
			t.Fatalf("received %d of %d candidates", i, buffered+late)
		}
	}
}
