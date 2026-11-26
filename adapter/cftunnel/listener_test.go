package cftunnel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/adapter/transport"
)

func upgradeHeaders(t *testing.T, opts DialOptions) http.Header {
	t.Helper()
	proof, err := SignClientUpgradeProof(opts.PrivateKey, opts.ConnectionContext)
	if err != nil {
		t.Fatal(err)
	}
	headers := make(http.Header)
	headers.Set(ticketHeader, opts.JTI)
	headers.Set(proofHeader, proof)
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", "websocket")
	headers.Set("Sec-WebSocket-Version", "13")
	headers.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	headers.Set("Sec-WebSocket-Protocol", Subprotocol)
	return headers
}

func assertForbidden(t *testing.T, listener *Listener, method, path, host string, headers http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+listener.Origin()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	req.Host, req.Header = host, headers
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusForbidden || response.Header.Get("Cache-Control") != "no-store" ||
		string(payload) != "Forbidden" {
		t.Fatalf("%s %s returned HTTP %d, cache %q, body %q (%v)", method, path, response.StatusCode,
			response.Header.Get("Cache-Control"), payload, err)
	}
}

func TestPreUpgradeRejectsAnonymousAndMalformedRequests(t *testing.T) {
	listener, handler := newTestListener(t, ListenerOptions{})
	permit, opts := tunnelOptions(listener, newKey(t))
	register(t, listener, permit)
	for _, path := range []string{"/healthz", "/", tunnelPath} {
		assertForbidden(t, listener, http.MethodGet, path, permit.Hostname, nil)
	}
	for _, path := range []string{"/healthz", "/", tunnelPath + "?probe=1", tunnelPath + "?",
		"/v1/tunnel/%77s", "/v1%2Ftunnel%2Fws", tunnelPath + "/"} {
		assertForbidden(t, listener, http.MethodGet, path, permit.Hostname, upgradeHeaders(t, opts))
	}
	assertForbidden(t, listener, http.MethodPost, tunnelPath, permit.Hostname, upgradeHeaders(t, opts))
	assertForbidden(t, listener, http.MethodGet, tunnelPath, "wrong.example", upgradeHeaders(t, opts))
	assertForbidden(t, listener, http.MethodGet, tunnelPath, permit.Hostname+":80", upgradeHeaders(t, opts))
	for _, edit := range []func(http.Header){
		func(headers http.Header) { headers.Set(proofHeader, "wrong") },
		func(headers http.Header) { headers.Del("Sec-WebSocket-Protocol") },
		func(headers http.Header) { headers.Set("Sec-WebSocket-Protocol", "unsupported") },
		func(headers http.Header) { headers.Add(ticketHeader, permit.JTI) },
		func(headers http.Header) { headers.Add(proofHeader, headers.Get(proofHeader)) },
	} {
		headers := upgradeHeaders(t, opts)
		edit(headers)
		assertForbidden(t, listener, http.MethodGet, tunnelPath, permit.Hostname, headers)
	}
	for _, extraHeader := range []string{
		"Host: " + permit.Hostname + "\r\n",
		"Padding:" + strings.Repeat(" ", maxHeaderSize) + "ok\r\n",
	} {
		conn, err := net.DialTimeout("tcp", listener.Origin(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var request bytes.Buffer
		_, _ = fmt.Fprintf(&request, "GET %s HTTP/1.1\r\nHost: %s\r\n%s", tunnelPath, permit.Hostname, extraHeader)
		if err := upgradeHeaders(t, opts).Write(&request); err != nil {
			t.Fatal(err)
		}
		request.WriteString("\r\n")
		_, _ = conn.Write(request.Bytes())
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		_ = conn.Close()
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatal(err)
		}
		if response != nil {
			_ = response.Body.Close()
			if response.StatusCode < 400 {
				t.Fatalf("invalid raw headers returned %d", response.StatusCode)
			}
		}
	}
	select {
	case <-handler.opened:
		t.Fatal("handler opened for a malformed request")
	default:
	}
	dialPeer(t, opts)
	await(t, handler.opened)
	assertForbidden(t, listener, http.MethodGet, tunnelPath, permit.Hostname, upgradeHeaders(t, opts))
	if err := listener.RegisterPermit(permit); err == nil {
		t.Fatal("re-registered a consumed JTI")
	}
}

func TestPermitExpiryAndPendingCapacity(t *testing.T) {
	listener, _ := newTestListener(t, ListenerOptions{})
	visitor := newKey(t)
	expiring, _ := tunnelOptions(listener, visitor)
	expiring.ExpiresAt = time.Now().Add(200 * time.Millisecond)
	register(t, listener, expiring)
	for index := 1; index < 32; index++ {
		permit, _ := tunnelOptions(listener, visitor)
		register(t, listener, permit)
	}
	extra, _ := tunnelOptions(listener, visitor)
	if err := listener.RegisterPermit(extra); err == nil {
		t.Fatal("exceeded the 32-permit default")
	}
	eventually(t, func() bool {
		listener.mu.Lock()
		defer listener.mu.Unlock()
		return len(listener.pending) == 31
	})
	register(t, listener, extra)
}

func TestConcurrentReplayConsumesOnlyOneJTI(t *testing.T) {
	listener, handler := newTestListener(t, ListenerOptions{})
	permit, opts := tunnelOptions(listener, newKey(t))
	register(t, listener, permit)
	var group sync.WaitGroup
	successes := make(chan transport.Peer, 8)
	start := make(chan struct{})
	for range cap(successes) {
		group.Go(func() {
			<-start
			peer, err := Dial(t.Context(), opts)
			if err == nil {
				successes <- peer
			}
		})
	}
	close(start)
	group.Wait()
	close(successes)
	if len(successes) != 1 {
		t.Errorf("single permit opened %d connections", len(successes))
	}
	for peer := range successes {
		defer peer.Close()
	}
	await(t, handler.opened)
}

func TestHandshakeAndActiveCapacity(t *testing.T) {
	t.Run("handshakes", func(t *testing.T) {
		listener, _ := newTestListener(t, ListenerOptions{})
		for range 4 {
			permit, opts := tunnelOptions(listener, newKey(t))
			register(t, listener, permit)
			ws, response, err := websocket.Dial(t.Context(), opts.DialURL+tunnelPath, &websocket.DialOptions{
				Host: strings.ToUpper(permit.Hostname) + ":443", HTTPHeader: upgradeHeaders(t, opts),
				Subprotocols: []string{Subprotocol},
			})
			if err != nil {
				t.Fatalf("handshake capacity reservation failed (%v): %v", response, err)
			}
			t.Cleanup(func() { _ = ws.CloseNow() })
		}
		permit, opts := tunnelOptions(listener, newKey(t))
		register(t, listener, permit)
		assertForbidden(t, listener, http.MethodGet, tunnelPath, permit.Hostname, upgradeHeaders(t, opts))
	})
	t.Run("active", func(t *testing.T) {
		listener, handler := newTestListener(t, ListenerOptions{})
		first := newKey(t)
		for range 2 {
			permit, opts := tunnelOptions(listener, first)
			register(t, listener, permit)
			dialPeer(t, opts)
			await(t, handler.opened)
		}
		permit, opts := tunnelOptions(listener, first)
		register(t, listener, permit)
		assertForbidden(t, listener, http.MethodGet, tunnelPath, permit.Hostname, upgradeHeaders(t, opts))
		for range 14 {
			permit, opts := tunnelOptions(listener, newKey(t))
			register(t, listener, permit)
			dialPeer(t, opts)
			await(t, handler.opened)
		}
		if listener.ActivePeers() != 16 {
			t.Fatalf("active peers = %d, want 16", listener.ActivePeers())
		}
		permit, opts = tunnelOptions(listener, newKey(t))
		register(t, listener, permit)
		assertForbidden(t, listener, http.MethodGet, tunnelPath, permit.Hostname, upgradeHeaders(t, opts))
	})
}

func TestRevocationClosesOnlyMatchingPeersAndPermits(t *testing.T) {
	listener, handler := newTestListener(t, ListenerOptions{})
	first, second, third := newKey(t), newKey(t), newKey(t)
	start := func(key DialOptions, permit Permit) *Peer {
		register(t, listener, permit)
		dialPeer(t, key)
		return await(t, handler.opened)
	}
	permit, opts := tunnelOptions(listener, first)
	permit.UserID = "first"
	firstHost := start(opts, permit)
	firstPending, firstOpts := tunnelOptions(listener, first)
	register(t, listener, firstPending)
	secondPermit, secondOpts := tunnelOptions(listener, second)
	secondPermit.UserID = "second"
	secondHost := start(secondOpts, secondPermit)
	secondPending, secondPendingOpts := tunnelOptions(listener, newKey(t))
	secondPending.UserID = "second"
	register(t, listener, secondPending)
	thirdPermit, thirdOpts := tunnelOptions(listener, third)
	thirdPermit.UserID = "third"
	thirdHost := start(thirdOpts, thirdPermit)

	listener.RevokeVisitor(firstPending.VisitorDeviceID)
	if firstHost.Allows(false) || await(t, handler.closed) != firstHost || !secondHost.Allows(false) || !thirdHost.Allows(true) {
		t.Fatal("device revocation did not isolate the matching peer")
	}
	assertForbidden(t, listener, http.MethodGet, tunnelPath, firstPending.Hostname, upgradeHeaders(t, firstOpts))
	listener.RevokeUser("second")
	if secondHost.Allows(false) || await(t, handler.closed) != secondHost || !thirdHost.Allows(true) || listener.ActivePeers() != 1 {
		t.Fatal("user revocation did not isolate the matching peer")
	}
	assertForbidden(t, listener, http.MethodGet, tunnelPath, secondPending.Hostname, upgradeHeaders(t, secondPendingOpts))
}

func TestAssemblyBudgetExhaustionAndCloseRelease(t *testing.T) {
	budget := NewAssemblyBudget(2 * maxChunk)
	listener, handler := newTestListener(t, ListenerOptions{AssemblyBudget: budget})
	permit, opts := tunnelOptions(listener, newKey(t))
	register(t, listener, permit)
	visitor := dialPeer(t, opts)
	host := await(t, handler.opened)
	writeFirstChunk := func(peer *Peer) {
		t.Helper()
		frame := make([]byte, chunkHeader+maxChunk)
		copy(frame, chunkMagic)
		frame[15] = 8
		if err := writeRecord(peer.conn, frameData, frame); err != nil {
			t.Fatal(err)
		}
	}
	writeFirstChunk(visitor)
	eventually(t, func() bool { return budget.Used() == maxChunk })
	otherPermit, otherOpts := tunnelOptions(listener, newKey(t))
	register(t, listener, otherPermit)
	other := dialPeer(t, otherOpts)
	otherHost := await(t, handler.opened)
	_ = other.Send(make([]byte, 4*maxChunk), false)
	if await(t, handler.closed) != otherHost || !host.Allows(false) {
		t.Fatal("budget exhaustion affected the wrong peer")
	}
	if budget.Used() != maxChunk {
		t.Fatalf("exhausted peer left %d assembly bytes", budget.Used())
	}
	visitor.Close()
	if await(t, handler.closed) != host || budget.Used() != 0 {
		t.Fatalf("partial frame left %d reserved bytes on close", budget.Used())
	}
}

func TestMalformedControlRecordsClosePeer(t *testing.T) {
	listener, handler := newTestListener(t, ListenerOptions{})
	for _, payload := range []string{
		`{"type":"unknown"}`,
		`{"type":"ping","unknown":true}`,
		`{"type":"pong","proof":null}`,
		`{"type":"close","reason":null}`,
		`{"type":"ping","type":"pong"}`,
		`{"type":"lease.update","proof":{"certificate":"cert","lease":"lease"}}`,
	} {
		permit, opts := tunnelOptions(listener, newKey(t))
		register(t, listener, permit)
		client := dialPeer(t, opts)
		host := await(t, handler.opened)
		if err := writeRecord(client.conn, frameControl, []byte(payload)); err != nil {
			t.Fatal(err)
		}
		if await(t, handler.closed) != host {
			t.Fatalf("malformed control %s closed the wrong peer", payload)
		}
	}
}

func TestListenerAddressValidation(t *testing.T) {
	opts := ListenerOptions{PrivateKey: newKey(t), Handler: newTestHandler()}
	for _, address := range []string{"0.0.0.0:0", "localhost:0", "127.0.0.2:0", "[::]:0", "[::ffff:127.0.0.1]:0"} {
		opts.Address = address
		listener, err := NewListener(opts)
		if err == nil {
			_ = listener.Close()
			t.Fatalf("accepted %s", address)
		}
	}
}

func TestDialDisablesRedirects(t *testing.T) {
	first, _ := newTestListener(t, ListenerOptions{})
	_, opts := tunnelOptions(first, newKey(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	redirect := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+first.Origin()+tunnelPath, http.StatusTemporaryRedirect)
	})}
	go func() { _ = redirect.Serve(ln) }()
	t.Cleanup(func() { _ = redirect.Close() })
	opts.DialURL = "ws://" + ln.Addr().String()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	peer, err := Dial(ctx, opts)
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		if peer != nil {
			peer.Close()
		}
		t.Fatalf("expected original redirect, got %v", err)
	}
}
