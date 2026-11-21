package ice

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

func newTestServer(t *testing.T, onRemove func(removal)) *Server {
	t.Helper()

	s, err := newServer(options{
		publicIP:               net.IPv4(127, 0, 0, 1),
		bindIP:                 net.IPv4(127, 0, 0, 1),
		relayBindIP:            net.IPv4(127, 0, 0, 1),
		port:                   0,
		realm:                  "vanora-test",
		enableUDP:              true,
		maxGrants:              16,
		maxAllocationsPerGrant: 4,
		allowUnsafePeers:       true,
		onRemove:               onRemove,
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return s
}

func turnCredentials(t *testing.T, servers []ICEServer) (string, string) {
	t.Helper()

	for _, srv := range servers {
		if srv.Username != "" {
			return srv.Username, srv.Credential
		}
	}
	t.Fatalf("no TURN credentials in %+v", servers)

	return "", ""
}

func newTURNClient(t *testing.T, s *Server, username, password string) *turn.Client {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: s.controlAddr,
		TURNServerAddr: s.controlAddr,
		Conn:           conn,
		Username:       username,
		Password:       password,
		Realm:          s.realm,
	})
	if err != nil {
		t.Fatalf("turn.NewClient: %v", err)
	}
	t.Cleanup(client.Close)

	if err := client.Listen(); err != nil {
		t.Fatalf("client.Listen: %v", err)
	}

	return client
}

func allocate(t *testing.T, s *Server, username, password string) (*turn.Client, net.PacketConn) {
	t.Helper()

	client := newTURNClient(t, s, username, password)
	relayConn, err := client.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	t.Cleanup(func() { _ = relayConn.Close() })

	return client, relayConn
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestConfigGrantsAndReusesCredential(t *testing.T) {
	s := newTestServer(t, nil)
	until := time.Now().Add(time.Minute)

	first, err := s.Config("conn-1", "visitor-a", until)
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("got %d ICE servers, want STUN and TURN", len(first))
	}
	if first[0].Username != "" || first[0].Credential != "" {
		t.Fatalf("STUN entry carries credentials: %+v", first[0])
	}
	if len(first[1].URLs) == 0 {
		t.Fatal("TURN entry has no URLs")
	}
	username, password := turnCredentials(t, first)

	second, err := s.Config("conn-1", "visitor-a", until.Add(time.Minute))
	if err != nil {
		t.Fatalf("second Config: %v", err)
	}
	username2, password2 := turnCredentials(t, second)
	if username != username2 || password != password2 {
		t.Fatalf("credential changed between endpoints: %q/%q vs %q/%q", username, password, username2, password2)
	}

	stunOnly, err := s.Config("conn-2", "visitor-a", time.Time{})
	if err != nil {
		t.Fatalf("STUN-only Config: %v", err)
	}
	if len(stunOnly) != 1 || len(stunOnly[0].URLs) != 1 || stunOnly[0].Username != "" {
		t.Fatalf("STUN-only result = %+v", stunOnly)
	}

	if _, err := s.Config("conn-1", "visitor-b", until); !errors.Is(err, ErrVisitorMismatch) {
		t.Fatalf("visitor change error = %v, want ErrVisitorMismatch", err)
	}
}

func TestRevokeClosesAllocationAndCountsBytes(t *testing.T) {
	removed := make(chan removal, 1)
	s := newTestServer(t, func(r removal) { removed <- r })

	servers, err := s.Config("conn-relay", "visitor-a", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	username, password := turnCredentials(t, servers)
	client, relayConn := allocate(t, s, username, password)

	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	defer func() { _ = peer.Close() }()

	go func() {
		buf := make([]byte, 1500)
		_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, readErr := peer.ReadFrom(buf)
		if readErr != nil {
			return
		}
		_, _ = peer.WriteTo(buf[:n], addr)
	}()

	if err := client.CreatePermission(peer.LocalAddr()); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}

	payload := []byte("vanora relay payload")
	if _, err := relayConn.WriteTo(payload, peer.LocalAddr()); err != nil {
		t.Fatalf("relay write: %v", err)
	}

	_ = relayConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := relayConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("relayed payload = %q, want %q", buf[:n], payload)
	}

	s.Revoke("conn-relay")

	select {
	case r := <-removed:
		if r.reason != "revoked" {
			t.Fatalf("removal reason = %q, want revoked", r.reason)
		}
		want := uint64(2 * len(payload))
		if r.bytes != want {
			t.Fatalf("relay bytes = %d, want %d", r.bytes, want)
		}
		if r.visitorBytes != want {
			t.Fatalf("visitor bytes = %d, want %d", r.visitorBytes, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("grant removal was not reported")
	}

	waitFor(t, "allocation to close", 3*time.Second, func() bool {
		return s.turnServer.AllocationCount() == 0
	})
}

func TestGrantExpiryClosesAllocation(t *testing.T) {
	removed := make(chan removal, 1)
	s := newTestServer(t, func(r removal) { removed <- r })

	servers, err := s.Config("conn-exp", "visitor-b", time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	username, password := turnCredentials(t, servers)
	allocate(t, s, username, password)

	select {
	case r := <-removed:
		if r.reason != "expired" {
			t.Fatalf("removal reason = %q, want expired", r.reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("grant did not expire")
	}

	waitFor(t, "allocation to close", 3*time.Second, func() bool {
		return s.turnServer.AllocationCount() == 0
	})

	// The expired credential must no longer authenticate a new allocation.
	client := newTURNClient(t, s, username, password)
	if _, err := client.Allocate(); err == nil {
		t.Fatal("expired credential was accepted")
	}
}

func TestPublicPeerFilter(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"100.64.0.1", false},
		{"192.0.2.10", false},
		{"198.18.0.1", false},
		{"224.0.0.1", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},
		{"::1", false},
		{"fc00::1", false},
		{"fe80::1", false},
		{"ff02::1", false},
		{"2001:db8::1", false},
		{"::ffff:127.0.0.1", false},
	}

	for _, tc := range tests {
		if got := publicPeer(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("publicPeer(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if publicPeer(nil) {
		t.Error("publicPeer(nil) = true, want false")
	}
}

func newStrictTestServer(t *testing.T, onRemove func(removal)) *Server {
	t.Helper()

	s, err := newServer(options{
		publicIP:               net.IPv4(127, 0, 0, 1),
		bindIP:                 net.IPv4(127, 0, 0, 1),
		relayBindIP:            net.IPv4(127, 0, 0, 1),
		port:                   0,
		realm:                  "vanora-test",
		enableUDP:              true,
		maxGrants:              16,
		maxAllocationsPerGrant: 4,
		onRemove:               onRemove,
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return s
}

// TestHairpinCountsPayloadOnce exercises the case where both endpoints of one
// connection relay through this server. A payload must be credited once per
// direction, not once per relay socket it crosses.
func TestHairpinCountsPayloadOnce(t *testing.T) {
	removed := make(chan removal, 1)
	s := newTestServer(t, func(r removal) { removed <- r })

	servers, err := s.Config("conn-pair", "visitor-pair", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	username, password := turnCredentials(t, servers)
	clientA, relayA := allocate(t, s, username, password)
	clientB, relayB := allocate(t, s, username, password)

	if err := clientA.CreatePermission(relayB.LocalAddr()); err != nil {
		t.Fatalf("client A CreatePermission: %v", err)
	}
	if err := clientB.CreatePermission(relayA.LocalAddr()); err != nil {
		t.Fatalf("client B CreatePermission: %v", err)
	}

	payload := []byte("hairpin request payload")
	reply := []byte("hairpin reply payload, longer on purpose")

	if _, err := relayA.WriteTo(payload, relayB.LocalAddr()); err != nil {
		t.Fatalf("A to B relay write: %v", err)
	}
	_ = relayB.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := relayB.ReadFrom(buf)
	if err != nil {
		t.Fatalf("B relay read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("B received %q, want %q", buf[:n], payload)
	}

	if _, err := relayB.WriteTo(reply, relayA.LocalAddr()); err != nil {
		t.Fatalf("B to A relay write: %v", err)
	}
	_ = relayA.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = relayA.ReadFrom(buf)
	if err != nil {
		t.Fatalf("A relay read: %v", err)
	}
	if string(buf[:n]) != string(reply) {
		t.Fatalf("A received %q, want %q", buf[:n], reply)
	}

	s.Revoke("conn-pair")

	select {
	case r := <-removed:
		want := uint64(len(payload) + len(reply))
		if r.bytes != want {
			t.Fatalf("hairpin relay bytes = %d, want %d (one credit per direction, not double)", r.bytes, want)
		}
		if r.visitorBytes != want {
			t.Fatalf("visitor bytes = %d, want %d", r.visitorBytes, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("grant removal was not reported")
	}
}

// TestStrictPeerPolicyAllowsOnlyOwnRelaySockets checks that granting a
// permission to the server's own address (required for hairpin) does not
// expose other services listening there, while same-connection relay sockets
// still work.
func TestStrictPeerPolicyAllowsOnlyOwnRelaySockets(t *testing.T) {
	removed := make(chan removal, 1)
	s := newStrictTestServer(t, func(r removal) { removed <- r })

	servers, err := s.Config("conn-strict", "visitor-strict", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	username, password := turnCredentials(t, servers)
	clientA, relayA := allocate(t, s, username, password)
	clientB, relayB := allocate(t, s, username, password)

	if err := clientA.CreatePermission(relayB.LocalAddr()); err != nil {
		t.Fatalf("client A CreatePermission relay: %v", err)
	}
	if err := clientB.CreatePermission(relayA.LocalAddr()); err != nil {
		t.Fatalf("client B CreatePermission relay: %v", err)
	}

	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen service on own address: %v", err)
	}
	defer func() { _ = listener.Close() }()

	if err := clientA.CreatePermission(listener.LocalAddr()); err != nil {
		t.Fatalf("client A CreatePermission own address: %v", err)
	}

	// The permission is per IP, so the write must be dropped by the relay
	// socket even though the permission exists.
	if _, err := relayA.WriteTo([]byte("must not arrive"), listener.LocalAddr()); err != nil {
		t.Fatalf("relay write to own address: %v", err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1500)
	if n, _, readErr := listener.ReadFrom(buf); readErr == nil {
		t.Fatalf("service on own address received %q", buf[:n])
	} else if nerr, ok := readErr.(net.Error); !ok || !nerr.Timeout() {
		t.Fatalf("listener read error = %v, want timeout", readErr)
	}

	payload := []byte("strict hairpin payload")
	if _, err := relayA.WriteTo(payload, relayB.LocalAddr()); err != nil {
		t.Fatalf("hairpin relay write: %v", err)
	}
	_ = relayB.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := relayB.ReadFrom(buf)
	if err != nil {
		t.Fatalf("hairpin read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("hairpin payload = %q, want %q", buf[:n], payload)
	}

	s.Revoke("conn-strict")

	select {
	case r := <-removed:
		want := uint64(len(payload))
		if r.bytes != want {
			t.Fatalf("relay bytes = %d, want %d", r.bytes, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("grant removal was not reported")
	}
}
