package ice

import (
	"net"
	"testing"
	"time"
)

func TestAllocationKeyDistinguishesTransports(t *testing.T) {
	src := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40123}
	dst := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3478}
	other := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40123}
	dstUDP := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3478}

	tcpKey := allocationKey("udp", src, dst) // pion passes protocol as allocation.UDP for TCP conns
	udpKey := allocationKey("udp", other, dstUDP)
	if tcpKey == udpKey {
		t.Fatalf("colliding TCP/UDP five-tuples must produce distinct allocation keys: %q", tcpKey)
	}
	if got := allocationKey("udp", other, dstUDP); got != udpKey {
		t.Fatalf("allocation key must be stable: %q != %q", got, udpKey)
	}
}

func TestLimitedListenerEnforcesPerIPCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	limited := newLimitedListener(ln, 8, 1)
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	var first net.Conn
	select {
	case first = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("first connection was not accepted")
	}

	// A second concurrent connection from the same source IP must be closed
	// by the per-IP cap instead of being handed out.
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	select {
	case extra := <-accepted:
		extra.Close()
		t.Fatal("per-IP cap failed: second connection from the same IP was accepted")
	case <-time.After(300 * time.Millisecond):
	}

	// Releasing the slot lets the next same-IP connection through.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	c3, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("connection not accepted after slot released")
	}
}

func TestLimitedListenerEnforcesTotalCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	limited := newLimitedListener(ln, 2, 8)
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	var held []net.Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatalf("connection %d was not accepted", i)
		}
	}

	// With both slots held, a third concurrent connection must be refused
	// by the total cap and never handed out.
	c3, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	select {
	case extra := <-accepted:
		extra.Close()
		t.Fatal("total cap failed: third connection was accepted")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestFirstReadConnClearsIdleDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	limited := newLimitedListener(ln, 8, 8)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := limited.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	if got, ok := server.(*firstReadConn); !ok {
		t.Fatalf(
			"listener must hand out first-read connections, got %T", server)
	} else if got.cleared.Load() {
		t.Fatal("idle deadline must still be armed before the peer sends data")
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("first read failed: %v", err)
	}
	if !server.(*firstReadConn).cleared.Load() {
		t.Fatal("first-read deadline was not cleared after data arrived")
	}
}
