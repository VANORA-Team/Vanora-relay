package ice

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v4"
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

func TestFirstReadConnClosesSlowlorisAndReleasesSlot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := newLimitedListener(ln, 1, 1)
	defer limited.Close()
	limited.firstTimeout = 200 * time.Millisecond

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, make([]byte, 20))
		read <- err
	}()
	select {
	case err := <-read:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("incomplete frame read returned %v, want timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("incomplete frame held the control connection open")
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("client read returned %v, want closed connection", err)
	}

	replacement, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	second, err := limited.Accept()
	if err != nil {
		t.Fatalf("replacement connection was not accepted: %v", err)
	}
	defer second.Close()
}

func TestFirstReadConnArmsIdleDeadlineAfterSTUNFrame(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := newLimitedListener(ln, 1, 1)
	defer limited.Close()
	limited.firstTimeout = 5 * time.Second
	limited.idleTimeout = 50 * time.Millisecond

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	frame := stun.MustBuild(stun.TransactionID, stun.BindingRequest).Raw
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(server, make([]byte, 9)); err != nil {
		t.Fatal(err)
	}
	if server.(*firstReadConn).established {
		t.Fatal("partial STUN header armed the long idle deadline")
	}
	if _, err := io.ReadFull(server, make([]byte, len(frame)-9)); err != nil {
		t.Fatal(err)
	}
	if !server.(*firstReadConn).established {
		t.Fatal("complete STUN frame did not arm the idle deadline")
	}
	start := time.Now()
	_, err = server.Read(make([]byte, 1))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() || time.Since(start) > time.Second {
		t.Fatalf("idle read returned %v after %v, want short timeout", err, time.Since(start))
	}
}
