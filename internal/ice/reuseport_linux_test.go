package ice

import (
	"net"
	"runtime"
	"testing"
)

func TestListenUDPControlSharesFixedPort(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1)
	ephemeral, err := listenUDPControl(ip, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, socket := range ephemeral {
		_ = socket.Close()
	}
	if len(ephemeral) != 1 {
		t.Fatalf("ephemeral control listener has %d sockets, want 1", len(ephemeral))
	}
	port := ephemeral[0].LocalAddr().(*net.UDPAddr).Port

	sockets, err := listenUDPControl(ip, port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	if want := min(runtime.GOMAXPROCS(0), 4); len(sockets) != want {
		t.Fatalf("control port has %d sockets, want %d", len(sockets), want)
	}
	for _, socket := range sockets {
		addr := socket.LocalAddr().(*net.UDPAddr)
		if !addr.IP.Equal(ip) || addr.Port != port {
			t.Fatalf("control socket address %s, want %s:%d", addr, ip, port)
		}
	}
}
