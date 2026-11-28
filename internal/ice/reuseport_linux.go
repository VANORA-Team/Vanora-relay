package ice

import (
	"context"
	"net"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenUDPControl(ip net.IP, port int) ([]*net.UDPConn, error) {
	if port == 0 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
		if err != nil {
			return nil, err
		}
		return []*net.UDPConn{conn}, nil
	}

	config := net.ListenConfig{Control: func(_, _ string, conn syscall.RawConn) error {
		var socketErr error
		if err := conn.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return socketErr
	}}
	count := min(runtime.GOMAXPROCS(0), 4)
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	sockets := make([]*net.UDPConn, 0, count)
	for range count {
		conn, err := config.ListenPacket(context.Background(), "udp4", addr)
		if err != nil {
			for _, socket := range sockets {
				_ = socket.Close()
			}
			return nil, err
		}
		sockets = append(sockets, conn.(*net.UDPConn))
	}
	return sockets, nil
}
