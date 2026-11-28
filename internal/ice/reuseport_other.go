//go:build !linux

package ice

import "net"

func listenUDPControl(ip net.IP, port int) ([]*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, err
	}
	return []*net.UDPConn{conn}, nil
}
