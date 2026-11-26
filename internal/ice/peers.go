package ice

import (
	"net"
	"net/netip"
)

// blockedPeerPrefixes are additional non-public ranges that are neither
// reported as private nor as link-local by net/netip. The goal is that a TURN
// allocation can only ever relay to a globally routable unicast peer.
var blockedPeerPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved and broadcast
	netip.MustParsePrefix("::/96"),           // deprecated IPv4-compatible IPv6
	netip.MustParsePrefix("64:ff9b::/96"),    // well-known NAT64 prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2001:10::/28"),    // ORCHID
	netip.MustParsePrefix("2001:20::/28"),    // ORCHIDv2
	netip.MustParsePrefix("2002::/16"),       // deprecated 6to4
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
}

// publicPeer reports whether peerIP is a safe public unicast address to relay
// to. Loopback, private, link-local, multicast, unspecified, documentation,
// benchmarking, CGNAT, and other special-use ranges are rejected.
func publicPeer(peerIP net.IP) bool {
	addr, ok := netip.AddrFromSlice(peerIP)
	if !ok {
		return false
	}
	addr = addr.Unmap()

	if !addr.IsValid() ||
		addr.IsUnspecified() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() {
		return false
	}
	if !addr.IsGlobalUnicast() {
		return false
	}

	for _, prefix := range blockedPeerPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}

	return true
}

// hostInterfaceAddrs collects all IP addresses currently assigned to the relay
// host's network interfaces so TURN permissions cannot be used to reach
// non-advertised secondary host interfaces (such as management or extra public
// IPs).
func hostInterfaceAddrs() map[netip.Addr]struct{} {
	out := make(map[netip.Addr]struct{})
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			addr = addr.Unmap()
			if addr.IsValid() && !addr.IsUnspecified() {
				out[addr] = struct{}{}
			}
		}
	}
	return out
}

func (s *Server) isLocalHostAddr(addr netip.Addr) bool {
	_, ok := s.localAddrs[addr.Unmap()]
	return ok
}

// peerAllowed is the pion PermissionHandler. Pion calls it for both
// CreatePermission and ChannelBind, so a blocked peer can never be reached
// through either mechanism.
func (s *Server) peerAllowed(_ net.Addr, peerIP net.IP) bool {
	if s.allowUnsafePeers {
		return true
	}
	addr, ok := netip.AddrFromSlice(peerIP)
	if !ok {
		return false
	}
	addr = addr.Unmap()

	// Pion permissions are per IP, not per port. The server's own advertised
	// address must be allowed so two allocations of one connection can relay
	// to each other; relayConn.WriteTo then ensures that only that
	// connection's relay sockets are reachable there.
	if addr == s.publicIP {
		return true
	}
	// Block every other local interface address assigned to the relay host,
	// even if it falls in a globally routable prefix.
	if s.isLocalHostAddr(addr) {
		return false
	}
	return publicPeer(peerIP)
}
