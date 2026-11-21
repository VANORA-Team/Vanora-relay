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
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2001:10::/28"),    // ORCHID
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

// peerAllowed is the pion PermissionHandler. Pion calls it for both
// CreatePermission and ChannelBind, so a blocked peer can never be reached
// through either mechanism.
func (s *Server) peerAllowed(_ net.Addr, peerIP net.IP) bool {
	if s.allowUnsafePeers {
		return true
	}
	if publicPeer(peerIP) {
		return true
	}

	// Pion permissions are per IP, not per port. The server's own advertised
	// address must be allowed so two allocations of one connection can relay
	// to each other; relayConn.WriteTo then ensures that only that
	// connection's relay sockets are reachable there.
	addr, ok := netip.AddrFromSlice(peerIP)

	return ok && addr.Unmap() == s.publicIP
}
