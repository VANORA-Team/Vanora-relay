package ice

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v4"
)

// errRelayPeerDenied is returned when a relay socket is asked to reach an
// address it must not reach: another connection's relay socket, or a service
// on the server's own advertised address.
var errRelayPeerDenied = errors.New("ice: peer is not a relayed socket of this connection")

// relayStats counts relayed payload bytes at the peer-facing relay socket:
// every datagram the server reads from a peer and every datagram it writes to a
// peer is counted once, in that direction. Client-facing STUN/channel framing
// and direct peer-to-peer traffic are outside this boundary.
type relayStats struct {
	fromPeers atomic.Uint64 // peer -> TURN client
	toPeers   atomic.Uint64 // TURN client -> peer
}

// relayConn wraps a relay socket so payload bytes can be attributed to the
// grant that created the allocation.
type relayConn struct {
	net.PacketConn

	srv      *Server
	stats    relayStats
	addrKey  string
	grant    *grant
	grantRef atomic.Pointer[grant]
	visitor  string
	credited bool

	localKey    netip.AddrPort
	hasLocalKey bool

	closeOnce sync.Once
	closeErr  error
}

// Close unregisters the socket and closes it once. Pion closes relay sockets
// both when an allocation is deleted and when it probes for an even port, so
// the registration must be dropped here rather than only on grant removal.
func (r *relayConn) Close() error {
	r.closeOnce.Do(func() {
		if r.srv != nil {
			r.srv.unregisterRelay(r)
		}
		r.closeErr = r.PacketConn.Close()
	})

	return r.closeErr
}

func (r *relayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := r.PacketConn.ReadFrom(p)
	if n > 0 {
		r.stats.fromPeers.Add(uint64(n))
	}

	return n, addr, err
}

func (r *relayConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if key, ok := relayAddrPort(addr); ok {
		if key.Addr() == r.srv.publicIP {
			if dst := r.srv.localRelay(key); dst != nil {
				owner := r.ownerGrant()
				if owner == nil || dst.ownerGrant() != owner {
					return 0, errRelayPeerDenied
				}

				// Hairpin within one connection: the receiving allocation counts
				// the datagram when it reads it, so it is credited exactly once.
				return r.PacketConn.WriteTo(p, addr)
			}
			if !r.srv.allowUnsafePeers {
				// Permissions are per IP, so allowing the server's own address
				// would expose every other service listening on it. Only relay
				// sockets of this grant may be reached there.
				return 0, errRelayPeerDenied
			}
		} else if !r.srv.allowUnsafePeers && r.srv.isLocalHostAddr(key.Addr()) {
			return 0, errRelayPeerDenied
		}
	}

	n, err := r.PacketConn.WriteTo(p, addr)
	if n > 0 {
		r.stats.toPeers.Add(uint64(n))
	}

	return n, err
}

func (r *relayConn) ownerGrant() *grant {
	return r.grantRef.Load()
}

func (r *relayConn) relayedBytes() uint64 {
	return r.stats.fromPeers.Load() + r.stats.toPeers.Load()
}

// countingGenerator decorates the upstream relay generator. Pion calls
// AllocatePacketConn before it reports the allocation, so the socket is
// registered under its relay address and bound to the grant by
// allocationCreated.
type countingGenerator struct {
	inner turn.RelayAddressGenerator
	srv   *Server
}

func (g *countingGenerator) Validate() error {
	return g.inner.Validate()
}

func (g *countingGenerator) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	conn, addr, err := g.inner.AllocatePacketConn(network, requestedPort)
	if err != nil {
		return nil, nil, err
	}

	rc := &relayConn{PacketConn: conn}
	g.srv.registerRelay(addr, rc)

	return rc, addr, nil
}

// AllocateConn is not used by pion's allocation manager (TURN relays are UDP),
// but the interface requires it.
func (g *countingGenerator) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	return g.inner.AllocateConn(network, requestedPort)
}

func (s *Server) registerRelay(addr net.Addr, rc *relayConn) {
	rc.srv = s
	rc.addrKey = addr.String()
	if key, ok := relayAddrPort(addr); ok {
		rc.localKey, rc.hasLocalKey = key, true
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = rc.Close()

		return
	}
	s.relays[rc.addrKey] = rc
	if rc.hasLocalKey {
		s.localMu.Lock()
		s.localRelays[rc.localKey] = rc
		s.localMu.Unlock()
	}
	s.mu.Unlock()
}

func (s *Server) unregisterRelay(rc *relayConn) {
	s.mu.Lock()
	if rc.addrKey != "" && s.relays[rc.addrKey] == rc {
		delete(s.relays, rc.addrKey)
	}
	if rc.hasLocalKey {
		s.localMu.Lock()
		if s.localRelays[rc.localKey] == rc {
			delete(s.localRelays, rc.localKey)
		}
		s.localMu.Unlock()
	}
	s.mu.Unlock()
}

func (s *Server) localRelay(key netip.AddrPort) *relayConn {
	s.localMu.RLock()
	defer s.localMu.RUnlock()

	return s.localRelays[key]
}

// relayAddrPort normalises a relayed address so IPv4 and IPv4-mapped IPv6
// spellings compare equal.
func relayAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}

	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		ap := udpAddr.AddrPort()

		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}

	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, false
	}

	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func (s *Server) authenticate(username, _ string, _ net.Addr) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	g := s.byUsername[username]
	if g == nil || s.closed || !time.Now().Before(g.until) {
		return nil, false
	}

	return g.key, true
}

const pendingAllocTTL = 5 * time.Second

func (s *Server) quota(username, _ string, srcAddr net.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	g := s.byUsername[username]
	if g == nil || s.closed || !now.Before(g.until) {
		return false
	}
	g.prunePendingLocked(now)

	srcKey := ""
	if srcAddr != nil {
		srcKey = srcAddr.String()
	}
	pending := len(g.pendingAllocs)
	if srcKey != "" {
		if _, dup := g.pendingAllocs[srcKey]; dup {
			pending--
		}
	}
	if len(g.allocations)+pending >= s.maxAllocationsPerGrant {
		return false
	}
	if srcKey != "" {
		g.pendingAllocs[srcKey] = now.Add(pendingAllocTTL)
	}
	return true
}

func (s *Server) allocationCreated(
	srcAddr, dstAddr net.Addr,
	protocol, username, _ string,
	relayAddr net.Addr,
	_ int,
) {
	key := allocationKey(protocol, srcAddr, dstAddr)
	relayKey := relayAddr.String()

	s.mu.Lock()
	rc := s.relays[relayKey]
	g := s.byUsername[username]
	if g != nil && srcAddr != nil {
		delete(g.pendingAllocs, srcAddr.String())
	}
	if rc == nil || g == nil || s.closed || !time.Now().Before(g.until) || len(g.allocations) >= s.maxAllocationsPerGrant {
		s.mu.Unlock()
		if rc != nil {
			_ = rc.Close()
		}

		return
	}

	rc.grant = g
	rc.grantRef.Store(g)
	rc.visitor = g.visitor
	g.allocations[key] = rc
	s.allocRelays[key] = rc
	s.mu.Unlock()
}

func (s *Server) allocationDeleted(srcAddr, dstAddr net.Addr, protocol, _, _ string) {
	key := allocationKey(protocol, srcAddr, dstAddr)

	s.mu.Lock()
	rc := s.allocRelays[key]
	delete(s.allocRelays, key)
	if rc != nil {
		if rc.grant != nil {
			delete(rc.grant.allocations, key)
		}
		s.creditLocked(rc)
	}
	s.mu.Unlock()

	if rc != nil {
		_ = rc.Close()
	}
}

func allocationKey(protocol string, srcAddr, dstAddr net.Addr) string {
	return protocol + "|" + srcAddr.String() + "|" + dstAddr.String()
}
