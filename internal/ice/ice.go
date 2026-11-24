// Package ice runs the single-region STUN/TURN edge used by Vanora remote
// connections.
//
// A Server issues one short-lived TURN credential per authorized connection.
// Grants are revocable and expire on their own: revoking a grant, or letting it
// expire, closes the relay sockets of every allocation created with that
// grant, so established relaying stops at the grant boundary instead of
// waiting for the client's TURN allocation refresh lifetime to elapse.
//
// All state lives in this process. The server is meant to run as a single
// regional instance; it does not cluster or persist grants across restarts.
package ice

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/pion/turn/v4"
)

// ICEServer is the standard WebRTC RTCIceServer JSON shape. An entry is
// STUN-only when Username and Credential are empty.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

var (
	// ErrClosed is returned by Config after Close.
	ErrClosed = errors.New("ice: server is closed")
	// ErrInvalidIdentifier is returned when a connection or visitor identifier
	// is empty, too long, or contains control characters.
	ErrInvalidIdentifier = errors.New("ice: invalid identifier")
	// ErrVisitorMismatch is returned when a live connection is reconfigured
	// for a different visitor. A connection belongs to exactly one visitor.
	ErrVisitorMismatch = errors.New("ice: connection already belongs to another visitor")
	// ErrTooManyGrants is returned when the server is at its active-grant limit.
	ErrTooManyGrants = errors.New("ice: too many active relay grants")
	// ErrVisitorGrantLimit is returned when one visitor reaches the per-visitor
	// concurrent active-grant cap.
	ErrVisitorGrantLimit = errors.New("ice: too many active relay grants for visitor")
)

const maxIdentifierLen = 256

// Server is the STUN/TURN server and grant tracker. Create one with FromEnv
// and stop it with Close.
type Server struct {
	turnServer *turn.Server

	realm       string
	controlAddr string
	publicIP    netip.Addr
	stunURLs    []string
	turnURLs    []string

	maxGrants              int
	maxGrantsPerVisitor    int
	maxAllocationsPerGrant int
	allowUnsafePeers       bool
	localAddrs             map[netip.Addr]struct{}
	onRemove               func(removal)

	// localRelays maps an advertised relay address to its socket so
	// same-server hairpin traffic can be recognised on the hot path. It has
	// its own lock because it is read for every relayed datagram.
	localMu     sync.RWMutex
	localRelays map[netip.AddrPort]*relayConn

	mu          sync.Mutex
	closed      bool
	grants      map[string]*grant
	byUsername  map[string]*grant
	allocRelays map[string]*relayConn
	relays      map[string]*relayConn
	visitors    map[string]*visitorUsage
}

type grant struct {
	connectionID  string
	visitor       string
	username      string
	password      string
	key           []byte
	until         time.Time
	gen           uint64
	timer         *time.Timer
	allocations   map[string]*relayConn
	pendingAllocs map[string]time.Time
	relayed       uint64
	removed       bool
}

func (g *grant) prunePendingLocked(now time.Time) {
	for src, exp := range g.pendingAllocs {
		if !now.Before(exp) {
			delete(g.pendingAllocs, src)
		}
	}
}

type visitorUsage struct {
	grants  int
	relayed uint64
}

// removal is the accounting record emitted when a grant is dropped. It is also
// the logging payload so operators see the final per-visitor byte total.
type removal struct {
	connectionID string
	visitor      string
	reason       string
	bytes        uint64
	visitorBytes uint64
}

// Config returns the ICE servers for one authorized connection.
//
// A zero until means the visitor has no relay entitlement: only the STUN entry
// is returned and credentials are empty. Any non-zero until at or before the
// current time is treated as expired and likewise yields STUN-only, so callers
// never receive credentials that are already dead.
//
// For a live grant the returned entries are a STUN entry and a TURN entry whose
// URLs carry both enabled control transports and whose Username/Credential are
// shared by every endpoint of the connection, so the desktop and phone can each
// call Config for the same connection and both can authenticate. Calling again
// for the same connection extends the grant to the new until.
func (s *Server) Config(connectionID, visitor string, until time.Time) ([]ICEServer, error) {
	if err := validateIdentifier("connection_id", connectionID); err != nil {
		return nil, err
	}
	if err := validateIdentifier("visitor", visitor); err != nil {
		return nil, err
	}

	if until.IsZero() || !until.After(time.Now()) {
		s.revokeFor(connectionID, visitor, "not entitled")
		return s.stunOnly(), nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrClosed
	}

	if g := s.grants[connectionID]; g != nil {
		if g.visitor != visitor {
			return nil, ErrVisitorMismatch
		}
		g.until = until
		g.gen++
		gen := g.gen
		if g.timer != nil {
			g.timer.Stop()
		}
		g.timer = time.AfterFunc(time.Until(until), func() { s.expire(connectionID, g, gen) })

		return s.turnServers(g), nil
	}

	if len(s.grants) >= s.maxGrants {
		return nil, ErrTooManyGrants
	}
	if v := s.visitors[visitor]; v != nil && s.maxGrantsPerVisitor > 0 && v.grants >= s.maxGrantsPerVisitor {
		return nil, ErrVisitorGrantLimit
	}

	username, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("ice: generate TURN username: %w", err)
	}
	password, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("ice: generate TURN credential: %w", err)
	}

	g := &grant{
		connectionID:  connectionID,
		visitor:       visitor,
		username:      username,
		password:      password,
		key:           turn.GenerateAuthKey(username, s.realm, password),
		until:         until,
		allocations:   make(map[string]*relayConn),
		pendingAllocs: make(map[string]time.Time),
	}
	g.gen = 1
	gen := g.gen
	g.timer = time.AfterFunc(time.Until(until), func() { s.expire(connectionID, g, gen) })

	s.grants[connectionID] = g
	s.byUsername[username] = g

	v := s.visitors[visitor]
	if v == nil {
		v = &visitorUsage{}
		s.visitors[visitor] = v
	}
	v.grants++

	return s.turnServers(g), nil
}

// Revoke closes every allocation opened with the connection's grant and
// invalidates its credential. It is safe to call for unknown or already
// removed connections.
func (s *Server) Revoke(connectionID string) {
	if connectionID == "" {
		return
	}

	s.mu.Lock()
	g := s.grants[connectionID]
	if g == nil {
		s.mu.Unlock()
		return
	}
	r, conns := s.removeGrantLocked(g, "revoked")
	s.mu.Unlock()

	closeRelays(conns)
	s.emitRemoval(r)
}

// Close revokes all grants, closes all relay and control sockets, and stops the
// TURN server. It is safe to call more than once.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true

	removals := make([]removal, 0, len(s.grants))
	var conns []*relayConn
	for _, g := range s.grants {
		r, grantConns := s.removeGrantLocked(g, "server closed")
		removals = append(removals, r)
		conns = append(conns, grantConns...)
	}

	// Relay sockets usually belong to a grant; close stragglers that were
	// created between authentication and the allocation callback.
	for key, rc := range s.relays {
		delete(s.relays, key)
		conns = append(conns, rc)
	}
	s.allocRelays = make(map[string]*relayConn)
	s.mu.Unlock()

	closeRelays(conns)
	for _, r := range removals {
		s.emitRemoval(r)
	}

	return s.turnServer.Close()
}

func (s *Server) stunOnly() []ICEServer {
	return []ICEServer{{URLs: slices.Clone(s.stunURLs)}}
}

func (s *Server) turnServers(g *grant) []ICEServer {
	return []ICEServer{
		{URLs: slices.Clone(s.stunURLs)},
		{URLs: slices.Clone(s.turnURLs), Username: g.username, Credential: g.password},
	}
}

func (s *Server) revokeFor(connectionID, visitor, reason string) {
	s.mu.Lock()
	g := s.grants[connectionID]
	if g == nil || g.visitor != visitor {
		s.mu.Unlock()
		return
	}
	r, conns := s.removeGrantLocked(g, reason)
	s.mu.Unlock()

	closeRelays(conns)
	s.emitRemoval(r)
}

// expire runs from the grant timer. Only the timer installed for the current
// generation may remove the grant, so a Config extension that raced with a
// firing timer cannot cut the extended grant short.
func (s *Server) expire(connectionID string, g *grant, gen uint64) {
	s.mu.Lock()
	if s.grants[connectionID] != g || g.removed || g.gen != gen {
		s.mu.Unlock()
		return
	}
	r, conns := s.removeGrantLocked(g, "expired")
	s.mu.Unlock()

	closeRelays(conns)
	s.emitRemoval(r)
}

// removeGrantLocked drops the grant, detaches the relay sockets it owns, and
// returns the accounting summary plus the sockets the caller must close after
// unlocking. Closing under the lock would deadlock with relayConn.Close, which
// unregisters itself under the same lock.
func (s *Server) removeGrantLocked(g *grant, reason string) (removal, []*relayConn) {
	if g.removed {
		return removal{connectionID: g.connectionID, visitor: g.visitor, reason: reason}, nil
	}
	g.removed = true

	delete(s.grants, g.connectionID)
	delete(s.byUsername, g.username)
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}

	var conns []*relayConn
	for key, rc := range g.allocations {
		delete(g.allocations, key)
		delete(s.allocRelays, key)
		if s.relays[rc.addrKey] == rc {
			delete(s.relays, rc.addrKey)
		}
		conns = append(conns, rc)
		s.creditLocked(rc)
	}

	r := removal{
		connectionID: g.connectionID,
		visitor:      g.visitor,
		reason:       reason,
		bytes:        g.relayed,
	}
	if v := s.visitors[g.visitor]; v != nil {
		v.grants--
		r.visitorBytes = v.relayed
		if v.grants <= 0 {
			delete(s.visitors, g.visitor)
		}
	}

	return r, conns
}

func closeRelays(conns []*relayConn) {
	for _, rc := range conns {
		_ = rc.Close()
	}
}

// creditLocked adds a relay socket's counters to its grant and visitor exactly
// once. Callers must hold s.mu.
func (s *Server) creditLocked(rc *relayConn) {
	if rc == nil || rc.credited {
		return
	}
	rc.credited = true

	n := rc.relayedBytes()
	if rc.grant != nil {
		rc.grant.relayed += n
	}
	if v := s.visitors[rc.visitor]; v != nil {
		v.relayed += n
	}
}

func (s *Server) emitRemoval(r removal) {
	if s.onRemove != nil {
		s.onRemove(r)
		return
	}

	slog.Info("turn relay grant removed",
		"connection_id", r.connectionID,
		"visitor", r.visitor,
		"reason", r.reason,
		"relay_bytes", r.bytes,
		"visitor_relay_bytes", r.visitorBytes,
	)
}

func validateIdentifier(name, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidIdentifier, name)
	}
	if len(value) > maxIdentifierLen {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidIdentifier, name, maxIdentifierLen)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidIdentifier, name)
		}
	}

	return nil
}

func randomToken() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}
