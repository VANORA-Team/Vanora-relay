package cftunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/identity"
)

const (
	ticketHeader  = "Vanora-Ticket-ID"
	proofHeader   = "Vanora-Client-Proof"
	edgeHeader    = "Vanora-Edge-Ticket"
	maxHeaderSize = 4096
)

type Permit struct {
	ConnectionContext
	VisitorPublicKey   ed25519.PublicKey
	UserID             string
	ExpiresAt          time.Time
	AccessUntil        time.Time
	Allows             func() bool
	CA                 ed25519.PublicKey
	LocalPrincipal     identity.Principal
	RemotePrincipal    identity.Principal
	LocalLeaseProvider func(context.Context) (endpoint.LeaseProof, error)
}

type ListenerOptions struct {
	Address            string
	PrivateKey         ed25519.PrivateKey
	Handler            transport.Handler
	AssemblyBudget     *AssemblyBudget
	MaxPendingPermits  int
	MaxHandshakes      int
	MaxActivePeers     int
	MaxPeersPerVisitor int
}

type pendingPermit struct {
	Permit
	access *endpoint.Access
}

type connectionSlot struct {
	permit *pendingPermit
	cancel context.CancelFunc
	peer   *Peer
}

type Listener struct {
	opts   ListenerOptions
	ctx    context.Context
	cancel context.CancelFunc
	server *http.Server
	origin string

	mu          sync.Mutex
	pending     map[string]*pendingPermit
	spent       map[string]time.Time
	connections map[string]*connectionSlot
	handshakes  int
	authority   atomic.Uint64
}

// NewListener starts a loopback-only HTTP server for permitted upgrades.
func NewListener(opts ListenerOptions) (*Listener, error) {
	if opts.Address == "" {
		opts.Address = "127.0.0.1:0"
	}
	address, err := netip.ParseAddrPort(opts.Address)
	if err != nil || !literalLoopback(address.Addr()) {
		return nil, errors.New("cftunnel: listener must bind to a literal loopback address")
	}
	if !validPrivateKey(opts.PrivateKey) || opts.Handler == nil {
		return nil, errors.New("cftunnel: listener device key and handler required")
	}
	opts.PrivateKey = slices.Clone(opts.PrivateKey)
	if opts.AssemblyBudget == nil {
		opts.AssemblyBudget = processAssemblyBudget
	}
	setDefault(&opts.MaxPendingPermits, 32)
	setDefault(&opts.MaxHandshakes, 4)
	setDefault(&opts.MaxActivePeers, 16)
	setDefault(&opts.MaxPeersPerVisitor, 2)
	ln, err := net.Listen("tcp", address.String())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	listener := &Listener{
		opts: opts, ctx: ctx, cancel: cancel, origin: ln.Addr().String(),
		pending: make(map[string]*pendingPermit), spent: make(map[string]time.Time),
		connections: make(map[string]*connectionSlot),
	}
	listener.server = &http.Server{
		Handler: http.HandlerFunc(listener.serveHTTP), MaxHeaderBytes: maxHeaderSize,
		ReadHeaderTimeout: handshakeTimeout,
	}
	listener.server.SetKeepAlivesEnabled(false)
	go func() {
		_ = listener.server.Serve(headerListener{ln})
		listener.cancel()
	}()
	go listener.sweep()
	return listener, nil
}

func setDefault(value *int, fallback int) {
	if *value <= 0 {
		*value = fallback
	}
}

func literalLoopback(address netip.Addr) bool {
	return address == netip.AddrFrom4([4]byte{127, 0, 0, 1}) || address == netip.IPv6Loopback()
}

// Origin returns the bound address and port for the connector's ingress rule.
func (l *Listener) Origin() string { return l.origin }

func (l *Listener) RegisterPermit(permit Permit) error {
	binding := permit.ConnectionContext
	if err := binding.validate(l.opts.PrivateKey.Public().(ed25519.PublicKey), permit.VisitorPublicKey); err != nil {
		return err
	}
	if permit.Allows == nil || permit.UserID == "" {
		return errors.New("cftunnel: permit requires a user and local authorization")
	}
	if binding.official() && permit.UserID != permit.RemotePrincipal.RemoteUserID() {
		return errors.New("cftunnel: permit visitor identity mismatch")
	}
	access, err := leaseAccess(binding, true, permit.CA, permit.LocalPrincipal, permit.RemotePrincipal, permit.LocalLeaseProvider)
	if err != nil {
		return err
	}
	permit.VisitorPublicKey = slices.Clone(permit.VisitorPublicKey)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweepLocked(now)
	if l.ctx.Err() != nil || !now.Before(permit.ExpiresAt) || !now.Before(permit.AccessUntil) {
		return transport.ErrUnauthorized
	}
	if len(l.pending) >= l.opts.MaxPendingPermits || l.pending[binding.JTI] != nil ||
		!l.spent[binding.JTI].IsZero() || l.connections[binding.ConnectionID] != nil {
		return errors.New("cftunnel: permit capacity or duplicate binding")
	}
	for _, pending := range l.pending {
		if pending.ConnectionID == binding.ConnectionID {
			return errors.New("cftunnel: duplicate connection binding")
		}
	}
	l.pending[binding.JTI] = &pendingPermit{Permit: permit, access: access}
	return nil
}

func (l *Listener) sweep() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			l.mu.Lock()
			l.sweepLocked(time.Now())
			l.mu.Unlock()
		}
	}
}

func (l *Listener) sweepLocked(now time.Time) {
	for jti, permit := range l.pending {
		if !now.Before(permit.ExpiresAt) || !now.Before(permit.AccessUntil) {
			l.invalidateLocked(jti, permit)
		}
	}
	for jti, until := range l.spent {
		if !now.Before(until) {
			delete(l.spent, jti)
		}
	}
}

func (l *Listener) invalidateLocked(jti string, permit *pendingPermit) {
	delete(l.pending, jti)
	l.spent[jti] = permit.ExpiresAt
}

func upgradeProofMessage(binding ConnectionContext) []byte {
	return frameFields("vanora/tunnel-ws/v1", binding.Scope, binding.VisitorDeviceID,
		binding.HostDeviceID, binding.Hostname, binding.JTI, binding.ConnectionID,
		strconv.FormatInt(binding.Generation, 10), strconv.FormatInt(binding.Incarnation, 10), binding.RuntimeID)
}

func SignClientUpgradeProof(key ed25519.PrivateKey, binding ConnectionContext) (string, error) {
	if !validPrivateKey(key) {
		return "", errors.New("cftunnel: invalid upgrade signing key")
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, upgradeProofMessage(binding))), nil
}

func VerifyClientUpgradeProof(key ed25519.PublicKey, binding ConnectionContext, proof string) bool {
	if len(key) != ed25519.PublicKeySize || len(proof) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return false
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(proof)
	return err == nil && ed25519.Verify(key, upgradeProofMessage(binding), signature)
}

func hasSubprotocol(header http.Header) bool {
	for _, field := range header.Values("Sec-WebSocket-Protocol") {
		for token := range strings.SplitSeq(field, ",") {
			if strings.TrimSpace(token) == Subprotocol {
				return true
			}
		}
	}
	return false
}

func forbidden(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, "Forbidden")
}

func (l *Listener) serveHTTP(w http.ResponseWriter, r *http.Request) {
	jti, proofs := r.Header.Values(ticketHeader), r.Header.Values(proofHeader)
	if r.Method != http.MethodGet || r.RequestURI != tunnelPath || r.URL.Path != tunnelPath ||
		r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" ||
		r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
		len(jti) != 1 || len(proofs) != 1 || len(r.Header.Values("Host")) != 0 || !hasSubprotocol(r.Header) {
		forbidden(w)
		return
	}
	l.mu.Lock()
	permit := l.pending[jti[0]]
	l.mu.Unlock()
	if permit == nil || !strings.EqualFold(strings.TrimSuffix(r.Host, ":443"), permit.Hostname) ||
		!time.Now().Before(permit.ExpiresAt) ||
		!VerifyClientUpgradeProof(permit.VisitorPublicKey, permit.ConnectionContext, proofs[0]) || !permit.Allows() {
		forbidden(w)
		return
	}
	ctx, slot := l.admit(jti[0], permit)
	if slot == nil {
		forbidden(w)
		return
	}
	defer l.finish(slot)
	handshake, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if handshake.Err() != nil {
		forbidden(w)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
	if err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = ws.CloseNow() })
	defer stop()
	defer ws.CloseNow()
	cfg, err := tlsConfig(l.opts.PrivateKey, permit.VisitorPublicKey, true)
	if err != nil {
		return
	}
	conn, err := innerHandshake(handshake, ctx, ws, cfg, permit.ConnectionContext, true, permit.access, permit.LocalLeaseProvider)
	if err != nil || !permit.Allows() {
		return
	}
	cancel()
	l.mu.Lock()
	peer := newPeer(ctx, slot.cancel, conn, permit.UserID, permit.Allows, permit.AccessUntil, permit.access, l.opts.Handler, l.opts.AssemblyBudget)
	peer.deviceID = permit.VisitorDeviceID
	slot.peer = peer
	l.handshakes--
	l.mu.Unlock()
	peer.run()
}

func (l *Listener) admit(jti string, permit *pendingPermit) (context.Context, *connectionSlot) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.ctx.Err() != nil || l.pending[jti] != permit || !now.Before(permit.ExpiresAt) ||
		!now.Before(permit.AccessUntil) || l.handshakes >= l.opts.MaxHandshakes ||
		len(l.connections) >= l.opts.MaxActivePeers {
		return nil, nil
	}
	visitorPeers := 0
	for _, slot := range l.connections {
		if slot.permit.VisitorDeviceID == permit.VisitorDeviceID {
			visitorPeers++
		}
	}
	if visitorPeers >= l.opts.MaxPeersPerVisitor {
		return nil, nil
	}
	l.invalidateLocked(jti, permit)
	ctx, cancel := context.WithCancel(l.ctx)
	slot := &connectionSlot{permit: permit, cancel: cancel}
	l.connections[permit.ConnectionID] = slot
	l.handshakes++
	return ctx, slot
}

func (l *Listener) finish(slot *connectionSlot) {
	slot.cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	if slot.peer == nil {
		l.handshakes--
	}
	delete(l.connections, slot.permit.ConnectionID)
}

func (l *Listener) revoke(matches func(*pendingPermit) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for jti, permit := range l.pending {
		if matches(permit) {
			l.invalidateLocked(jti, permit)
		}
	}
	for _, slot := range l.connections {
		if matches(slot.permit) {
			slot.cancel()
		}
	}
}

func (l *Listener) RevokeVisitor(device string) {
	l.revoke(func(permit *pendingPermit) bool { return permit.VisitorDeviceID == device })
}

func (l *Listener) RevokeUser(user string) {
	l.revoke(func(permit *pendingPermit) bool { return permit.UserID == user })
}

func (l *Listener) CloseConnection(connectionID string) {
	l.revoke(func(permit *pendingPermit) bool { return permit.ConnectionID == connectionID })
}

func (l *Listener) RevokeAll() {
	l.revoke(func(*pendingPermit) bool { return true })
}

func (l *Listener) RecheckPeers() {
	l.mu.Lock()
	permits := make([]*pendingPermit, 0, len(l.pending)+len(l.connections))
	for _, permit := range l.pending {
		permits = append(permits, permit)
	}
	for _, slot := range l.connections {
		permits = append(permits, slot.permit)
	}
	l.mu.Unlock()
	denied := make(map[*pendingPermit]bool)
	for _, permit := range permits {
		if !permit.Allows() {
			denied[permit] = true
		}
	}
	l.revoke(func(permit *pendingPermit) bool { return denied[permit] })
}

func (l *Listener) UpdateAccessUntil(connectionID string, until time.Time) {
	l.updateAccessUntil(connectionID, "", until)
}

func (l *Listener) updateAccessUntil(connectionID, ticket string, until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for jti, permit := range l.pending {
		if permit.ConnectionID == connectionID && (ticket == "" || ticket == jti) {
			permit.AccessUntil = until
			if !time.Now().Before(until) {
				l.invalidateLocked(jti, permit)
			}
			return
		}
	}
	if slot := l.connections[connectionID]; slot != nil && (ticket == "" || slot.permit.JTI == ticket) {
		slot.permit.AccessUntil = until
		if slot.peer != nil {
			slot.peer.UpdateAccessUntil(until)
		} else if !time.Now().Before(until) {
			slot.cancel()
		}
	}
}

func (l *Listener) UpdateLocalLease(proof endpoint.LeaseProof) error {
	return l.updateLocalLease(proof, func() bool { return true })
}

func (l *Listener) updateLocalLease(proof endpoint.LeaseProof, current func() bool) error {
	l.mu.Lock()
	revision := l.authority.Load()
	peers := make([]*Peer, 0, len(l.connections))
	for _, slot := range l.connections {
		if slot.peer != nil && slot.permit.official() && slot.peer.ctx.Err() == nil {
			peers = append(peers, slot.peer)
		}
	}
	l.mu.Unlock()
	results := make(chan error, len(peers))
	for _, peer := range peers {
		go func() {
			results <- peer.updateLocalLease(proof, func() bool { return l.authority.Load() == revision && current() })
		}()
	}
	var result error
	for range peers {
		result = errors.Join(result, <-results)
	}
	return result
}

func (l *Listener) AuthorityLost() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.authority.Add(1)
	for jti, permit := range l.pending {
		if permit.official() {
			l.invalidateLocked(jti, permit)
		}
	}
	for _, slot := range l.connections {
		if slot.peer != nil {
			slot.peer.AuthorityLost()
		} else if slot.permit.official() {
			slot.cancel()
		}
	}
}

func (l *Listener) ActivePeers() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	count := 0
	for _, slot := range l.connections {
		if slot.peer != nil && slot.peer.ctx.Err() == nil {
			count++
		}
	}
	return count
}

func (l *Listener) Close() error {
	l.cancel()
	l.mu.Lock()
	clear(l.pending)
	clear(l.spent)
	l.mu.Unlock()
	return l.server.Close()
}

type headerListener struct{ net.Listener }

func (ln headerListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &headerConn{Conn: conn, remaining: maxHeaderSize}, nil
}

// net/http adds a fixed read allowance to MaxHeaderBytes. Bound raw bytes
// through the first header terminator, including discarded HTTP whitespace.
type headerConn struct {
	net.Conn
	remaining int
	lastBytes uint32
	complete  bool
}

func (conn *headerConn) Read(buffer []byte) (int, error) {
	if conn.complete {
		return conn.Conn.Read(buffer)
	}
	if conn.remaining == 0 {
		return 0, errors.New("cftunnel: HTTP header limit exceeded")
	}
	buffer = buffer[:min(len(buffer), conn.remaining)]
	size, err := conn.Conn.Read(buffer)
	conn.remaining -= size
	for _, char := range buffer[:size] {
		conn.lastBytes = conn.lastBytes<<8 | uint32(char)
		if conn.lastBytes == 0x0d0a0d0a || uint16(conn.lastBytes) == 0x0a0a {
			conn.complete = true
			break
		}
	}
	return size, err
}
