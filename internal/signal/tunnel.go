package signal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

const (
	tunnelAudience        = "tunnel-v1"
	tunnelPath            = "/v1/tunnel/ws"
	tunnelHostTTL         = 45 * time.Second
	tunnelOfferTTL        = 5 * time.Second
	tunnelRefreshInterval = 10 * time.Second
)

var (
	tunnelIdentifier     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	errTunnelUnavailable = errors.New("device_unavailable")
	errInvalidTunnel     = errors.New("invalid_tunnel_record")
)

type TunnelAccessRequest struct {
	Host, Visitor           identity.Principal
	HostLease, VisitorLease time.Time
	Generation, Incarnation int64
}

type TunnelController interface {
	ScopeID() string
	RecordHostPresence(context.Context, identity.Principal, string, string, string, int64, int64, int64, bool) error
	AuthorizeVisitor(context.Context, TunnelAccessRequest) (string, time.Time, error)
	RefreshVisitorAccess(context.Context, TunnelAccessRequest) (string, time.Time, error)
	MintEdgeTicket(context.Context, identity.Principal, int64, int64, string, string) (string, error)
	ReleasedForOwner(context.Context, identity.Principal, string) bool
}

func (h *Hub) ConfigureTunnel(ctrl TunnelController) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, session := range h.tunnelSessions {
		h.dropTunnel(session, "tunnel_unavailable", 0)
	}
	for _, p := range h.peers {
		p.tunnelHost = tunnelHostState{}
	}
	h.tunnel = ctrl
	h.tunnelSessions = make(map[string]*tunnelSession)
}

func (h *Hub) ConfigureTunnelClientIP(extract func(*http.Request) string) {
	h.tunnelClientIP = extract
}

func (h *Hub) HasActiveTunnelRuntime(deviceID, deviceKeyHash, runtimeID string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	host := h.peers[deviceID]
	return h.tunnel != nil && host != nil && host.live(now) && tunnelKeyHash(host.id.PublicKey) == deviceKeyHash &&
		runtimeID != "" && host.tunnelHost.RuntimeID == runtimeID && now.Before(host.tunnelHost.expires) &&
		(host.tunnelHost.Phase == "starting" || host.tunnelHost.Phase == "listening")
}

type tunnelDomain struct {
	Audience string `json:"aud"`
	Scope    string `json:"scope"`
}

type tunnelHostBody struct {
	tunnelDomain
	SocketID    string `json:"socket_id"`
	RuntimeID   string `json:"runtime_id"`
	Phase       string `json:"phase"`
	Generation  int64  `json:"generation"`
	Incarnation int64  `json:"incarnation"`
	CanRecover  bool   `json:"can_recover"`
}

type tunnelHostState struct {
	tunnelHostBody
	seq     uint64
	expires time.Time
}

type tunnelConnectBody struct {
	tunnelDomain
	ExpectedOwner string `json:"expected_owner"`
	TargetPinHash string `json:"target_pin_hash"`
	ClientNonce   string `json:"client_nonce"`
	Lease         string `json:"lease,omitempty"`
	PairProof     string `json:"pair_proof,omitempty"`
	Role          string `json:"role,omitempty"`
}

type tunnelSessionBinding struct {
	Generation  int64  `json:"generation"`
	Incarnation int64  `json:"incarnation"`
	RuntimeID   string `json:"runtime_id"`
}

type tunnelPermitBody struct {
	tunnelDomain
	tunnelSessionBinding
	Hostname       string    `json:"hostname"`
	JTI            string    `json:"jti"`
	ClientNonce    string    `json:"client_nonce"`
	VisitorKeyHash string    `json:"visitor_key_hash"`
	Path           string    `json:"path"`
	ExpiresAt      time.Time `json:"expires_at"`
	Lease          string    `json:"lease,omitempty"`
}

type tunnelRefreshBody struct {
	tunnelDomain
	tunnelSessionBinding
	JTI string `json:"jti"`
}

type tunnelCloseBody struct {
	tunnelDomain
	Reason     string `json:"reason"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

type tunnelSession struct {
	tunnelSessionBinding
	id                                   string
	host, visitor                        *peer
	scope, hostname, clientNonce, jti    string
	socketID                             string
	offerUntil, accessUntil, lastRefresh time.Time
	offered, permitting, permitted       bool
	visitorSeq, hostSeq                  uint64
}

func tunnelKeyHash(key []byte) string {
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:])
}

func validTunnelValue(value string) bool {
	return len(value) >= 1 && len(value) <= 128 &&
		!strings.ContainsFunc(value, func(char rune) bool { return char < '!' || char > '~' })
}

func (h *Hub) handleTunnel(p *peer, m protocol.Message, ctrl TunnelController) error {
	if m.From != p.id.DeviceID || m.Seq == 0 || m.Round != 0 || m.Certificate != "" || len(m.Data) != 0 {
		return errInvalidTunnel
	}
	raw, err := m.Verify(p.id.PublicKey)
	if err != nil {
		return errors.New("bad_proof")
	}
	if len(raw) > 8<<10 || m.Type != "tunnel.host" && !protocol.ValidID(m.Connection) {
		return errInvalidTunnel
	}
	scope := ctrl.ScopeID()
	switch m.Type {
	case "tunnel.host":
		var body tunnelHostBody
		if strictjson.Decode(raw, &body) == nil && body.valid(scope) {
			return h.announceTunnelHost(p, m, body, ctrl)
		}
	case "tunnel.connect":
		var body tunnelConnectBody
		if strictjson.Decode(raw, &body) == nil && body.valid(scope) {
			return h.connectTunnel(p, m, body, ctrl)
		}
	case "tunnel.permit":
		var body tunnelPermitBody
		if strictjson.Decode(raw, &body) == nil && body.valid(scope) {
			return h.permitTunnel(p, m, body, ctrl)
		}
	case "tunnel.refresh":
		var body tunnelRefreshBody
		if strictjson.Decode(raw, &body) == nil && body.valid(scope) {
			return h.refreshTunnel(p, m, body, ctrl)
		}
	case "tunnel.close":
		var body tunnelCloseBody
		if strictjson.Decode(raw, &body) == nil && body.valid(scope) {
			return h.closeTunnel(p, m, body)
		}
	}
	return errInvalidTunnel
}

func (d tunnelDomain) valid(scope string) bool {
	return d.Audience == tunnelAudience && scope != "" && d.Scope == scope
}

func (h *Hub) announceTunnelHost(p *peer, m protocol.Message, body tunnelHostBody, ctrl TunnelController) error {
	if p.role != "desktop" || p.desktop != "" || m.Connection != "" || m.To != "" && m.To != "signal" ||
		!validTunnelValue(body.RuntimeID) || !validTunnelValue(body.SocketID) || body.Generation < 0 ||
		body.Incarnation < 0 || body.Incarnation > body.Generation || m.Seq > math.MaxInt64 ||
		(body.Phase != "starting" && body.Phase != "listening" && body.Phase != "stopping") {
		return errInvalidTunnel
	}
	h.mu.Lock()
	now := time.Now()
	if h.peers[p.slotKey()] != p || !p.live(now) || m.Seq <= p.tunnelHost.seq {
		h.mu.Unlock()
		return errInvalidTunnel
	}
	old := p.tunnelHost
	expires := now.Add(tunnelHostTTL)
	p.tunnelHost = tunnelHostState{body, m.Seq, expires}
	if body.Phase != "listening" || old.RuntimeID != body.RuntimeID || old.Generation != body.Generation ||
		old.Incarnation != body.Incarnation || old.SocketID != body.SocketID {
		h.dropPeerHostTunnels(p, "runtime_changed")
	}
	id := p.id
	h.mu.Unlock()
	if body.Generation > 0 {
		ctx, cancel := context.WithTimeout(p.ctx, time.Second)
		defer cancel()
		if err := ctrl.RecordHostPresence(ctx, id, body.RuntimeID, body.SocketID, body.Phase, body.Generation,
			body.Incarnation, int64(m.Seq), body.CanRecover); err != nil {
			slog.DebugContext(ctx, "tunnel presence update failed")
		}
	}
	p.send(protocol.Message{Type: "tunnel.host.ack", Data: protocol.Encode(struct {
		RuntimeID string    `json:"runtime_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}{body.RuntimeID, expires.UTC()})})
	return nil
}

func tunnelAllows(host, visitor *peer) bool {
	return host.allows(visitor) && (!host.selfHosted || host.grants[visitor.id.DeviceID])
}

func tunnelOwner(p *peer) string {
	if p.selfHosted {
		return p.id.DeviceID
	}
	return p.id.RemoteUserID()
}

func (h *Hub) connectTunnel(p *peer, m protocol.Message, body tunnelConnectBody, ctrl TunnelController) error {
	if (p.role != "mobile" && p.role != "desktop") || p.desktop != "" && p.desktop != m.To ||
		!tunnelIdentifier.MatchString(m.To) || !validTunnelValue(body.ClientNonce) || (body.Role != "" && body.Role != p.role) {
		return errTunnelUnavailable
	}
	h.mu.Lock()
	now := time.Now()
	host := h.peers[m.To]
	if !p.live(now) || h.peers[p.slotKey()] != p {
		h.mu.Unlock()
		return errTunnelUnavailable
	}
	if host == nil || !host.live(now) || !host.online {
		id, owner := p.id, tunnelOwner(p)
		h.mu.Unlock()
		if body.ExpectedOwner == owner && ctrl.ReleasedForOwner(p.ctx, id, m.To) {
			h.mu.Lock()
			defer h.mu.Unlock()
			current := h.peers[m.To]
			now = time.Now()
			if p.live(now) && (current == nil || !current.online || !current.live(now)) {
				return errors.New("tunnel_released")
			}
		}
		return errTunnelUnavailable
	}
	state := host.tunnelHost
	if !tunnelAllows(host, p) || state.Phase != "listening" || !now.Before(state.expires) ||
		state.Generation < 1 || state.Incarnation < 1 || body.ExpectedOwner != tunnelOwner(host) ||
		body.TargetPinHash != tunnelKeyHash(host.id.PublicKey) || h.tunnelSessions[m.Connection] != nil ||
		!h.tunnelCapacity(host, p, nil, false) {
		h.mu.Unlock()
		return errTunnelUnavailable
	}
	session := &tunnelSession{
		tunnelSessionBinding: tunnelSessionBinding{state.Generation, state.Incarnation, state.RuntimeID},
		id:                   m.Connection, host: host, visitor: p, scope: body.Scope, socketID: state.SocketID,
		clientNonce: body.ClientNonce, visitorSeq: m.Seq, offerUntil: now.Add(tunnelOfferTTL),
	}
	req := session.accessRequest()
	cert := p.cert
	h.tunnelSessions[session.id] = session
	h.mu.Unlock()
	ctx, cancel := context.WithDeadline(p.ctx, session.offerUntil)
	defer cancel()
	var hostname string
	var until time.Time
	var authErr error
	if body.Lease != "" {
		req.VisitorLease = h.tunnelLease(body.Lease, cert, req.Visitor, req.VisitorLease, now)
		if req.VisitorLease.IsZero() {
			authErr = errInvalidTunnel
		}
	}
	if authErr == nil {
		hostname, until, authErr = ctrl.AuthorizeVisitor(ctx, req)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now = time.Now()
	until = session.clampAccess(until, now)
	if h.tunnelSessions[session.id] != session {
		return nil
	}
	if authErr != nil || hostname == "" || !session.live(now) || !until.After(now) ||
		!h.tunnelCapacity(host, p, session, false) {
		delete(h.tunnelSessions, session.id)
		return errTunnelUnavailable
	}
	session.hostname, session.accessUntil, session.offered = hostname, until, true
	session.offerUntil = now.Add(tunnelOfferTTL)
	var visitorKey string
	if p.selfHosted {
		visitorKey = base64.RawURLEncoding.EncodeToString(p.id.PublicKey)
	} else {
		m.Certificate = cert
	}
	host.send(protocol.Message{Type: "tunnel.offer", Connection: session.id, From: m.From, To: m.To, Data: protocol.Encode(struct {
		Connect          protocol.Message `json:"connect"`
		VisitorPublicKey string           `json:"visitor_public_key,omitempty"`
		tunnelSessionBinding
		AccessUntil time.Time `json:"access_until"`
	}{m, visitorKey, session.tunnelSessionBinding, until.UTC()})})
	return nil
}

func (h *Hub) permitTunnel(p *peer, m protocol.Message, body tunnelPermitBody, ctrl TunnelController) error {
	h.mu.Lock()
	now := time.Now()
	session := h.tunnelSessions[m.Connection]
	if session == nil || session.scope != body.Scope || p != session.host || m.To != session.visitor.id.DeviceID ||
		!session.offered || session.permitting || session.permitted || !session.live(now) || !session.accessUntil.After(now) ||
		m.Seq <= session.hostSeq || body.tunnelSessionBinding != session.tunnelSessionBinding ||
		body.Hostname != session.hostname || body.ClientNonce != session.clientNonce ||
		body.VisitorKeyHash != tunnelKeyHash(session.visitor.id.PublicKey) || body.Path != tunnelPath ||
		!tunnelIdentifier.MatchString(body.JTI) || !body.ExpiresAt.After(now) || body.ExpiresAt.After(now.Add(20*time.Second)) {
		h.mu.Unlock()
		return errInvalidTunnel
	}
	id, cert, lease := p.id, p.cert, p.lease
	session.permitting, session.hostSeq = true, m.Seq
	h.mu.Unlock()
	if body.Lease != "" {
		lease = h.tunnelLease(body.Lease, cert, id, lease, now)
	}
	ctx, cancel := context.WithDeadline(p.ctx, session.offerUntil)
	defer cancel()
	var ticket string
	var err error
	if h.selfHosted && body.Lease == "" || lease.After(now) {
		ticket, err = ctrl.MintEdgeTicket(ctx, id, body.Generation, body.Incarnation, body.Hostname, body.JTI)
	} else {
		err = errInvalidTunnel
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now = time.Now()
	if h.tunnelSessions[session.id] != session {
		return nil
	}
	until := session.clampAccess(session.accessUntil, now)
	if !h.selfHosted && lease.Before(until) {
		until = lease
	}
	if err != nil || !session.live(now) || !until.After(now) || !body.ExpiresAt.After(now) ||
		!h.tunnelCapacity(p, session.visitor, session, true) {
		h.dropTunnel(session, "device_unavailable", 0)
		return nil
	}
	session.permitting, session.permitted, session.jti, session.lastRefresh, session.accessUntil = false, true, body.JTI, now, until
	m.Certificate = cert
	session.visitor.send(protocol.Message{Type: "tunnel.target", Connection: session.id, From: m.From, To: m.To, Data: protocol.Encode(struct {
		Permit      protocol.Message `json:"permit"`
		EdgeTicket  string           `json:"edge_ticket"`
		AccessUntil time.Time        `json:"access_until"`
	}{m, ticket, until.UTC()})})
	return nil
}

func (h *Hub) refreshTunnel(p *peer, m protocol.Message, body tunnelRefreshBody, ctrl TunnelController) error {
	h.mu.Lock()
	now := time.Now()
	session := h.tunnelSessions[m.Connection]
	if session == nil || session.visitor != p || m.To != session.host.id.DeviceID || !session.permitted ||
		body.Scope != session.scope || body.JTI != session.jti || body.tunnelSessionBinding != session.tunnelSessionBinding ||
		m.Seq <= session.visitorSeq || now.Sub(session.lastRefresh) < tunnelRefreshInterval {
		h.mu.Unlock()
		return errInvalidTunnel
	}
	if !session.live(now) {
		h.dropTunnel(session, "access_expired", 0)
		h.mu.Unlock()
		return nil
	}
	session.lastRefresh, session.visitorSeq = now, m.Seq
	req := session.accessRequest()
	expires := session.accessUntil
	h.mu.Unlock()
	ctx, cancel := context.WithDeadline(p.ctx, expires)
	defer cancel()
	hostname, until, err := ctrl.RefreshVisitorAccess(ctx, req)
	h.mu.Lock()
	defer h.mu.Unlock()
	now = time.Now()
	if h.tunnelSessions[session.id] != session {
		return nil
	}
	until = session.clampAccess(until, now)
	if err != nil || hostname != session.hostname || !session.live(now) || !until.After(now) {
		h.dropTunnel(session, "access_revoked", 0)
		return nil
	}
	session.accessUntil = until
	msg := protocol.Message{Type: "tunnel.access", Connection: session.id, Data: protocol.Encode(struct {
		tunnelSessionBinding
		JTI         string    `json:"jti"`
		AccessUntil time.Time `json:"access_until"`
	}{session.tunnelSessionBinding, session.jti, until.UTC()})}
	session.host.send(msg)
	p.send(msg)
	return nil
}

func (h *Hub) closeTunnel(p *peer, m protocol.Message, body tunnelCloseBody) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	session := h.tunnelSessions[m.Connection]
	if session == nil || body.Scope != session.scope || !p.live(time.Now()) ||
		!tunnelIdentifier.MatchString(body.Reason) || body.RetryAfter < 0 {
		return errInvalidTunnel
	}
	switch {
	case p == session.host && m.To == session.visitor.id.DeviceID && session.offered && m.Seq > session.hostSeq:
	case p == session.visitor && m.To == session.host.id.DeviceID && m.Seq > session.visitorSeq:
	default:
		return errInvalidTunnel
	}
	h.dropTunnel(session, body.Reason, body.RetryAfter)
	return nil
}

func (s *tunnelSession) live(now time.Time) bool {
	host := s.host.tunnelHost
	if !s.host.live(now) || !s.visitor.live(now) || !tunnelAllows(s.host, s.visitor) || host.Phase != "listening" ||
		!now.Before(host.expires) || host.Generation != s.Generation || host.Incarnation != s.Incarnation ||
		host.RuntimeID != s.RuntimeID || host.SocketID != s.socketID {
		return false
	}
	if s.permitted {
		return now.Before(s.accessUntil)
	}
	return now.Before(s.offerUntil)
}

func (s *tunnelSession) accessRequest() TunnelAccessRequest {
	return TunnelAccessRequest{s.host.id, s.visitor.id, s.host.lease, s.visitor.lease, s.Generation, s.Incarnation}
}

func (s *tunnelSession) clampAccess(until, now time.Time) time.Time {
	if s.host.selfHosted {
		return minTime(until, now.Add(time.Minute))
	}
	return minTime(until, now.Add(time.Minute), s.host.id.Expires, s.host.lease, s.visitor.id.Expires, s.visitor.lease)
}

func minTime(value time.Time, bounds ...time.Time) time.Time {
	for _, bound := range bounds {
		if bound.Before(value) {
			value = bound
		}
	}
	return value
}

func (h *Hub) tunnelLease(raw, cert string, id identity.Principal, current, now time.Time) time.Time {
	expires, err := identity.VerifyEndpointLease(raw, h.key, now, cert, id)
	if h.selfHosted || err != nil || !expires.After(now) {
		return time.Time{}
	}
	return minTime(current, expires)
}

func (h *Hub) tunnelCapacity(host, visitor *peer, current *tunnelSession, permitting bool) bool {
	pending, perVisitor, perIP, active, activeVisitor := 0, 0, 0, 0, 0
	for _, s := range h.tunnelSessions {
		if s == current || s.host != host {
			continue
		}
		sameVisitor := s.visitor.id.DeviceID == visitor.id.DeviceID
		if s.permitted {
			active++
			if sameVisitor {
				activeVisitor++
			}
			continue
		}
		pending++
		if sameVisitor {
			perVisitor++
		}
		if s.visitor.tunnelIP == visitor.tunnelIP {
			perIP++
		}
	}
	if permitting {
		return active < 16 && activeVisitor < 2
	}
	return pending < 32 && perVisitor < 2 && perIP < 16 && active < 16 && activeVisitor < 2
}

func (h *Hub) dropTunnel(s *tunnelSession, reason string, retry int) {
	delete(h.tunnelSessions, s.id)
	domain := tunnelDomain{Audience: tunnelAudience, Scope: s.scope}
	msg := protocol.Message{Type: "tunnel.close", Connection: s.id, Data: protocol.Encode(tunnelCloseBody{
		tunnelDomain: domain, Reason: reason, RetryAfter: retry,
	})}
	if s.offered {
		s.host.send(msg)
	}
	if !s.permitted {
		msg.Data = protocol.Encode(tunnelCloseBody{tunnelDomain: domain, Reason: "device_unavailable"})
	}
	s.visitor.send(msg)
}

func (h *Hub) dropPeerTunnels(p *peer, reason string) {
	for _, s := range h.tunnelSessions {
		if s.host == p || s.visitor == p {
			h.dropTunnel(s, reason, 0)
		}
	}
}

func (h *Hub) dropPeerHostTunnels(p *peer, reason string) {
	for _, s := range h.tunnelSessions {
		if s.host == p {
			h.dropTunnel(s, reason, 0)
		}
	}
}

func (h *Hub) revokeTunnelGrants(p *peer) {
	for _, s := range h.tunnelSessions {
		if s.host == p && !tunnelAllows(p, s.visitor) {
			h.dropTunnel(s, "access_revoked", 0)
		}
	}
}

func (h *Hub) expireTunnels(now time.Time) {
	for _, s := range h.tunnelSessions {
		if !s.live(now) {
			h.dropTunnel(s, "access_expired", 0)
		}
	}
}
