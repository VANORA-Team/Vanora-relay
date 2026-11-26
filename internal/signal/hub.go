// Package signal routes authenticated, endpoint-signed WebRTC negotiation.
package signal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"vanora-relay/endpoint"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/pairing"
	"vanora-relay/protocol"
)

const (
	selfTurnWindow = 10 * time.Minute

	maxAuthenticatedSlots = 1024
	maxPreAuthSlots       = 256
	maxPreAuthPerIP       = 16

	maxPhoneLinks          = 8
	maxHostAcceptedLinks   = 32
	maxHostPendingLinks    = 32
	maxPendingPerPhoneHost = 2
	maxPendingPerIPHost    = 16
)

// EntitlementVerifier checks whether the account that signed in with issuer
// and subject may use TURN relay. A zero time with a nil error means the
// account is definitively not entitled.
type EntitlementVerifier interface {
	Check(context.Context, string, string) (time.Time, error)
}
type iceService interface {
	Config(connectionID, visitor string, until time.Time) ([]ice.ICEServer, error)
	Revoke(connectionID string)
}

type Hub struct {
	key            ed25519.PublicKey
	allowedIssuer  string
	selfHosted     bool
	entitlement    EntitlementVerifier
	ice            iceService
	accessToken    [sha256.Size]byte
	requireToken   bool
	preAuthSlots   chan struct{}
	preAuthMu      sync.Mutex
	preAuthByIP    map[string]int
	slots          chan struct{}
	mu             sync.Mutex
	peers          map[string]*peer
	links          map[string]*link
	invites        map[string]*peer
	activity       *activityTracker
	gate           unauthGate
	tunnel         TunnelController
	tunnelSessions map[string]*tunnelSession
	tunnelClientIP func(*http.Request) string
}

type peer struct {
	id         identity.Principal
	cert, role string
	desktop    string
	tunnelOnly bool
	selfHosted bool
	remoteIP   string
	card       protocol.Message
	lease      time.Time
	online     bool
	grants     map[string]bool
	out        chan protocol.Message
	probeWake  chan struct{}
	lastProbe  time.Time
	ctx        context.Context
	cancel     context.CancelFunc
	pairTicket string
	invites    map[string]pairing.Record
	tunnelHost tunnelHostState
	tunnelIP   string
}

type link struct {
	id                 string
	phone, host        *peer
	created            time.Time
	lastConfig         time.Time
	accepted, answered bool
	round              uint32
	phoneSeq, hostSeq  uint64
}

// New creates an official-site hub that verifies endpoint certificates against
// key and checks TURN entitlement via entitlement.
func New(key ed25519.PublicKey, entitlement EntitlementVerifier, network iceService) *Hub {
	return &Hub{
		key:          key,
		entitlement:  entitlement,
		ice:          network,
		preAuthSlots: make(chan struct{}, maxPreAuthSlots),
		preAuthByIP:  make(map[string]int),
		slots:        make(chan struct{}, maxAuthenticatedSlots),
		peers:        make(map[string]*peer),
		links:        make(map[string]*link),
		invites:      make(map[string]*peer),
		gate:         newUnauthGate(),
	}
}

// NewSelfHosted creates an account-free self-hosted hub. Access to /v1/signal
// is gated by accessToken and endpoint proof-of-possession over self-generated
// Ed25519 keys; desktop authorization is enforced end-to-end via one-time
// pairing on the desktop.
func NewSelfHosted(accessToken string, network iceService) *Hub {
	h := &Hub{
		selfHosted:   true,
		ice:          network,
		preAuthSlots: make(chan struct{}, maxPreAuthSlots),
		preAuthByIP:  make(map[string]int),
		slots:        make(chan struct{}, maxAuthenticatedSlots),
		peers:        make(map[string]*peer),
		links:        make(map[string]*link),
		invites:      make(map[string]*peer),
		gate:         newUnauthGate(),
	}
	if accessToken != "" {
		h.RequireAccessToken(accessToken)
	}
	return h
}

// RequireIssuer restricts an official hub to endpoint certificates whose iss
// claim exactly matches issuer. Call it before serving requests.
func (h *Hub) RequireIssuer(issuer string) {
	h.allowedIssuer = strings.TrimSpace(issuer)
}

// RequireAccessToken restricts WebSocket upgrades to clients that present
// token as a bearer credential. A self-hosted node uses it so a leaked URL
// does not let strangers relay traffic. Call it before serving requests.
func (h *Hub) RequireAccessToken(token string) {
	h.accessToken = sha256.Sum256([]byte(token))
	h.requireToken = true
}

func (p *peer) send(m protocol.Message) {
	select {
	case <-p.ctx.Done():
	case p.out <- m:
	default:
		p.cancel()
	}
}

func (host *peer) allows(visitor *peer) bool {
	if !host.online || host.role != "desktop" || host.id.DeviceID == visitor.id.DeviceID {
		return false
	}
	if host.selfHosted {
		return visitor.selfHosted && (visitor.role == "mobile" || visitor.role == "desktop")
	}
	if visitor.selfHosted {
		return false
	}
	return host.id.RemoteUserID() == visitor.id.RemoteUserID() || host.grants[visitor.id.RemoteUserID()]
}

func (p *peer) live(now time.Time) bool {
	if p.ctx.Err() != nil {
		return false
	}
	if p.selfHosted {
		return true
	}
	return now.Before(p.lease) && now.Before(p.id.Expires)
}

func (h *Hub) drop(l *link, reason string) {
	delete(h.links, l.id)
	if h.ice != nil {
		h.ice.Revoke(l.id)
	}
	msg := protocol.Message{Type: "connect.closed", Connection: l.id, Data: protocol.Encode(reason)}
	l.host.send(msg)
	l.phone.send(msg)
}

func (p *peer) slotKey() string {
	if p.tunnelOnly {
		return p.id.DeviceID + "\x00" + p.desktop + "\x00tunnel"
	}
	if p.desktop != "" {
		return p.id.DeviceID + "\x00" + p.desktop
	}
	return p.id.DeviceID
}

func (h *Hub) remove(p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[p.slotKey()] != p {
		return
	}
	delete(h.peers, p.slotKey())
	for key := range p.invites {
		delete(h.invites, key)
	}
	for _, l := range h.links {
		if l.host == p || l.phone == p {
			h.drop(l, "endpoint_offline")
		}
	}
	h.dropPeerTunnels(p, "endpoint_offline")
}

func (h *Hub) expire(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key, host := range h.invites {
		if !now.Before(host.invites[key].Expires) {
			delete(host.invites, key)
			delete(h.invites, key)
		}
	}
	for _, p := range h.peers {
		if !p.live(now) {
			p.cancel()
		}
	}
	for _, l := range h.links {
		if !l.accepted && now.Sub(l.created) > 20*time.Second {
			h.drop(l, "request_timeout")
		}
	}
	h.expireTunnels(now)
}

func (h *Hub) Run(ctx context.Context) {
	h.ensureActivityTracker().startWorker(ctx)
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case now := <-timer.C:
			h.expire(now)
		case <-ctx.Done():
			h.mu.Lock()
			for _, p := range h.peers {
				p.cancel()
			}
			h.mu.Unlock()
			return
		}
	}
}

func (h *Hub) handle(p *peer, m protocol.Message) error {
	if strings.HasPrefix(m.Type, "tunnel.") {
		h.mu.Lock()
		ctrl := h.tunnel
		h.mu.Unlock()
		if ctrl != nil {
			return h.handleTunnel(p, m, ctrl)
		}
		if p.tunnelOnly {
			return errors.New("tunnel_unavailable")
		}
	}
	if p.tunnelOnly && m.Type != "auth.lease" {
		return errors.New("tunnel_only")
	}
	if m.Type == "connect.accept" || m.Type == "ice.refresh" {
		return h.configure(p, m)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !p.live(time.Now()) {
		return errors.New("authorization_expired")
	}
	switch m.Type {
	case "auth.lease":
		if h.selfHosted {
			return errors.New("lease_unsupported")
		}
		var update struct {
			Lease       string `json:"lease"`
			Certificate string `json:"certificate"`
		}
		if json.Unmarshal(m.Data, &update) != nil {
			return errors.New("invalid_lease")
		}
		cert, next := p.cert, p.id
		if update.Certificate != "" {
			var err error
			cert = update.Certificate
			next, err = identity.VerifyCertificate(cert, h.key, time.Now())
			if err != nil || next.DeviceID != p.id.DeviceID || !next.PublicKey.Equal(p.id.PublicKey) || next.RemoteUserID() != p.id.RemoteUserID() {
				return errors.New("identity_changed")
			}
			if h.allowedIssuer != "" && next.Issuer != h.allowedIssuer {
				return errors.New("issuer_not_allowed")
			}
		}
		until, err := identity.VerifyEndpointLease(update.Lease, h.key, time.Now(), cert, next)
		if err != nil {
			return errors.New("invalid_lease")
		}
		p.lease, p.cert, p.id.Expires = until, cert, next.Expires
		p.send(protocol.Message{Type: "auth.renewed", Data: protocol.Encode(until.UTC())})
		return nil
	case "device.online":
		var d struct {
			Card   protocol.Message `json:"card"`
			Guests []string         `json:"guests"`
		}
		if p.role != "desktop" || p.desktop != "" || json.Unmarshal(m.Data, &d) != nil {
			return errors.New("invalid_device")
		}
		if h.selfHosted {
			if d.Card.Certificate != "" || len(d.Guests) > 256 || d.Card.Type != "device.card" || d.Card.From != p.id.DeviceID || d.Card.To != "self" || d.Card.Connection != "" || d.Card.Round != 0 || d.Card.Seq != 0 {
				return errors.New("invalid_device")
			}
			nameBytes, err := d.Card.Verify(p.id.PublicKey)
			if err != nil || !validSelfName(string(nameBytes)) {
				return errors.New("invalid_device")
			}
			// Self-hosted guests are the paired device IDs the desktop currently
			// authorizes; the activity poll uses them as the read ACL.
			grants := make(map[string]bool, len(d.Guests))
			for _, id := range d.Guests {
				if id == p.id.DeviceID || !identity.ValidSelfDeviceID(id) {
					return errors.New("invalid_guest")
				}
				grants[id] = true
			}
			p.card, p.grants, p.online = d.Card, grants, true
			h.revokeTunnelGrants(p)
			h.refreshActivityGrants(p)
			p.registered()
			return nil
		}
		if d.Card.Certificate != p.cert || len(d.Guests) > 256 {
			return errors.New("invalid_device")
		}
		if _, err := endpoint.VerifyDevice(d.Card, h.key, time.Now()); err != nil {
			return errors.New("invalid_device")
		}
		grants := make(map[string]bool, len(d.Guests))
		for _, id := range d.Guests {
			if len(id) == 0 || len(id) > 128 {
				return errors.New("invalid_guest")
			}
			grants[id] = true
		}
		p.card, p.grants, p.online = d.Card, grants, true
		h.revokeTunnelGrants(p)
		h.refreshActivityGrants(p)
		for _, l := range h.links {
			if l.host == p && !p.allows(l.phone) {
				h.drop(l, "access_revoked")
			}
		}
		p.registered()
		return nil
	case "devices.list":
		if h.selfHosted {
			return errors.New("directory_unavailable")
		}
		found := []protocol.Message{}
		for _, host := range h.peers {
			if host.allows(p) && host.live(time.Now()) {
				card := host.card
				card.Certificate = host.cert
				found = append(found, card)
			}
		}
		sort.Slice(found, func(i, j int) bool { return found[i].From < found[j].From })
		p.send(protocol.Message{Type: "devices.list", Data: protocol.Encode(found)})
		return nil
	}
	if !protocol.ValidID(m.Connection) || m.From != p.id.DeviceID || m.Seq == 0 || len(m.Data) != 0 || m.Certificate != "" {
		return errors.New("invalid_record")
	}
	if _, err := m.Verify(p.id.PublicKey); err != nil {
		return errors.New("bad_proof")
	}
	if m.Type == "connect.request" {
		host := h.peers[m.To]
		if (p.role != "mobile" && p.role != "desktop") || (p.desktop != "" && p.desktop != m.To) || host == nil || !host.live(time.Now()) || !host.allows(p) {
			return errors.New("device_unavailable")
		}
		if _, exists := h.links[m.Connection]; exists || m.Round != 0 {
			return errors.New("invalid_connection")
		}
		phoneCount, hostAccepted, hostPending, phoneHostPending, ipHostPending := 0, 0, 0, 0, 0
		for _, l := range h.links {
			if l.phone.id.DeviceID == p.id.DeviceID {
				phoneCount++
			}
			if l.host == host {
				if l.accepted {
					hostAccepted++
				} else {
					hostPending++
					if l.phone.id.DeviceID == p.id.DeviceID {
						phoneHostPending++
					}
					if p.remoteIP != "" && l.phone.remoteIP == p.remoteIP {
						ipHostPending++
					}
				}
			}
		}
		if phoneCount >= maxPhoneLinks ||
			hostAccepted >= maxHostAcceptedLinks ||
			hostPending >= maxHostPendingLinks ||
			phoneHostPending >= maxPendingPerPhoneHost ||
			ipHostPending >= maxPendingPerIPHost {
			return errors.New("connection_limit")
		}
		h.links[m.Connection] = &link{id: m.Connection, phone: p, host: host, phoneSeq: m.Seq, created: time.Now()}
		if !h.selfHosted {
			m.Certificate = p.cert
		}
		host.send(m)
		return nil
	}
	l := h.links[m.Connection]
	if l == nil {
		return errors.New("unknown_connection")
	}
	dest, last := l.host, &l.phoneSeq
	if l.host == p {
		dest, last = l.phone, &l.hostSeq
	} else if l.phone != p {
		return errors.New("unknown_connection")
	}
	if m.To != dest.id.DeviceID || !dest.live(time.Now()) || !l.host.allows(l.phone) || m.Seq <= *last {
		return errors.New("invalid_peer_or_sequence")
	}
	if m.Type == "connect.close" {
		reason := "peer_closed"
		if !l.accepted && p == l.host {
			reason = "access_denied"
		}
		h.drop(l, reason)
		return nil
	}
	if !l.accepted {
		return errors.New("not_accepted")
	}
	switch m.Type {
	case "rtc.offer":
		if p != l.phone || m.Round == 0 || m.Round != l.round+1 || (l.round > 0 && !l.answered) {
			return errors.New("invalid_round")
		}
		l.round, l.answered = m.Round, false
	case "rtc.answer":
		if p != l.host || l.round == 0 || m.Round != l.round || l.answered {
			return errors.New("invalid_answer")
		}
		l.answered = true
	case "rtc.candidate":
		if l.round == 0 || m.Round != l.round {
			return errors.New("invalid_round")
		}
	default:
		return errors.New("unknown_type")
	}
	*last = m.Seq
	dest.send(m)
	return nil
}

func (h *Hub) configure(p *peer, m protocol.Message) error {
	h.mu.Lock()
	l := h.links[m.Connection]
	if l == nil || !l.host.allows(l.phone) || !l.host.live(time.Now()) || !l.phone.live(time.Now()) {
		h.mu.Unlock()
		return errors.New("invalid_connection")
	}
	accepting := m.Type == "connect.accept"
	if accepting {
		if l.host != p || l.accepted || m.From != p.id.DeviceID || m.To != l.phone.id.DeviceID || m.Round != 0 || m.Seq <= l.hostSeq || len(m.Data) != 0 || m.Certificate != "" {
			h.mu.Unlock()
			return errors.New("invalid_accept")
		}
		if _, err := m.Verify(p.id.PublicKey); err != nil {
			h.mu.Unlock()
			return errors.New("bad_proof")
		}
	} else if l.phone != p || !l.accepted || time.Since(l.lastConfig) < 10*time.Second {
		h.mu.Unlock()
		return errors.New("refresh_unavailable")
	}
	l.lastConfig = time.Now()
	issuer, subject := l.phone.id.Issuer, l.phone.id.Subject
	phoneExpires := l.phone.id.Expires
	h.mu.Unlock()
	var until time.Time
	switch {
	case h.selfHosted:
		// Self-hosted nodes do not consult an external membership service; grant
		// a bounded sliding window renewed via ice.refresh while the link stays live.
		until = time.Now().Add(selfTurnWindow)
	case h.entitlement != nil:
		ctx, cancel := context.WithTimeout(p.ctx, 3*time.Second)
		var err error
		until, err = h.entitlement.Check(ctx, issuer, subject)
		cancel()
		if err != nil {
			until = time.Time{}
		}
	default:
		until = phoneExpires
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.links[m.Connection] != l || !l.host.allows(l.phone) || !l.host.live(time.Now()) || !l.phone.live(time.Now()) {
		return errors.New("connection_expired")
	}
	if !h.selfHosted {
		if until.After(l.phone.id.Expires) {
			until = l.phone.id.Expires
		}
		if until.After(l.host.id.Expires) {
			until = l.host.id.Expires
		}
	}
	if !until.After(time.Now()) {
		if h.ice != nil {
			h.ice.Revoke(l.id)
		}
		until = time.Time{}
	}
	visitor := l.phone.id.RemoteUserID()
	if h.selfHosted {
		visitor = l.phone.id.DeviceID
	}
	servers := []ice.ICEServer{}
	if h.ice != nil {
		var err error
		servers, err = h.ice.Config(l.id, visitor, until)
		if err != nil {
			h.drop(l, "ice_unavailable")
			return errors.New("ice_unavailable")
		}
	}
	if accepting {
		hostAccepted := 0
		for _, existing := range h.links {
			if existing.host == l.host && existing.accepted {
				hostAccepted++
			}
		}
		if hostAccepted >= maxHostAcceptedLinks {
			h.drop(l, "connection_limit")
			return errors.New("connection_limit")
		}
		l.accepted, l.hostSeq = true, m.Seq
		if !h.selfHosted {
			m.Certificate = p.cert
		}
		l.phone.send(m)
	}
	cfg := protocol.Message{Type: "ice.config", Connection: l.id, Data: protocol.Encode(servers)}
	l.phone.send(cfg)
	l.host.send(cfg)
	return nil
}

func validSelfName(name string) bool {
	return len(name) > 0 && len(name) <= 128 && strings.TrimSpace(name) == name && strings.IndexFunc(name, func(r rune) bool {
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	}) < 0
}
