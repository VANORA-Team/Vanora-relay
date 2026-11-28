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
	"sync/atomic"
	"time"
	"unicode"

	"github.com/coder/websocket"

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
	key             ed25519.PublicKey
	keys            []ed25519.PublicKey
	allowedIssuer   string
	selfHosted      bool
	entitlement     EntitlementVerifier
	ice             iceService
	accessToken     [sha256.Size]byte
	requireToken    bool
	preAuthSlots    chan struct{}
	preAuthMu       sync.Mutex
	preAuthByIP     map[string]int
	maxSlots        int
	mu              sync.Mutex
	peers           map[string]*peer
	peersByDevice   map[string]deviceSlots
	links           map[string]*link
	phoneLinkCount  map[string]int
	revokingICE     map[string]bool
	draining        bool
	connections     sync.WaitGroup
	invites         map[string]*peer
	activity        *activityTracker
	activityVersion uint64
	gate            *unauthGate
	tunnel          TunnelController
	tunnelSessions  map[string]*tunnelSession
	extractIP       func(*http.Request) string
}

type deviceSlots struct {
	role            string
	normal, tunnels int
}

type peer struct {
	id                 identity.Principal
	cert, role         string
	desktop            string
	tunnelOnly         bool
	selfHosted         bool
	remoteIP           string
	card               protocol.Message
	lease              time.Time
	online             bool
	grants             map[string]bool
	out                chan protocol.Message
	probeWake          chan struct{}
	lastProbe          time.Time
	connectedAt        time.Time
	done               chan struct{}
	ws                 *websocket.Conn
	ctx                context.Context
	cancel             context.CancelFunc
	pairTicket         string
	invites            map[string]pairing.Record
	tunnelHost         tunnelHostState
	tunnelIP           string
	legacyTunnelAcks   bool
	legacyTunnelErrors bool
	hostLinks          map[string]*link
	phoneLinks         map[string]*link
	hostTunnels        map[string]*tunnelSession
	visitorTunnels     map[string]*tunnelSession
	releasedLookup     bool
	nextReleasedLookup time.Time
	activityACL        atomic.Pointer[activityACL]
}

type link struct {
	id                 string
	phone, host        *peer
	created            time.Time
	lastConfig         time.Time
	grantUntil         time.Time
	configuring        bool
	accepting          bool
	accepted, answered bool
	round              uint32
	phoneSeq, hostSeq  uint64
}

// New creates an official-site hub that verifies endpoint certificates against
// key and checks TURN entitlement via entitlement.
func New(key ed25519.PublicKey, entitlement EntitlementVerifier, network iceService) *Hub {
	var keys []ed25519.PublicKey
	if len(key) > 0 {
		keys = []ed25519.PublicKey{append(ed25519.PublicKey(nil), key...)}
	}
	return &Hub{
		key:            key,
		keys:           keys,
		entitlement:    entitlement,
		ice:            network,
		preAuthSlots:   make(chan struct{}, maxPreAuthSlots),
		preAuthByIP:    make(map[string]int),
		maxSlots:       maxAuthenticatedSlots,
		peers:          make(map[string]*peer),
		peersByDevice:  make(map[string]deviceSlots),
		links:          make(map[string]*link),
		phoneLinkCount: make(map[string]int),
		revokingICE:    make(map[string]bool),
		invites:        make(map[string]*peer),
		gate:           newUnauthGate(),
	}
}

// ConfigureTrustedKeys replaces the set of trusted CA verification keys to
// support zero-downtime CA key rotation before serving traffic.
func (h *Hub) ConfigureTrustedKeys(keys []ed25519.PublicKey) {
	copied := make([]ed25519.PublicKey, 0, len(keys))
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize {
			copied = append(copied, append(ed25519.PublicKey(nil), k...))
		}
	}
	if len(copied) > 0 {
		h.key = copied[0]
		h.keys = copied
	}
}

func (h *Hub) trustedKeys() []ed25519.PublicKey {
	if len(h.keys) > 0 {
		return h.keys
	}
	if len(h.key) > 0 {
		return []ed25519.PublicKey{h.key}
	}
	return nil
}

// NewSelfHosted creates an account-free self-hosted hub. Access to /v1/signal
// is gated by accessToken and endpoint proof-of-possession over self-generated
// Ed25519 keys; desktop authorization is enforced end-to-end via one-time
// pairing on the desktop.
func NewSelfHosted(accessToken string, network iceService) *Hub {
	h := New(nil, nil, network)
	h.selfHosted = true
	if accessToken != "" {
		h.RequireAccessToken(accessToken)
	}
	return h
}

func (h *Hub) ConfigureMaxSlots(limit int) {
	if limit > 0 {
		h.mu.Lock()
		h.maxSlots = limit
		h.mu.Unlock()
	}
}

func (h *Hub) ConfigureClientIP(extract func(*http.Request) string) {
	h.extractIP = extract
}

func (h *Hub) clientIP(r *http.Request) string {
	if h.extractIP != nil {
		if ip := h.extractIP(r); ip != "" {
			return ip
		}
	}
	return remoteIPAddr(r.RemoteAddr)
}

type MetricsSnapshot struct {
	ActivePeers   int `json:"active_peers"`
	ActiveLinks   int `json:"active_links"`
	ActiveTunnels int `json:"active_tunnels"`
	PreAuthSlots  int `json:"pre_auth_slots"`
}

func (h *Hub) Metrics() MetricsSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return MetricsSnapshot{len(h.peers), len(h.links), len(h.tunnelSessions), len(h.preAuthSlots)}
}

func (h *Hub) Drain(ctx context.Context) {
	h.mu.Lock()
	h.draining = true
	peers := make([]*peer, 0, len(h.peers))
	for _, p := range h.peers {
		if p.ws != nil {
			peers = append(peers, p)
		}
	}
	h.mu.Unlock()
	for _, p := range peers {
		go func() { _ = p.ws.Close(websocket.StatusGoingAway, "relay shutting down") }()
	}
	for _, p := range peers {
		select {
		case <-p.done:
		case <-ctx.Done():
			for _, p := range peers {
				p.cancel()
			}
			return
		}
	}
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

func (h *Hub) drop(l *link, reason string) string {
	delete(h.links, l.id)
	delete(l.host.hostLinks, l.id)
	delete(l.phone.phoneLinks, l.id)
	device := l.phone.id.DeviceID
	if h.phoneLinkCount[device]--; h.phoneLinkCount[device] == 0 {
		delete(h.phoneLinkCount, device)
	}
	msg := protocol.Message{Type: "connect.closed", Connection: l.id, Data: protocol.Encode(reason)}
	l.host.send(msg)
	l.phone.send(msg)
	if h.ice == nil {
		return ""
	}
	h.revokingICE[l.id] = true
	if l.configuring {
		return ""
	}
	return l.id
}

func (h *Hub) revokeICE(ids ...string) {
	for _, id := range ids {
		if id != "" {
			h.ice.Revoke(id)
			h.mu.Lock()
			delete(h.revokingICE, id)
			h.mu.Unlock()
		}
	}
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
	if h.peers[p.slotKey()] != p {
		h.mu.Unlock()
		return
	}
	delete(h.peers, p.slotKey())
	device := p.id.DeviceID
	count := h.peersByDevice[device]
	if p.tunnelOnly {
		count.tunnels--
	} else {
		count.normal--
	}
	if count.normal+count.tunnels <= 0 {
		delete(h.peersByDevice, device)
	} else {
		h.peersByDevice[device] = count
	}
	for key := range p.invites {
		delete(h.invites, key)
	}
	var revoke []string
	for _, l := range p.hostLinks {
		revoke = append(revoke, h.drop(l, "endpoint_offline"))
	}
	for _, l := range p.phoneLinks {
		revoke = append(revoke, h.drop(l, "endpoint_offline"))
	}
	h.dropPeerTunnels(p, "endpoint_offline")
	if p.done != nil {
		close(p.done)
	}
	h.mu.Unlock()
	h.revokeICE(revoke...)
}

func (h *Hub) expire(now time.Time) {
	h.mu.Lock()
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
	var revoke []string
	for _, l := range h.links {
		if !l.accepted && now.Sub(l.created) > 20*time.Second {
			revoke = append(revoke, h.drop(l, "request_timeout"))
		}
	}
	h.expireTunnels(now)
	h.mu.Unlock()
	h.revokeICE(revoke...)
}

func (h *Hub) Run(ctx context.Context) {
	tr := h.ensureActivityTracker()
	tr.startWorker()
	defer tr.stopWorker()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	activityTimer := time.NewTicker(30 * time.Second)
	defer activityTimer.Stop()
	for {
		select {
		case now := <-timer.C:
			h.expire(now)
		case now := <-activityTimer.C:
			tr.prune(now)
		case <-ctx.Done():
			h.mu.Lock()
			h.draining = true
			for _, p := range h.peers {
				p.cancel()
			}
			h.mu.Unlock()
			h.connections.Wait()
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
	switch m.Type {
	case "auth.lease":
		return h.renewLease(p, m.Data)
	case "device.online":
		return h.registerDevice(p, m.Data)
	}
	if m.Type != "devices.list" {
		if !protocol.ValidID(m.Connection) || m.From != p.id.DeviceID || m.Seq == 0 || len(m.Data) != 0 || m.Certificate != "" {
			return errors.New("invalid_record")
		}
		if _, err := m.Verify(p.id.PublicKey); err != nil {
			return errors.New("bad_proof")
		}
	}
	h.mu.Lock()
	var revoke string
	defer func() {
		h.mu.Unlock()
		h.revokeICE(revoke)
	}()
	if !p.live(time.Now()) {
		return errors.New("authorization_expired")
	}
	if m.Type == "devices.list" {
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
	if m.Type == "connect.request" {
		host := h.peers[m.To]
		if (p.role != "mobile" && p.role != "desktop") || (p.desktop != "" && p.desktop != m.To) || host == nil || !host.live(time.Now()) || !host.allows(p) {
			return errors.New("device_unavailable")
		}
		if h.links[m.Connection] != nil || h.revokingICE[m.Connection] || m.Round != 0 {
			return errors.New("invalid_connection")
		}
		hostAccepted, hostPending, phoneHostPending, ipHostPending := 0, 0, 0, 0
		for _, l := range host.hostLinks {
			if l.accepted {
				hostAccepted++
				continue
			}
			hostPending++
			if l.phone.id.DeviceID == p.id.DeviceID {
				phoneHostPending++
			}
			if p.remoteIP != "" && l.phone.remoteIP == p.remoteIP {
				ipHostPending++
			}
		}
		if h.phoneLinkCount[p.id.DeviceID] >= maxPhoneLinks ||
			hostAccepted >= maxHostAcceptedLinks ||
			hostPending >= maxHostPendingLinks ||
			phoneHostPending >= maxPendingPerPhoneHost ||
			ipHostPending >= maxPendingPerIPHost {
			return errors.New("connection_limit")
		}
		request := &link{id: m.Connection, phone: p, host: host, phoneSeq: m.Seq, created: time.Now()}
		if host.hostLinks == nil {
			host.hostLinks = make(map[string]*link)
		}
		if p.phoneLinks == nil {
			p.phoneLinks = make(map[string]*link)
		}
		h.links[m.Connection], host.hostLinks[m.Connection], p.phoneLinks[m.Connection] = request, request, request
		h.phoneLinkCount[p.id.DeviceID]++
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
		revoke = h.drop(l, reason)
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

func (h *Hub) renewLease(p *peer, raw json.RawMessage) error {
	if h.selfHosted {
		return errors.New("lease_unsupported")
	}
	var update struct {
		Lease       string `json:"lease"`
		Certificate string `json:"certificate"`
	}
	if json.Unmarshal(raw, &update) != nil {
		return errors.New("invalid_lease")
	}
	h.mu.Lock()
	previousCert, previousID := p.cert, p.id
	h.mu.Unlock()
	now := time.Now()
	cert, next := previousCert, previousID
	if update.Certificate != "" {
		var err error
		cert = update.Certificate
		next, err = identity.VerifyCertificateWithKeys(cert, h.trustedKeys(), now)
		if err != nil || next.DeviceID != previousID.DeviceID || !next.PublicKey.Equal(previousID.PublicKey) || next.RemoteUserID() != previousID.RemoteUserID() {
			return errors.New("identity_changed")
		}
		if h.allowedIssuer != "" && next.Issuer != h.allowedIssuer {
			return errors.New("issuer_not_allowed")
		}
	}
	until, err := identity.VerifyEndpointLeaseWithKeys(update.Lease, h.trustedKeys(), now, cert, next)
	if err != nil {
		return errors.New("invalid_lease")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !p.live(time.Now()) || p.cert != previousCert {
		return errors.New("authorization_expired")
	}
	p.lease, p.cert, p.id.Expires = until, cert, next.Expires
	p.send(protocol.Message{Type: "auth.renewed", Data: protocol.Encode(until.UTC())})
	return nil
}

func (h *Hub) registerDevice(p *peer, raw json.RawMessage) error {
	var d struct {
		Card   protocol.Message `json:"card"`
		Guests []string         `json:"guests"`
	}
	if p.role != "desktop" || p.desktop != "" || json.Unmarshal(raw, &d) != nil || len(d.Guests) > 256 {
		return errors.New("invalid_device")
	}
	if h.selfHosted {
		if d.Card.Certificate != "" || d.Card.Type != "device.card" || d.Card.From != p.id.DeviceID || d.Card.To != "self" || d.Card.Connection != "" || d.Card.Round != 0 || d.Card.Seq != 0 {
			return errors.New("invalid_device")
		}
		nameBytes, err := d.Card.Verify(p.id.PublicKey)
		if err != nil || !validSelfName(string(nameBytes)) {
			return errors.New("invalid_device")
		}
	} else if _, err := endpoint.VerifyDeviceWithKeys(d.Card, h.trustedKeys(), time.Now()); err != nil {
		return errors.New("invalid_device")
	}
	grants := make(map[string]bool, len(d.Guests))
	for _, id := range d.Guests {
		if h.selfHosted && (id == p.id.DeviceID || !identity.ValidSelfDeviceID(id)) ||
			!h.selfHosted && (len(id) == 0 || len(id) > 128) {
			return errors.New("invalid_guest")
		}
		grants[id] = true
	}
	h.mu.Lock()
	if !p.live(time.Now()) {
		h.mu.Unlock()
		return errors.New("authorization_expired")
	}
	if !h.selfHosted && d.Card.Certificate != p.cert {
		h.mu.Unlock()
		return errors.New("invalid_device")
	}
	p.card, p.grants, p.online = d.Card, grants, true
	h.revokeTunnelGrants(p)
	h.activityVersion++
	p.activityACL.Store(&activityACL{owner: tunnelOwner(p), grants: grants, version: h.activityVersion})
	tr := h.activity
	var revoke []string
	for _, l := range p.hostLinks {
		if !p.allows(l.phone) {
			revoke = append(revoke, h.drop(l, "access_revoked"))
		}
	}
	h.mu.Unlock()
	if tr != nil {
		tr.refreshActivityGrants(p)
	}
	h.mu.Lock()
	p.registered()
	h.mu.Unlock()
	h.revokeICE(revoke...)
	return nil
}

func (h *Hub) configure(p *peer, m protocol.Message) error {
	accepting := m.Type == "connect.accept"
	var proofErr error
	if accepting {
		_, proofErr = m.Verify(p.id.PublicKey)
	}
	h.mu.Lock()
	l := h.links[m.Connection]
	if l == nil || !l.host.allows(l.phone) || !l.host.live(time.Now()) || !l.phone.live(time.Now()) {
		h.mu.Unlock()
		return errors.New("invalid_connection")
	}
	if accepting {
		if l.host != p || l.accepted || l.accepting || m.From != p.id.DeviceID || m.To != l.phone.id.DeviceID || m.Round != 0 || m.Seq <= l.hostSeq || len(m.Data) != 0 || m.Certificate != "" {
			h.mu.Unlock()
			return errors.New("invalid_accept")
		}
		if proofErr != nil {
			h.mu.Unlock()
			return errors.New("bad_proof")
		}
	} else if l.phone != p || !l.accepted || l.configuring || time.Since(l.lastConfig) < 10*time.Second {
		h.mu.Unlock()
		return errors.New("refresh_unavailable")
	}
	l.configuring, l.accepting = true, accepting
	l.lastConfig = time.Now()
	issuer, subject := l.phone.id.Issuer, l.phone.id.Subject
	phoneExpires := l.phone.id.Expires
	h.mu.Unlock()
	var until time.Time
	var entitlementErr error
	switch {
	case h.selfHosted:
		// Self-hosted nodes do not consult an external membership service; grant
		// a bounded sliding window renewed via ice.refresh while the link stays live.
		until = time.Now().Add(selfTurnWindow)
	case h.entitlement != nil:
		ctx, cancel := context.WithTimeout(p.ctx, 3*time.Second)
		until, entitlementErr = h.entitlement.Check(ctx, issuer, subject)
		cancel()
	default:
		until = phoneExpires
	}
	h.mu.Lock()
	var revoke string
	defer func() {
		l.configuring, l.accepting = false, false
		if h.revokingICE[l.id] {
			revoke = l.id
		}
		h.mu.Unlock()
		h.revokeICE(revoke)
	}()
	if h.links[m.Connection] != l || !l.host.allows(l.phone) || !l.host.live(time.Now()) || !l.phone.live(time.Now()) {
		return errors.New("connection_expired")
	}
	if entitlementErr != nil {
		until = time.Time{}
		if !accepting {
			until = l.grantUntil
		}
	}
	if !h.selfHosted {
		until = minTime(until, l.phone.id.Expires, l.host.id.Expires, l.phone.lease, l.host.lease)
	}
	if !until.After(time.Now()) {
		until = time.Time{}
	}
	visitor := l.phone.id.RemoteUserID()
	if h.selfHosted {
		visitor = l.phone.id.DeviceID
	}
	servers := []ice.ICEServer{}
	if h.ice != nil {
		h.mu.Unlock()
		if until.IsZero() {
			h.ice.Revoke(l.id)
		}
		var err error
		servers, err = h.ice.Config(l.id, visitor, until)
		h.mu.Lock()
		if h.links[m.Connection] != l {
			return errors.New("connection_expired")
		}
		if !l.host.allows(l.phone) || !l.host.live(time.Now()) || !l.phone.live(time.Now()) ||
			!h.selfHosted && until.After(minTime(l.phone.id.Expires, l.host.id.Expires, l.phone.lease, l.host.lease)) {
			h.drop(l, "connection_expired")
			return errors.New("connection_expired")
		}
		if err != nil {
			h.drop(l, "ice_unavailable")
			return errors.New("ice_unavailable")
		}
	}
	if accepting {
		hostAccepted := 0
		for _, existing := range l.host.hostLinks {
			if existing.accepted {
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
	l.grantUntil = until
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
