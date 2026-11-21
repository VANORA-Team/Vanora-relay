// Package signal routes authenticated, endpoint-signed WebRTC negotiation.
package signal

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"vanora-relay/endpoint"
	"vanora-relay/internal/ice"
	"vanora-relay/internal/identity"
	"vanora-relay/protocol"
)

type membership interface {
	Check(context.Context, string, string) (time.Time, error)
}
type iceService interface {
	Config(connectionID, visitor string, until time.Time) ([]ice.ICEServer, error)
	Revoke(connectionID string)
}

type Hub struct {
	key     ed25519.PublicKey
	billing membership
	ice     iceService
	slots   chan struct{}
	mu      sync.Mutex
	peers   map[string]*peer
	links   map[string]*link
}

type peer struct {
	id         identity.Principal
	cert, role string
	card       protocol.Message
	lease      time.Time
	online     bool
	grants     map[string]bool
	out        chan protocol.Message
	ctx        context.Context
	cancel     context.CancelFunc
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

func New(key ed25519.PublicKey, billing membership, network iceService) *Hub {
	return &Hub{key: key, billing: billing, ice: network, slots: make(chan struct{}, 1024), peers: make(map[string]*peer), links: make(map[string]*link)}
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
	return host.online && host.role == "desktop" && (host.id.RemoteUserID() == visitor.id.RemoteUserID() || host.grants[visitor.id.RemoteUserID()])
}

func (p *peer) live(now time.Time) bool {
	return p.ctx.Err() == nil && now.Before(p.lease) && now.Before(p.id.Expires)
}

func (h *Hub) drop(l *link, reason string) {
	delete(h.links, l.id)
	h.ice.Revoke(l.id)
	msg := protocol.Message{Type: "connect.closed", Connection: l.id, Data: protocol.Encode(reason)}
	l.host.send(msg)
	l.phone.send(msg)
}

func (h *Hub) remove(p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[p.id.DeviceID] != p {
		return
	}
	delete(h.peers, p.id.DeviceID)
	for _, l := range h.links {
		if l.host == p || l.phone == p {
			h.drop(l, "endpoint_offline")
		}
	}
}

func (h *Hub) expire(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
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
}

func (h *Hub) Run(ctx context.Context) {
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
		if p.role != "desktop" || json.Unmarshal(m.Data, &d) != nil || d.Card.Certificate != p.cert || len(d.Guests) > 256 {
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
		for _, l := range h.links {
			if l.host == p && !p.allows(l.phone) {
				h.drop(l, "access_revoked")
			}
		}
		p.send(protocol.Message{Type: "device.registered"})
		return nil
	case "devices.list":
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
		if p.role != "mobile" || host == nil || !host.live(time.Now()) || !host.allows(p) {
			return errors.New("device_unavailable")
		}
		if _, exists := h.links[m.Connection]; exists || m.Round != 0 {
			return errors.New("invalid_connection")
		}
		phoneCount, hostCount := 0, 0
		for _, l := range h.links {
			if l.phone == p {
				phoneCount++
			}
			if l.host == host {
				hostCount++
			}
		}
		if phoneCount >= 8 || hostCount >= 32 {
			return errors.New("connection_limit")
		}
		h.links[m.Connection] = &link{id: m.Connection, phone: p, host: host, phoneSeq: m.Seq, created: time.Now()}
		m.Certificate = p.cert
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
		h.drop(l, "peer_closed")
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
	h.mu.Unlock()
	ctx, cancel := context.WithTimeout(p.ctx, 3*time.Second)
	defer cancel()
	until, err := h.billing.Check(ctx, issuer, subject)
	if err != nil {
		until = time.Time{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.links[m.Connection] != l || !l.host.allows(l.phone) || !l.host.live(time.Now()) || !l.phone.live(time.Now()) {
		return errors.New("connection_expired")
	}
	if until.After(l.phone.id.Expires) {
		until = l.phone.id.Expires
	}
	if until.After(l.host.id.Expires) {
		until = l.host.id.Expires
	}
	if !until.After(time.Now()) {
		h.ice.Revoke(l.id)
		until = time.Time{}
	}
	servers, err := h.ice.Config(l.id, l.phone.id.RemoteUserID(), until)
	if err != nil {
		h.drop(l, "ice_unavailable")
		return errors.New("ice_unavailable")
	}
	if accepting {
		l.accepted, l.hostSeq = true, m.Seq
		m.Certificate = p.cert
		l.phone.send(m)
	}
	cfg := protocol.Message{Type: "ice.config", Connection: l.id, Data: protocol.Encode(servers)}
	l.phone.send(cfg)
	l.host.send(cfg)
	return nil
}
