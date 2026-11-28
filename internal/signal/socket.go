package signal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/internal/identity"
	"vanora-relay/internal/pairing"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

const (
	maxConcurrentRPC    = 8
	tunnelHostQueueSize = 8
	duplicateWait       = 1300 * time.Millisecond
	freshPeerWindow     = 250 * time.Millisecond
)

func readMessage(ctx context.Context, ws *websocket.Conn) (protocol.Message, error) {
	var m protocol.Message
	kind, data, err := ws.Read(ctx)
	if err != nil {
		return m, err
	}
	if kind != websocket.MessageText {
		return m, errors.New("text record required")
	}
	err = strictjson.Decode(data, &m)
	return m, err
}
func writeMessage(ctx context.Context, ws *websocket.Conn, m protocol.Message) error {
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return ws.Write(deadline, websocket.MessageText, protocol.Encode(m))
}

type loginBody struct {
	Desktop   string `json:"desktop,omitempty"`
	Role      string `json:"role"`
	Lease     string `json:"lease,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Tunnel    bool   `json:"tunnel,omitempty"`
}

// authorized accepts "Authorization: Bearer <token>" with the configured
// self-hosted token. Hashing both sides keeps the comparison constant time
// regardless of the presented length.
func (h *Hub) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	presented := sha256.Sum256([]byte(header[len(prefix):]))
	return subtle.ConstantTimeCompare(h.accessToken[:], presented[:]) == 1
}

// authorizedReq performs the bearer check and, on failure, charges the
// per-IP gate. Repeated failures lock the source IP out with 429s before
// the token is hashed again, which throttles token guessing.
func (h *Hub) authorizedReq(w http.ResponseWriter, r *http.Request) bool {
	ip := h.clientIP(r)
	now := time.Now()
	if h.gate.tokenLocked(ip, now) {
		limitResponse(w, h.gate.lockRemaining(ip, now))
		return false
	}
	if h.authorized(r) {
		return true
	}
	if h.gate.recordTokenFailure(ip, now) {
		limitResponse(w, h.gate.lockRemaining(ip, now))
		return false
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="vanora-relay"`)
	http.Error(w, "invalid relay token", http.StatusUnauthorized)
	return false
}

func remoteIPAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

func (h *Hub) acquirePreAuth(ip string) (func(), int) {
	h.preAuthMu.Lock()
	if ip != "" && h.preAuthByIP[ip] >= maxPreAuthPerIP {
		h.preAuthMu.Unlock()
		return nil, http.StatusTooManyRequests
	}
	select {
	case h.preAuthSlots <- struct{}{}:
	default:
		h.preAuthMu.Unlock()
		return nil, http.StatusServiceUnavailable
	}
	if ip != "" {
		h.preAuthByIP[ip]++
	}
	h.preAuthMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			if ip != "" {
				h.preAuthMu.Lock()
				if n := h.preAuthByIP[ip] - 1; n <= 0 {
					delete(h.preAuthByIP, ip)
				} else {
					h.preAuthByIP[ip] = n
				}
				h.preAuthMu.Unlock()
			}
			<-h.preAuthSlots
		})
	}, 0
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Query().Get("probe") == "1" {
		h.ServeProbe(w, r)
		return
	}
	if r.URL.Query().Has("activity") {
		h.ServeActivity(w, r)
		return
	}
	if r.Method == http.MethodPost || (r.Method == http.MethodGet && r.URL.Query().Has("pairing")) {
		h.ServePairing(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.requireToken && !h.authorizedReq(w, r) {
		return
	}
	h.mu.Lock()
	draining := h.draining
	h.mu.Unlock()
	if draining {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}
	clientIP := h.clientIP(r)
	releasePreAuth, status := h.acquirePreAuth(clientIP)
	if status != 0 {
		http.Error(w, "busy", status)
		return
	}
	defer releasePreAuth()
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(192 << 10)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	deadline, stop := context.WithTimeout(ctx, 8*time.Second)
	defer stop()
	nonce := protocol.NewID()
	if writeMessage(deadline, ws, protocol.Message{Type: "auth.challenge", Connection: nonce}) != nil {
		return
	}
	m, err := readMessage(deadline, ws)
	if err != nil {
		return
	}
	var (
		id    identity.Principal
		auth  loginBody
		until time.Time
		cert  string
	)
	if h.selfHosted {
		if m.Certificate != "" {
			ws.Close(websocket.StatusPolicyViolation, "certificate not allowed")
			return
		}
		rawBody, err := base64.RawURLEncoding.Strict().DecodeString(m.Body)
		if err != nil || json.Unmarshal(rawBody, &auth) != nil || auth.Lease != "" || (auth.Role != "mobile" && auth.Role != "desktop") {
			ws.Close(websocket.StatusPolicyViolation, "invalid proof")
			return
		}
		pub, err := base64.RawURLEncoding.Strict().DecodeString(auth.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			ws.Close(websocket.StatusPolicyViolation, "invalid public key")
			return
		}
		devID, err := identity.SelfDeviceID(ed25519.PublicKey(pub))
		if err != nil || m.Type != "auth.login" || m.Connection != nonce || m.From != devID || m.To != "signal" || m.Seq != 0 || m.Round != 0 {
			ws.Close(websocket.StatusPolicyViolation, "invalid proof")
			return
		}
		if _, err := m.Verify(ed25519.PublicKey(pub)); err != nil {
			ws.Close(websocket.StatusPolicyViolation, "invalid proof")
			return
		}
		id = identity.Principal{
			Issuer:    "self",
			Subject:   devID,
			DeviceID:  devID,
			PublicKey: ed25519.PublicKey(pub),
		}
	} else {
		id, err = identity.VerifyCertificateWithKeys(m.Certificate, h.trustedKeys(), time.Now())
		if err != nil {
			ws.Close(websocket.StatusPolicyViolation, "invalid certificate")
			return
		}
		if h.allowedIssuer != "" && id.Issuer != h.allowedIssuer {
			ws.Close(websocket.StatusPolicyViolation, "issuer not allowed")
			return
		}
		signed, err := m.Verify(id.PublicKey)
		if err != nil || m.Type != "auth.login" || m.Connection != nonce || m.From != id.DeviceID || m.To != "signal" || m.Seq != 0 || m.Round != 0 || json.Unmarshal(signed, &auth) != nil || (auth.Role != "mobile" && auth.Role != "desktop") {
			ws.Close(websocket.StatusPolicyViolation, "invalid proof")
			return
		}
		until, err = identity.VerifyEndpointLeaseWithKeys(auth.Lease, h.trustedKeys(), time.Now(), m.Certificate, id)
		if err != nil {
			ws.Close(websocket.StatusPolicyViolation, "invalid lease")
			return
		}
		cert = m.Certificate
	}
	if auth.Tunnel && auth.Desktop == "" {
		ws.Close(websocket.StatusPolicyViolation, "tunnel target required")
		return
	}
	p := &peer{
		id:                 id,
		cert:               cert,
		role:               auth.Role,
		desktop:            auth.Desktop,
		tunnelOnly:         auth.Tunnel,
		selfHosted:         h.selfHosted,
		remoteIP:           clientIP,
		tunnelIP:           clientIP,
		legacyTunnelAcks:   r.Header.Get("X-Vanora-Tunnel-Ack-Seq") != "1",
		legacyTunnelErrors: r.Header.Get("X-Vanora-Tunnel-Availability") != "1",
		lease:              until,
		ctx:                ctx,
		cancel:             cancel,
		out:                make(chan protocol.Message, 32),
		probeWake:          make(chan struct{}, 1),
		done:               make(chan struct{}),
		ws:                 ws,
	}
	tunnel, closeStatus, reason := h.registerPeer(p, true)
	if closeStatus != 0 {
		ws.Close(closeStatus, reason)
		return
	}
	var handlers sync.WaitGroup
	defer func() {
		cancel()
		h.remove(p)
		handlers.Wait()
		h.connections.Done()
	}()
	releasePreAuth()
	stop()
	var tunnelScope string
	if tunnel != nil {
		tunnelScope = tunnel.ScopeID()
	}
	var okData any
	if h.selfHosted {
		okData = struct {
			Device      string `json:"device_id"`
			Mode        string `json:"mode"`
			TunnelScope string `json:"tunnel_scope,omitempty"`
		}{id.DeviceID, "self", tunnelScope}
	} else {
		okData = struct {
			Device      string `json:"device_id"`
			User        string `json:"remote_user_id"`
			TunnelScope string `json:"tunnel_scope,omitempty"`
		}{id.DeviceID, id.RemoteUserID(), tunnelScope}
	}
	if writeMessage(ctx, ws, protocol.Message{Type: "auth.ok", Data: protocol.Encode(okData)}) != nil {
		return
	}
	handlers.Go(func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-p.out:
				if writeMessage(ctx, ws, event) != nil {
					return
				}
			}
		}
	})
	handlers.Go(func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		ping := func(timeout time.Duration) bool {
			pingCtx, done := context.WithTimeout(ctx, timeout)
			err := ws.Ping(pingCtx)
			done()
			if err != nil {
				cancel()
				return false
			}
			return true
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.probeWake:
				if !ping(1200 * time.Millisecond) {
					return
				}
			case <-ticker.C:
				if !ping(5 * time.Second) {
					return
				}
			}
		}
	})
	rpcSlots := make(chan struct{}, maxConcurrentRPC)
	hostQueue := make(chan protocol.Message, tunnelHostQueueSize)
	dispatch := func(m protocol.Message) {
		if err := h.handle(p, m); err != nil {
			p.signalError(m, err.Error())
		}
	}
	handlers.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-hostQueue:
				if ctx.Err() != nil {
					return
				}
				dispatch(event)
			}
		}
	})
	// Burst allowance covers ICE trickling without allowing an unbounded verification loop.
	budget := 120
	window := time.Now()
	for {
		m, err = readMessage(ctx, ws)
		if err != nil {
			return
		}
		if time.Since(window) >= time.Second {
			budget = 120
			window = time.Now()
		}
		budget--
		if budget < 0 {
			cancel()
			return
		}
		switch m.Type {
		case "connect.accept", "ice.refresh", "tunnel.connect", "tunnel.permit", "tunnel.refresh":
			select {
			case rpcSlots <- struct{}{}:
				event := m
				handlers.Go(func() {
					defer func() { <-rpcSlots }()
					dispatch(event)
				})
			default:
				p.signalError(m, "busy")
			}
		case "tunnel.host":
			select {
			case hostQueue <- m:
			default:
				p.signalError(m, "busy")
			}
		default:
			dispatch(m)
		}
	}
}

func (h *Hub) registerPeer(p *peer, wait bool) (TunnelController, websocket.StatusCode, string) {
	h.mu.Lock()
	now := time.Now()
	if h.draining {
		h.mu.Unlock()
		return nil, websocket.StatusGoingAway, "relay shutting down"
	}
	if !p.live(now) {
		h.mu.Unlock()
		return nil, websocket.StatusPolicyViolation, "authorization_expired"
	}
	key := p.slotKey()
	if existing := h.peers[key]; existing != nil {
		sameKey := existing.role == p.role && existing.id.PublicKey.Equal(p.id.PublicKey)
		if sameKey && now.Sub(existing.lastProbe) >= 500*time.Millisecond {
			existing.lastProbe = now
			select {
			case existing.probeWake <- struct{}{}:
			default:
			}
		}
		canWait := sameKey && wait && now.Sub(existing.connectedAt) >= freshPeerWindow
		h.mu.Unlock()
		if canWait {
			timer := time.NewTimer(duplicateWait)
			defer timer.Stop()
			select {
			case <-existing.done:
				return h.registerPeer(p, false)
			case <-timer.C:
			case <-p.ctx.Done():
			}
		}
		return nil, websocket.StatusPolicyViolation, "endpoint already connected"
	}
	defer h.mu.Unlock()
	if p.desktop != "" {
		host := h.peers[p.desktop]
		if host == nil || !host.live(now) || !host.allows(p) {
			return nil, websocket.StatusPolicyViolation, "device_unavailable"
		}
	}
	slots := h.peersByDevice[p.id.DeviceID]
	if slots.role != "" && slots.role != p.role {
		return nil, websocket.StatusPolicyViolation, "device_unavailable"
	}
	if len(h.peers) >= h.maxSlots {
		return nil, websocket.StatusTryAgainLater, "slot_limit"
	}
	if p.tunnelOnly {
		if slots.tunnels >= maxPhoneLinks {
			return nil, websocket.StatusPolicyViolation, "slot_limit"
		}
		slots.tunnels++
	} else {
		if slots.normal >= maxPhoneLinks+1 {
			return nil, websocket.StatusPolicyViolation, "slot_limit"
		}
		slots.normal++
	}
	slots.role = p.role
	p.connectedAt = now
	h.peersByDevice[p.id.DeviceID], h.peers[key] = slots, p
	h.connections.Add(1)
	return h.tunnel, 0, ""
}

func (p *peer) signalError(m protocol.Message, reason string) {
	p.send(protocol.Message{Type: "error", Connection: m.Connection, Data: protocol.Encode(reason)})
}

func (h *Hub) ServeProbe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.requireToken && !h.authorizedReq(w, r) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *peer) registered() {
	if p.pairTicket == "" {
		p.pairTicket = protocol.NewID()
	}
	p.send(protocol.Message{Type: "device.registered", Data: protocol.Encode(map[string]string{"pairing_ticket": p.pairTicket})})
}

func (h *Hub) ServePairing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := h.clientIP(r)
	now := time.Now()
	if !h.gate.allowRequest(ip, now) {
		limitResponse(w, 0)
		return
	}
	if r.Method == http.MethodGet {
		locator := r.URL.Query().Get("pairing")
		if r.URL.Path == "/v1/pairing" && locator == "" {
			locator = r.URL.Query().Get("locator")
		}
		if !validPairingLocator(locator) {
			http.NotFound(w, r)
			return
		}
		h.mu.Lock()
		host := h.invites[locator]
		var box string
		if host != nil && host.live(now) {
			if invite := host.invites[locator]; now.Before(invite.Expires) {
				box = invite.Box
			}
		}
		h.mu.Unlock()
		if box == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(box))
		return
	}
	device := r.Header.Get("Vanora-Desktop")
	ticket, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	h.mu.Lock()
	host := h.peers[device]
	authorized := hasBearer && host != nil && host.online && host.role == "desktop" && host.pairTicket != "" &&
		subtle.ConstantTimeCompare([]byte(ticket), []byte(host.pairTicket)) == 1 && host.live(time.Now())
	h.mu.Unlock()
	if !authorized {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var record pairing.Record
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&record) != nil || len(record.Locator) != 43 || len(record.Box) > 12<<10 {
		http.Error(w, "invalid invitation", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[device] != host || host == nil || !host.live(now) {
		http.Error(w, "offline", http.StatusConflict)
		return
	}
	if record.Box == "" {
		if h.invites[record.Locator] == host {
			delete(h.invites, record.Locator)
			delete(host.invites, record.Locator)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !record.Expires.After(now) || record.Expires.After(now.Add(pairing.Lifetime+30*time.Second)) {
		http.Error(w, "invalid expiry", http.StatusBadRequest)
		return
	}
	if _, exists := h.invites[record.Locator]; exists || len(host.invites) >= 32 {
		http.Error(w, "invitation limit", http.StatusConflict)
		return
	}
	if h.invites == nil {
		h.invites = make(map[string]*peer)
	}
	if host.invites == nil {
		host.invites = make(map[string]pairing.Record)
	}
	h.invites[record.Locator] = host
	host.invites[record.Locator] = record
	w.WriteHeader(http.StatusNoContent)
}

// validPairingLocator filters obviously malformed locators (43-char base64url
// encoding of 32 bytes) before the hub lock is taken so garbage floods never
// contend with signaling.
func validPairingLocator(locator string) bool {
	if len(locator) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(locator)
	return err == nil && len(raw) == 32
}
