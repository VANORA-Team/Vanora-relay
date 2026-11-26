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
	"vanora-relay/protocol"
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
	err = json.Unmarshal(data, &m)
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
	if h.authorized(r) {
		return true
	}
	ip := remoteIPAddr(r.RemoteAddr)
	now := time.Now()
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
		w.Header().Set("Cache-Control", "no-store")
		if h.requireToken && !h.authorizedReq(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Query().Has("activity") {
		h.serveActivity(w, r)
		return
	}
	if r.Method == http.MethodPost || (r.Method == http.MethodGet && r.URL.Query().Has("pairing")) {
		h.servePairing(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.requireToken && !h.authorizedReq(w, r) {
		return
	}
	clientIP := remoteIPAddr(r.RemoteAddr)
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
		id, err = identity.VerifyCertificate(m.Certificate, h.key, time.Now())
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
		until, err = identity.VerifyEndpointLease(auth.Lease, h.key, time.Now(), m.Certificate, id)
		if err != nil {
			ws.Close(websocket.StatusPolicyViolation, "invalid lease")
			return
		}
		cert = m.Certificate
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		ws.Close(websocket.StatusTryAgainLater, "busy")
		return
	}
	releasePreAuth()
	p := &peer{
		id:         id,
		cert:       cert,
		role:       auth.Role,
		desktop:    auth.Desktop,
		selfHosted: h.selfHosted,
		remoteIP:   clientIP,
		lease:      until,
		ctx:        ctx,
		cancel:     cancel,
		out:        make(chan protocol.Message, 32),
		probeWake:  make(chan struct{}, 1),
	}
	h.mu.Lock()
	existing := h.peers[p.slotKey()]
	exists := existing != nil
	if p.desktop != "" {
		host := h.peers[p.desktop]
		exists = exists || (p.role != "mobile" && p.role != "desktop") || host == nil || !host.allows(p)
	}
	count := 0
	for _, other := range h.peers {
		if other.id.DeviceID == id.DeviceID {
			count++
			exists = exists || other.role != p.role
		}
	}
	exists = exists || count >= maxPhoneLinks+1
	if !exists {
		h.peers[p.slotKey()] = p
	} else if existing != nil && existing.role == p.role && existing.id.PublicKey.Equal(id.PublicKey) {
		// Preserve "first connection wins" so a racing connection cannot kick a
		// healthy peer, while immediately probing the incumbent socket so a
		// half-open blackholed connection is evicted within ~1.2s instead of
		// waiting out the full 15s+5s heartbeat cycle (VR-SEC-08).
		now := time.Now()
		if now.Sub(existing.lastProbe) >= 500*time.Millisecond {
			existing.lastProbe = now
			select {
			case existing.probeWake <- struct{}{}:
			default:
			}
		}
	}
	h.mu.Unlock()
	if exists {
		ws.Close(websocket.StatusPolicyViolation, "endpoint already connected")
		return
	}
	defer h.remove(p)
	stop()
	var okData any
	if h.selfHosted {
		okData = struct {
			Device string `json:"device_id"`
			Mode   string `json:"mode"`
		}{id.DeviceID, "self"}
	} else {
		okData = struct {
			Device string `json:"device_id"`
			User   string `json:"remote_user_id"`
		}{id.DeviceID, id.RemoteUserID()}
	}
	if writeMessage(ctx, ws, protocol.Message{Type: "auth.ok", Data: protocol.Encode(okData)}) != nil {
		return
	}
	go func() {
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
	}()
	go func() {
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
	}()
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
		if err = h.handle(p, m); err != nil {
			p.send(protocol.Message{Type: "error", Connection: m.Connection, Data: protocol.Encode(err.Error())})
		}
	}
}

func (p *peer) registered() {
	if p.pairTicket == "" {
		p.pairTicket = protocol.NewID()
	}
	p.send(protocol.Message{Type: "device.registered", Data: protocol.Encode(map[string]string{"pairing_ticket": p.pairTicket})})
}

func (h *Hub) servePairing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip := remoteIPAddr(r.RemoteAddr)
	now := time.Now()
	if !h.gate.allowRequest(ip, now) {
		limitResponse(w, 0)
		return
	}
	if r.Method == http.MethodGet {
		locator := r.URL.Query().Get("pairing")
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
