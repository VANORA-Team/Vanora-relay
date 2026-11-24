package signal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/internal/identity"
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

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	if h.requireToken && !h.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vanora-relay"`)
		http.Error(w, "invalid relay token", http.StatusUnauthorized)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "busy", 503)
		return
	}
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
	p := &peer{id: id, cert: cert, role: auth.Role, selfHosted: h.selfHosted, lease: until, ctx: ctx, cancel: cancel, out: make(chan protocol.Message, 32)}
	h.mu.Lock()
	_, exists := h.peers[id.DeviceID]
	if !exists {
		h.peers[id.DeviceID] = p
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pingCtx, done := context.WithTimeout(ctx, 5*time.Second)
				err := ws.Ping(pingCtx)
				done()
				if err != nil {
					cancel()
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
