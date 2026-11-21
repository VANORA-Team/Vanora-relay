package signal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
	Role  string `json:"role"`
	Lease string `json:"lease"`
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
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
	id, err := identity.VerifyCertificate(m.Certificate, h.key, time.Now())
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "invalid certificate")
		return
	}
	signed, err := m.Verify(id.PublicKey)
	var auth loginBody
	if err != nil || m.Type != "auth.login" || m.Connection != nonce || m.From != id.DeviceID || m.To != "signal" || m.Seq != 0 || m.Round != 0 || json.Unmarshal(signed, &auth) != nil || (auth.Role != "mobile" && auth.Role != "desktop") {
		ws.Close(websocket.StatusPolicyViolation, "invalid proof")
		return
	}
	until, err := identity.VerifyEndpointLease(auth.Lease, h.key, time.Now(), m.Certificate, id)
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "invalid lease")
		return
	}
	p := &peer{id: id, cert: m.Certificate, role: auth.Role, lease: until, ctx: ctx, cancel: cancel, out: make(chan protocol.Message, 32)}
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
	if writeMessage(ctx, ws, protocol.Message{Type: "auth.ok", Data: protocol.Encode(struct {
		Device string `json:"device_id"`
		User   string `json:"remote_user_id"`
	}{id.DeviceID, id.RemoteUserID()})}) != nil {
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
