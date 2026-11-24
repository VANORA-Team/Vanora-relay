package lan

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"
	"vanora-relay/adapter/transport"
	"vanora-relay/protocol"
)

type peer struct {
	socket  *websocket.Conn
	ctx     context.Context
	cancel  context.CancelFunc
	id      string
	allowed func() bool
}

func newPeer(ctx context.Context, socket *websocket.Conn, id string, allowed func() bool) *peer {
	ctx, cancel := context.WithCancel(ctx)
	return &peer{socket: socket, ctx: ctx, cancel: cancel, id: id, allowed: allowed}
}

func (p *peer) UserID() string { return p.id }
func (p *peer) Path() string   { return "lan" }

func (p *peer) Allows(bool) bool {
	return p.ctx.Err() == nil && p.allowed()
}

func (p *peer) Send(data []byte, online bool) error {
	if len(data) > transport.MaxFrameSize {
		return transport.ErrFrameTooLarge
	}
	if !p.Allows(online) {
		return errors.New("LAN: access unavailable")
	}
	ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
	defer cancel()
	return p.socket.Write(ctx, websocket.MessageBinary, data)
}

func (p *peer) Close() {
	p.cancel()
	_ = p.socket.CloseNow()
}

func (p *peer) SendRemoval(removal transport.Removal) error {
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
	defer cancel()
	return p.socket.Write(ctx, websocket.MessageBinary, protocol.Encode(removal))
}

func (p *peer) run(handler transport.Handler, readLimit int64) {
	defer handler.Closed(p)
	defer p.Close()
	p.socket.SetReadLimit(readLimit)
	handler.Open(p)
	go p.heartbeat()
	for p.Allows(false) {
		kind, data, err := p.socket.Read(p.ctx)
		if err != nil || kind != websocket.MessageBinary || !p.Allows(false) {
			return
		}
		handler.Message(p, data)
	}
}

func (p *peer) heartbeat() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
			err := p.socket.Ping(ctx)
			cancel()
			if err != nil {
				p.Close()
				return
			}
		}
	}
}
