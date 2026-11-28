package cftunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
)

const (
	peerInboxSize        = 256
	controlWriteTimeout  = 5 * time.Second
	keepaliveInterval    = 25 * time.Second
	keepaliveReadTimeout = 90 * time.Second
)

var (
	_ transport.Peer         = (*Peer)(nil)
	_ transport.PathReporter = (*Peer)(nil)
)

type Peer struct {
	ctx      context.Context
	cancel   context.CancelFunc
	conn     *tls.Conn
	userID   string
	deviceID string
	allows   func() bool
	handler  transport.Handler
	budget   *AssemblyBudget

	stateMu      sync.Mutex
	access       *endpoint.Access
	accessUntil  time.Time
	expiry       *time.Timer
	pendingLease *endpoint.LeaseProof
	onClose      func()
	closeOnce    sync.Once

	writeMu      sync.Mutex
	writeScratch []byte
	lastWriteAt  atomic.Int64

	pongWake  chan struct{}
	leaseWake chan struct{}
}

func newPeer(ctx context.Context, cancel context.CancelFunc, conn *tls.Conn, user string, allows func() bool, until time.Time, access *endpoint.Access, handler transport.Handler, budget *AssemblyBudget) *Peer {
	peer := &Peer{
		ctx:          ctx,
		cancel:       cancel,
		conn:         conn,
		userID:       user,
		allows:       allows,
		access:       access,
		handler:      handler,
		budget:       budget,
		writeScratch: make([]byte, 0, tlsMaxPlaintext),
		pongWake:     make(chan struct{}, 1),
		leaseWake:    make(chan struct{}, 1),
	}
	peer.lastWriteAt.Store(time.Now().UnixNano())
	peer.UpdateAccessUntil(until)
	return peer
}

func (p *Peer) UserID() string   { return p.userID }
func (p *Peer) DeviceID() string { return p.deviceID }
func (p *Peer) Path() string     { return "cf_tunnel" }

func (p *Peer) Allows(requiresOnline bool) bool {
	return p.ctx.Err() == nil && p.allows() && p.accessAllows(requiresOnline)
}

func (p *Peer) accessAllows(requiresOnline bool) bool {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	now := time.Now()
	return p.ctx.Err() == nil && now.Before(p.accessUntil) &&
		(p.access == nil || p.access.Allows(now, requiresOnline, true))
}

func (p *Peer) setOnClose(fn func()) {
	p.stateMu.Lock()
	p.onClose = fn
	p.stateMu.Unlock()
}

func (p *Peer) Close() {
	p.cancel()
	p.stateMu.Lock()
	if p.expiry != nil {
		p.expiry.Stop()
	}
	fn := p.onClose
	p.onClose = nil
	p.stateMu.Unlock()
	p.closeOnce.Do(func() {
		if p.conn != nil {
			_ = p.conn.Close()
		}
		if fn != nil {
			fn()
		}
	})
}

func (p *Peer) UpdateAccessUntil(until time.Time) {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.ctx.Err() != nil {
		return
	}
	p.accessUntil = until
	if !time.Now().Before(until) {
		p.cancel()
		if p.expiry != nil {
			p.expiry.Stop()
		}
		return
	}
	if p.expiry != nil {
		p.expiry.Reset(time.Until(until))
		return
	}
	p.expiry = time.AfterFunc(time.Until(until), func() {
		p.stateMu.Lock()
		defer p.stateMu.Unlock()
		if !time.Now().Before(p.accessUntil) {
			p.cancel()
		}
	})
}

func (p *Peer) AuthorityLost() {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.access != nil {
		p.access.AuthorityLost()
	}
}

func (p *Peer) UpdateLocalLease(proof endpoint.LeaseProof) error {
	return p.updateLocalLease(proof, nil)
}

func (p *Peer) updateLocalLease(proof endpoint.LeaseProof, current func() bool) error {
	if err := p.applyLocalLease(proof, current); err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.ctx.Err() != nil {
		return transport.ErrPeerClosed
	}
	return p.writeControl(controlRecord{Type: "lease.update", Proof: protocol.Encode(proof)})
}

// enqueueLocalLease updates local access synchronously and coalesces the
// outbound lease.update frame onto controlLoop so one slow peer cannot stall
// renewals for other peers on the same Listener.
func (p *Peer) enqueueLocalLease(proof endpoint.LeaseProof, current func() bool) error {
	if err := p.applyLocalLease(proof, current); err != nil {
		return err
	}
	cp := proof
	p.stateMu.Lock()
	p.pendingLease = &cp
	p.stateMu.Unlock()
	select {
	case p.leaseWake <- struct{}{}:
	default:
	}
	return nil
}

func (p *Peer) applyLocalLease(proof endpoint.LeaseProof, current func() bool) error {
	if p.ctx.Err() != nil {
		return transport.ErrPeerClosed
	}
	if !p.allows() {
		return transport.ErrUnauthorized
	}
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.access == nil || current != nil && !current() {
		return transport.ErrUnauthorized
	}
	return p.access.Update(true, proof, time.Now())
}

func (p *Peer) Send(data []byte, requiresOnline bool) error {
	return p.send(data, requiresOnline, false)
}

func (p *Peer) SendRemoval(removal transport.Removal) error {
	return p.send(protocol.Encode(removal), false, true)
}

func (p *Peer) send(data []byte, online, removal bool) error {
	if len(data) > transport.MaxFrameSize {
		return transport.ErrFrameTooLarge
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	allowed := func() bool {
		if removal {
			return p.accessAllows(false)
		}
		return p.Allows(online)
	}
	if !allowed() {
		return transport.ErrUnauthorized
	}
	defer p.conn.SetWriteDeadline(time.Time{})
	_ = p.conn.SetWriteDeadline(time.Now().Add(frameTimeout))
	if len(data) <= maxStreamPayload && !isChunk(data) {
		return p.write(frameData, data)
	}
	// Stream in exact TLS 1.3 record-aligned slices (5B header + 16379B = 16384B)
	// so every write emits one TLS record and one WebSocket binary frame.
	for offset, chunkIndex := 0, 0; offset < len(data); chunkIndex++ {
		if chunkIndex > 0 && chunkIndex%16 == 0 && !allowed() {
			p.Close()
			return transport.ErrUnauthorized
		}
		end := min(offset+maxStreamPayload, len(data))
		kind := frameDataPart
		if end == len(data) {
			kind = frameDataFinal
		}
		if err := p.write(kind, data[offset:end]); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (p *Peer) write(kind byte, data []byte) error {
	if err := writeRecordScratch(p.conn, &p.writeScratch, kind, data); err != nil {
		p.Close()
		return err
	}
	p.lastWriteAt.Store(time.Now().UnixNano())
	return nil
}

func (p *Peer) controlLoop(done <-chan struct{}) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	sendControl := func(rec controlRecord) bool {
		p.writeMu.Lock()
		defer p.writeMu.Unlock()
		if p.ctx.Err() != nil {
			return false
		}
		return p.writeControl(rec) == nil
	}
	for {
		select {
		case <-done:
			return
		case <-p.ctx.Done():
			return
		case <-p.leaseWake:
			p.stateMu.Lock()
			proof := p.pendingLease
			p.pendingLease = nil
			p.stateMu.Unlock()
			if proof != nil {
				if !sendControl(controlRecord{Type: "lease.update", Proof: protocol.Encode(*proof)}) {
					return
				}
			}
		case <-p.pongWake:
			if !sendControl(controlRecord{Type: "pong"}) {
				return
			}
		case now := <-ticker.C:
			last := time.Unix(0, p.lastWriteAt.Load())
			if now.Sub(last) >= keepaliveInterval {
				if !sendControl(controlRecord{Type: "ping"}) {
					return
				}
			}
		}
	}
}

func (p *Peer) run() {
	recv := assembly{budget: p.budget}
	opened := false
	controlDone := make(chan struct{})
	var inbox chan []byte
	var deliverDone chan struct{}
	defer func() {
		p.Close()
		close(controlDone)
		if inbox != nil {
			close(inbox)
			<-deliverDone
		}
		recv.reset()
		if opened {
			p.handler.Closed(p)
		}
	}()
	if !p.Allows(false) {
		return
	}
	if p.handler != nil {
		opened = true
		p.handler.Open(p)
		inbox = make(chan []byte, peerInboxSize)
		deliverDone = make(chan struct{})
		go func() {
			defer close(deliverDone)
			for frame := range inbox {
				if !p.Allows(false) {
					return
				}
				p.handler.Message(p, frame)
			}
		}()
	}
	go p.controlLoop(controlDone)

	for p.Allows(false) {
		deadline := time.Now().Add(keepaliveReadTimeout)
		if recv.active() && !recv.deadline.IsZero() && recv.deadline.Before(deadline) {
			deadline = recv.deadline
		}
		_ = p.conn.SetReadDeadline(deadline)
		kind, payload, err := readRecord(p.conn)
		if err != nil || !p.Allows(false) {
			return
		}
		switch kind {
		case frameData, frameDataPart, frameDataFinal:
			var frame []byte
			if kind == frameData {
				frame, err = recv.accept(payload, time.Now())
			} else {
				frame, err = recv.acceptStream(payload, kind == frameDataFinal, time.Now())
			}
			if err != nil {
				return
			}
			if frame != nil && inbox != nil && p.Allows(false) {
				select {
				case inbox <- frame:
				case <-p.ctx.Done():
					return
				default:
					// Slow consumer overflow: close cleanly so upper layer resumes via events.resume.
					return
				}
			}
		case frameControl:
			if err := p.handleControl(payload); err != nil {
				return
			}
		default:
			return
		}
	}
}

type controlRecord struct {
	Type   string          `json:"type"`
	Proof  json.RawMessage `json:"proof,omitempty"`
	Reason json.RawMessage `json:"reason,omitempty"`
}

func (p *Peer) writeControl(record controlRecord) error {
	defer p.conn.SetWriteDeadline(time.Time{})
	_ = p.conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
	return p.write(frameControl, protocol.Encode(record))
}

func (p *Peer) handleControl(payload []byte) error {
	var record controlRecord
	if strictjson.Decode(payload, &record) != nil {
		return errFrame
	}
	switch record.Type {
	case "lease.update":
		var proof endpoint.LeaseProof
		if record.Reason != nil || strictjson.Decode(record.Proof, &proof) != nil {
			return errFrame
		}
		p.stateMu.Lock()
		defer p.stateMu.Unlock()
		if p.access == nil {
			return errFrame
		}
		return p.access.Update(false, proof, time.Now())
	case "ping", "pong":
		if record.Proof != nil || record.Reason != nil {
			return errFrame
		}
		if record.Type == "ping" {
			select {
			case p.pongWake <- struct{}{}:
			default:
			}
		}
		return nil
	case "close":
		var reason *string
		if record.Proof != nil || json.Unmarshal(record.Reason, &reason) != nil || reason == nil {
			return errFrame
		}
		p.Close()
		return nil
	default:
		return errFrame
	}
}
