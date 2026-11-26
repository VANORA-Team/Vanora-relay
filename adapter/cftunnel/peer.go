package cftunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	"vanora-relay/adapter/transport"
	"vanora-relay/endpoint"
	"vanora-relay/internal/strictjson"
	"vanora-relay/protocol"
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

	stateMu     sync.Mutex
	access      *endpoint.Access
	accessUntil time.Time
	expiry      *time.Timer

	writeMu sync.Mutex
	writeID uint32
}

func newPeer(ctx context.Context, cancel context.CancelFunc, conn *tls.Conn, user string, allows func() bool, until time.Time, access *endpoint.Access, handler transport.Handler, budget *AssemblyBudget) *Peer {
	peer := &Peer{ctx: ctx, cancel: cancel, conn: conn, userID: user, allows: allows,
		access: access, handler: handler, budget: budget}
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

func (p *Peer) Close() {
	p.cancel()
	p.stateMu.Lock()
	if p.expiry != nil {
		p.expiry.Stop()
	}
	p.stateMu.Unlock()
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
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.ctx.Err() != nil {
		return transport.ErrPeerClosed
	}
	if !p.allows() {
		return transport.ErrUnauthorized
	}
	p.stateMu.Lock()
	var err error
	if p.access == nil || current != nil && !current() {
		err = transport.ErrUnauthorized
	} else {
		err = p.access.Update(true, proof, time.Now())
	}
	p.stateMu.Unlock()
	if err != nil {
		return err
	}
	return p.writeControl(controlRecord{Type: "lease.update", Proof: protocol.Encode(proof)})
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
	if len(data) <= maxChunk && !isChunk(data) {
		return p.write(frameData, data)
	}
	p.writeID++
	total := uint32((len(data) + maxChunk - 1) / maxChunk)
	chunk := make([]byte, chunkHeader, chunkHeader+maxChunk)
	copy(chunk, chunkMagic)
	binary.BigEndian.PutUint32(chunk[4:8], p.writeID)
	binary.BigEndian.PutUint32(chunk[12:16], total)
	for index := uint32(0); index < total; index++ {
		if !allowed() {
			p.Close()
			return transport.ErrUnauthorized
		}
		start := int(index) * maxChunk
		binary.BigEndian.PutUint32(chunk[8:12], index)
		if err := p.write(frameData, append(chunk, data[start:min(start+maxChunk, len(data))]...)); err != nil {
			return err
		}
	}
	return nil
}

func (p *Peer) write(kind byte, data []byte) error {
	if err := writeRecord(p.conn, kind, data); err != nil {
		p.Close()
		return err
	}
	return nil
}

func (p *Peer) run() {
	recv := assembly{budget: p.budget}
	opened := false
	defer func() {
		p.Close()
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
	}
	for p.Allows(false) {
		_ = p.conn.SetReadDeadline(recv.deadline)
		kind, payload, err := readRecord(p.conn)
		if err != nil || !p.Allows(false) {
			return
		}
		switch kind {
		case frameData:
			frame, err := recv.accept(payload, time.Now())
			if err != nil {
				return
			}
			if frame != nil && p.handler != nil && p.Allows(false) {
				p.handler.Message(p, frame)
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
	_ = p.conn.SetWriteDeadline(time.Now().Add(frameTimeout))
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
			p.writeMu.Lock()
			defer p.writeMu.Unlock()
			return p.writeControl(controlRecord{Type: "pong"})
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
