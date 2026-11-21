package transport

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/pion/webrtc/v4"
)

// Application frames are carried in one or more ordered DataChannel messages.
// SCTP has a small per-message limit, while desktop snapshots can be many
// megabytes, so transport splits large frames and reassembles them before the
// handler sees them. Every message stays far below the SCTP message limit.
const (
	// MaxFrameSize caps one complete application frame in both directions.
	// Larger frames are rejected with ErrFrameTooLarge; the caller must page
	// its payload instead of relying on transport to fragment without bound.
	MaxFrameSize = 64 << 20

	// maxChunkSize keeps each SCTP message well below the usual 256 KiB limit.
	maxChunkSize = 16 << 10
	frameHeader  = 16
	// maxChunksPerFrame bounds the total field and therefore receiver memory.
	maxChunksPerFrame = MaxFrameSize / maxChunkSize

	sendBufferHigh  = 1 << 20
	frameSendLimit  = 30 * time.Second
	chunkPollPeriod = 2 * time.Millisecond

	// frameAssemblyLimit bounds how long a partially received frame may occupy
	// memory while the peer stalls.
	frameAssemblyLimit = 30 * time.Second
)

var (
	// ErrFrameTooLarge reports a complete frame above MaxFrameSize. It is a
	// caller error: the link remains usable.
	ErrFrameTooLarge = errors.New("transport: application frame exceeds maximum size")

	// ErrBackpressure reports that the peer did not drain its send buffer
	// within frameSendLimit. The link is closed after a timeout.
	ErrBackpressure = errors.New("transport: application frame send stalled")
)

// frameMagic starts every chunk. It cannot start a JSON application frame, so
// raw frames and chunked frames are unambiguous on the wire.
var frameMagic = [4]byte{0x00, 'V', 'N', 'F'}

func isFrameChunk(data []byte) bool {
	return len(data) >= frameHeader &&
		data[0] == frameMagic[0] && data[1] == frameMagic[1] &&
		data[2] == frameMagic[2] && data[3] == frameMagic[3]
}

// sendApp writes one complete application frame. The caller holds sendMu.
func (l *link) sendApp(dc *webrtc.DataChannel, data []byte) error {
	if len(data) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	deadline := time.Now().Add(frameSendLimit)
	if len(data) <= maxChunkSize {
		return l.writeChunk(dc, data, deadline)
	}

	l.sendID++
	total := uint32((len(data) + maxChunkSize - 1) / maxChunkSize)
	for index := uint32(0); index < total; index++ {
		if l.closed.Load() {
			return ErrPeerClosed
		}
		start := int(index) * maxChunkSize
		end := min(start+maxChunkSize, len(data))
		chunk := make([]byte, frameHeader+end-start)
		copy(chunk[:4], frameMagic[:])
		binary.BigEndian.PutUint32(chunk[4:8], l.sendID)
		binary.BigEndian.PutUint32(chunk[8:12], index)
		binary.BigEndian.PutUint32(chunk[12:16], total)
		copy(chunk[frameHeader:], data[start:end])
		if err := l.writeChunk(dc, chunk, deadline); err != nil {
			return err
		}
	}
	return nil
}

// writeChunk sends one DataChannel message with a hard deadline. Pion has no
// context-aware send, so the send runs in a goroutine while the link's done
// channel and a timer guard the caller. A timed-out link is closed by the
// caller, which unblocks the pending SCTP write.
func (l *link) writeChunk(dc *webrtc.DataChannel, chunk []byte, deadline time.Time) error {
	for dc.BufferedAmount() > sendBufferHigh {
		if !time.Now().Before(deadline) {
			return ErrBackpressure
		}
		select {
		case <-l.done:
			return ErrPeerClosed
		case <-time.After(chunkPollPeriod):
		}
	}
	if !time.Now().Before(deadline) {
		return ErrBackpressure
	}

	sent := make(chan error, 1)
	go func() { sent <- dc.Send(chunk) }()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case err := <-sent:
		return err
	case <-l.done:
		return ErrPeerClosed
	case <-timer.C:
		return ErrBackpressure
	}
}

// onWireData distinguishes chunk envelopes from complete frames. Only the
// DataChannel callback calls it, so chunk assembly for one link is serial.
func (l *link) onWireData(data []byte) {
	if !isFrameChunk(data) {
		if len(data) > MaxFrameSize {
			l.close(ErrFrameTooLarge, false)
			return
		}
		l.recvMu.Lock()
		assembling := l.recvTotal != 0
		l.recvMu.Unlock()
		if assembling {
			l.close(errors.New("transport: raw frame interrupted chunked frame"), false)
			return
		}
		l.onData(data)
		return
	}
	if err := l.acceptChunk(data); err != nil {
		l.close(err, false)
	}
}

func (l *link) acceptChunk(data []byte) error {
	id := binary.BigEndian.Uint32(data[4:8])
	index := binary.BigEndian.Uint32(data[8:12])
	total := binary.BigEndian.Uint32(data[12:16])
	payload := data[frameHeader:]
	if total == 0 || total > maxChunksPerFrame || index >= total ||
		len(payload) == 0 || len(payload) > maxChunkSize {
		return errors.New("transport: invalid application frame chunk")
	}

	now := time.Now()
	l.recvMu.Lock()
	if l.recvTotal == 0 {
		if index != 0 {
			l.recvMu.Unlock()
			return errors.New("transport: application frame does not start at chunk zero")
		}
		l.recvID = id
		l.recvTotal = total
		l.recvNext = 0
		l.recvBuf = l.recvBuf[:0]
	} else if id != l.recvID || index != l.recvNext ||
		now.Sub(l.recvAt) > frameAssemblyLimit {
		l.resetFrameLocked()
		l.recvMu.Unlock()
		return errors.New("transport: application frame chunks out of sequence")
	}
	if len(l.recvBuf)+len(payload) > MaxFrameSize {
		l.resetFrameLocked()
		l.recvMu.Unlock()
		return ErrFrameTooLarge
	}
	l.recvBuf = append(l.recvBuf, payload...)
	l.recvNext++
	l.recvAt = now

	if l.recvNext != l.recvTotal {
		l.recvMu.Unlock()
		return nil
	}
	frame := append([]byte(nil), l.recvBuf...)
	l.resetFrameLocked()
	l.recvMu.Unlock()
	l.onData(frame)
	return nil
}

func (l *link) resetFrameLocked() {
	l.recvID = 0
	l.recvNext = 0
	l.recvTotal = 0
	l.recvBuf = l.recvBuf[:0]
	l.recvAt = time.Time{}
}
