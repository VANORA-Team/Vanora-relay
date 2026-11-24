package selfrelay

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/pion/webrtc/v4"
	"vanora-relay/adapter/transport"
)

const (
	maxChunkSize       = 16 << 10
	frameHeader        = 16
	maxChunksPerFrame  = transport.MaxFrameSize / maxChunkSize
	sendBufferHigh     = 1 << 20
	frameSendLimit     = 30 * time.Second
	chunkPollPeriod    = 2 * time.Millisecond
	frameAssemblyLimit = 30 * time.Second
)

var frameMagic = [4]byte{0x00, 'V', 'N', 'F'}

func isFrameChunk(data []byte) bool {
	return len(data) >= frameHeader &&
		data[0] == frameMagic[0] && data[1] == frameMagic[1] &&
		data[2] == frameMagic[2] && data[3] == frameMagic[3]
}

func (l *peerLink) sendApp(dc *webrtc.DataChannel, data []byte) error {
	if len(data) > transport.MaxFrameSize {
		return transport.ErrFrameTooLarge
	}
	deadline := time.Now().Add(frameSendLimit)
	if len(data) <= maxChunkSize {
		return l.writeChunk(dc, data, deadline)
	}
	l.sendID++
	total := uint32((len(data) + maxChunkSize - 1) / maxChunkSize)
	for index := uint32(0); index < total; index++ {
		if l.closed.Load() {
			return transport.ErrPeerClosed
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

func (l *peerLink) writeChunk(dc *webrtc.DataChannel, chunk []byte, deadline time.Time) error {
	for dc.BufferedAmount() > sendBufferHigh {
		if !time.Now().Before(deadline) {
			return transport.ErrBackpressure
		}
		select {
		case <-l.done:
			return transport.ErrPeerClosed
		case <-time.After(chunkPollPeriod):
		}
	}
	if !time.Now().Before(deadline) {
		return transport.ErrBackpressure
	}
	sent := make(chan error, 1)
	go func() { sent <- dc.Send(chunk) }()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case err := <-sent:
		return err
	case <-l.done:
		return transport.ErrPeerClosed
	case <-timer.C:
		return transport.ErrBackpressure
	}
}

func (l *peerLink) onWireData(data []byte) {
	if !isFrameChunk(data) {
		if len(data) > transport.MaxFrameSize {
			l.close(transport.ErrFrameTooLarge, false)
			return
		}
		l.recvMu.Lock()
		assembling := l.recvTotal != 0
		l.recvMu.Unlock()
		if assembling {
			l.close(errors.New("selfrelay: raw frame interrupted chunked frame"), false)
			return
		}
		l.onData(data)
		return
	}
	if err := l.acceptChunk(data); err != nil {
		l.close(err, false)
	}
}

func (l *peerLink) acceptChunk(data []byte) error {
	id := binary.BigEndian.Uint32(data[4:8])
	index := binary.BigEndian.Uint32(data[8:12])
	total := binary.BigEndian.Uint32(data[12:16])
	payload := data[frameHeader:]
	if total == 0 || total > maxChunksPerFrame || index >= total ||
		len(payload) == 0 || len(payload) > maxChunkSize {
		return errors.New("selfrelay: invalid application frame chunk")
	}
	now := time.Now()
	l.recvMu.Lock()
	if l.recvTotal == 0 {
		if index != 0 {
			l.recvMu.Unlock()
			return errors.New("selfrelay: application frame does not start at chunk zero")
		}
		l.recvID = id
		l.recvTotal = total
		l.recvNext = 0
		l.recvBuf = l.recvBuf[:0]
	} else if id != l.recvID || index != l.recvNext || now.Sub(l.recvAt) > frameAssemblyLimit {
		l.resetFrameLocked()
		l.recvMu.Unlock()
		return errors.New("selfrelay: application frame chunks out of sequence")
	}
	if len(l.recvBuf)+len(payload) > transport.MaxFrameSize {
		l.resetFrameLocked()
		l.recvMu.Unlock()
		return transport.ErrFrameTooLarge
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

func (l *peerLink) resetFrameLocked() {
	l.recvID = 0
	l.recvNext = 0
	l.recvTotal = 0
	l.recvBuf = l.recvBuf[:0]
	l.recvAt = time.Time{}
}
