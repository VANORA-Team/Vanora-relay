package transport

import (
	"errors"
	"time"

	"github.com/pion/webrtc/v4"

	"vanora-relay/internal/framing"
)

// Application frames are carried in one or more ordered DataChannel messages.
// SCTP has a small per-message limit, while desktop snapshots can be many
// megabytes, so transport splits large frames and reassembles them before the
// handler sees them. Every message stays far below the SCTP message limit.
const (
	// MaxFrameSize caps one complete application frame in both directions.
	// Larger frames are rejected with ErrFrameTooLarge; the caller must page
	// its payload instead of relying on transport to fragment without bound.
	MaxFrameSize = framing.MaxFrameSize

	maxChunkSize       = framing.MaxChunkSize
	frameHeader        = framing.HeaderSize
	maxChunksPerFrame  = framing.MaxChunksPerFrame
	sendBufferHigh     = framing.SendBufferHigh
	frameSendLimit     = framing.FrameSendLimit
	frameAssemblyLimit = framing.FrameAssemblyLimit
)

var (
	// ErrFrameTooLarge reports a complete frame above MaxFrameSize. It is a
	// caller error: the link remains usable.
	ErrFrameTooLarge = errors.New("transport: application frame exceeds maximum size")

	// ErrBackpressure reports that the peer did not drain its send buffer
	// within frameSendLimit. The link is closed after a timeout.
	ErrBackpressure = errors.New("transport: application frame send stalled")

	frameMagic = framing.Magic

	transportAssemblyBudget = framing.NewBudget(framing.DefaultAssemblyBudget)
)

func mapFramingErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, framing.ErrFrameTooLarge):
		return ErrFrameTooLarge
	case errors.Is(err, framing.ErrBackpressure):
		return ErrBackpressure
	case errors.Is(err, framing.ErrClosed):
		return ErrPeerClosed
	default:
		return err
	}
}

// sendApp writes one complete application frame. The caller holds sendMu.
func (l *link) sendApp(dc *webrtc.DataChannel, data []byte) error {
	return mapFramingErr(l.sender.SendApp(dc, data, l.done, l.closed.Load))
}

func (l *link) writeChunk(dc *webrtc.DataChannel, chunk []byte, deadline time.Time) error {
	return mapFramingErr(l.sender.WriteChunk(dc, chunk, deadline, l.done))
}

// onWireData distinguishes chunk envelopes from complete frames. Only the
// DataChannel callback calls it, so chunk assembly for one link is serial.
func (l *link) onWireData(data []byte) {
	frame, ready, err := l.assembler.Accept(data, time.Now())
	if err != nil {
		l.close(mapFramingErr(err), false)
		return
	}
	if ready {
		l.onData(frame)
	}
}
