package selfrelay

import (
	"errors"
	"time"

	"github.com/pion/webrtc/v4"

	"vanora-relay/adapter/transport"
	"vanora-relay/internal/framing"
)

const (
	maxChunkSize       = framing.MaxChunkSize
	frameHeader        = framing.HeaderSize
	maxChunksPerFrame  = framing.MaxChunksPerFrame
	sendBufferHigh     = framing.SendBufferHigh
	frameSendLimit     = framing.FrameSendLimit
	frameAssemblyLimit = framing.FrameAssemblyLimit
)

var (
	frameMagic = framing.Magic

	selfrelayAssemblyBudget = framing.NewBudget(framing.DefaultAssemblyBudget)
)

func mapFramingErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, framing.ErrFrameTooLarge):
		return transport.ErrFrameTooLarge
	case errors.Is(err, framing.ErrBackpressure):
		return transport.ErrBackpressure
	case errors.Is(err, framing.ErrClosed):
		return transport.ErrPeerClosed
	default:
		return err
	}
}

func (l *peerLink) sendApp(dc *webrtc.DataChannel, data []byte) error {
	return mapFramingErr(l.sender.SendApp(dc, data, l.done, l.closed.Load))
}

func (l *peerLink) onWireData(data []byte) {
	frame, ready, err := l.assembler.Accept(data, time.Now())
	if err != nil {
		l.close(mapFramingErr(err), false)
		return
	}
	if ready {
		l.onData(frame)
	}
}
