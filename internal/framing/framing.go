// Package framing implements ordered chunking, event-driven DataChannel
// backpressure, and memory-budgeted reassembly for WebRTC application frames.
package framing

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

const (
	// MaxFrameSize caps one complete application frame in both directions.
	MaxFrameSize = 64 << 20

	// MaxChunkSize keeps each SCTP message well below the usual 256 KiB limit.
	MaxChunkSize = 16 << 10
	HeaderSize   = 16

	// MaxChunksPerFrame bounds the chunk total field and therefore receiver memory.
	MaxChunksPerFrame = MaxFrameSize / MaxChunkSize

	SendBufferHigh        = 1 << 20
	SendBufferLow         = 512 << 10
	FrameSendLimit        = 30 * time.Second
	FrameAssemblyLimit    = 30 * time.Second
	MaxRetainedBufCap     = 256 << 10
	DefaultAssemblyBudget = 96 << 20
	fallbackPollPeriod    = 25 * time.Millisecond
)

var (
	// Magic starts every chunk envelope. It cannot start a JSON frame.
	Magic = [4]byte{0x00, 'V', 'N', 'F'}

	ErrFrameTooLarge  = errors.New("framing: application frame exceeds maximum size")
	ErrBackpressure   = errors.New("framing: application frame send stalled")
	ErrClosed         = errors.New("framing: peer closed")
	ErrInvalidChunk   = errors.New("framing: invalid application frame chunk")
	ErrOutOfSequence  = errors.New("framing: application frame chunks out of sequence")
	ErrInterrupted    = errors.New("framing: raw frame interrupted chunked frame")
	ErrBudgetExceeded = errors.New("framing: reassembly memory budget exhausted")
)

// IsChunk reports whether data begins with a VNF chunk header.
func IsChunk(data []byte) bool {
	return len(data) >= HeaderSize &&
		data[0] == Magic[0] && data[1] == Magic[1] &&
		data[2] == Magic[2] && data[3] == Magic[3]
}

// Budget caps aggregate in-flight reassembly bytes across concurrent peers.
type Budget struct {
	limit int64
	used  atomic.Int64
}

func NewBudget(limit int64) *Budget {
	if limit <= 0 {
		limit = DefaultAssemblyBudget
	}
	return &Budget{limit: limit}
}

func (b *Budget) Reserve(delta int64) bool {
	if b == nil || delta <= 0 {
		return true
	}
	for {
		cur := b.used.Load()
		next := cur + delta
		if next > b.limit {
			return false
		}
		if b.used.CompareAndSwap(cur, next) {
			return true
		}
	}
}

func (b *Budget) Release(delta int64) {
	if b == nil || delta <= 0 {
		return
	}
	for {
		cur := b.used.Load()
		next := cur - delta
		if next < 0 {
			next = 0
		}
		if b.used.CompareAndSwap(cur, next) {
			return
		}
	}
}

func (b *Budget) Used() int64 {
	if b == nil {
		return 0
	}
	return b.used.Load()
}

// Assembler reassembles ordered VNF chunks for one link.
type Assembler struct {
	mu       sync.Mutex
	budget   *Budget
	id       uint32
	next     uint32
	total    uint32
	buf      []byte
	at       time.Time
	reserved int64
}

func NewAssembler(budget *Budget) *Assembler {
	return &Assembler{budget: budget}
}

// Accept feeds one DataChannel message into the reassembler. When a complete
// application frame is ready, it returns (frame, true, nil).
func (a *Assembler) Accept(data []byte, now time.Time) ([]byte, bool, error) {
	if !IsChunk(data) {
		if len(data) > MaxFrameSize {
			return nil, false, ErrFrameTooLarge
		}
		a.mu.Lock()
		assembling := a.total != 0
		if assembling {
			a.resetLocked()
		}
		a.mu.Unlock()
		if assembling {
			return nil, false, ErrInterrupted
		}
		return data, true, nil
	}

	id := binary.BigEndian.Uint32(data[4:8])
	index := binary.BigEndian.Uint32(data[8:12])
	total := binary.BigEndian.Uint32(data[12:16])
	payload := data[HeaderSize:]
	if total == 0 || total > MaxChunksPerFrame || index >= total ||
		len(payload) == 0 || len(payload) > MaxChunkSize {
		a.Close()
		return nil, false, ErrInvalidChunk
	}

	a.mu.Lock()
	if a.total == 0 {
		if index != 0 {
			a.mu.Unlock()
			return nil, false, ErrOutOfSequence
		}
		a.id = id
		a.total = total
		a.next = 0
		a.buf = a.buf[:0]
	} else if id != a.id || total != a.total || index != a.next || now.Sub(a.at) > FrameAssemblyLimit {
		a.resetLocked()
		a.mu.Unlock()
		return nil, false, ErrOutOfSequence
	}
	if len(a.buf)+len(payload) > MaxFrameSize {
		a.resetLocked()
		a.mu.Unlock()
		return nil, false, ErrFrameTooLarge
	}
	delta := int64(len(payload))
	if !a.budget.Reserve(delta) {
		a.resetLocked()
		a.mu.Unlock()
		return nil, false, ErrBudgetExceeded
	}
	a.reserved += delta
	a.buf = append(a.buf, payload...)
	a.next++
	a.at = now

	if a.next != a.total {
		a.mu.Unlock()
		return nil, false, nil
	}
	var frame []byte
	if cap(a.buf) > MaxRetainedBufCap {
		// Hand over oversized backing slice directly so large snapshots do not
		// double-allocate and stay pinned on an idle link.
		frame = a.buf
		a.buf = nil
	} else {
		frame = append([]byte(nil), a.buf...)
	}
	a.resetLocked()
	a.mu.Unlock()
	return frame, true, nil
}

// Close discards any partial frame and releases reserved budget bytes.
func (a *Assembler) Close() {
	a.mu.Lock()
	a.resetLocked()
	a.buf = nil
	a.mu.Unlock()
}

func (a *Assembler) resetLocked() {
	if a.reserved > 0 {
		a.budget.Release(a.reserved)
		a.reserved = 0
	}
	a.id = 0
	a.next = 0
	a.total = 0
	a.at = time.Time{}
	if cap(a.buf) > MaxRetainedBufCap {
		a.buf = nil
	} else {
		a.buf = a.buf[:0]
	}
}

type sendJob struct {
	dc    *webrtc.DataChannel
	chunk []byte
	reply chan error
}

// Sender chunks outbound frames onto a Pion DataChannel with event-driven
// backpressure notifications and a persistent send worker to avoid per-chunk
// goroutines and timer leaks. Callers serialize SendApp/WriteChunk calls.
type Sender struct {
	sendID   uint32
	chunkBuf []byte

	lowOnce sync.Once
	lowCh   chan struct{}

	workerOnce sync.Once
	jobs       chan sendJob
}

func (s *Sender) ensureLowCh() chan struct{} {
	s.lowOnce.Do(func() {
		s.lowCh = make(chan struct{}, 1)
	})
	return s.lowCh
}

// Attach configures Pion's buffered-amount low callback for event-driven
// backpressure wakeup.
func (s *Sender) Attach(dc *webrtc.DataChannel) {
	if dc == nil {
		return
	}
	lowCh := s.ensureLowCh()
	dc.SetBufferedAmountLowThreshold(SendBufferLow)
	dc.OnBufferedAmountLow(func() {
		select {
		case lowCh <- struct{}{}:
		default:
		}
	})
}

func (s *Sender) startWorker(done <-chan struct{}) {
	s.workerOnce.Do(func() {
		s.jobs = make(chan sendJob)
		go func() {
			for {
				select {
				case <-done:
					return
				case job := <-s.jobs:
					job.reply <- job.dc.Send(job.chunk)
				}
			}
		}()
	})
}

// SendApp writes one complete application frame. The caller must serialize
// calls per Sender.
func (s *Sender) SendApp(dc *webrtc.DataChannel, data []byte, done <-chan struct{}, closed func() bool) error {
	if len(data) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	deadline := time.Now().Add(FrameSendLimit)
	if len(data) <= MaxChunkSize && !IsChunk(data) {
		return s.WriteChunk(dc, data, deadline, done)
	}
	s.sendID++
	total := uint32((len(data) + MaxChunkSize - 1) / MaxChunkSize)
	if cap(s.chunkBuf) < HeaderSize+MaxChunkSize {
		s.chunkBuf = make([]byte, HeaderSize+MaxChunkSize)
	}
	for index := uint32(0); index < total; index++ {
		if closed != nil && closed() {
			return ErrClosed
		}
		start := int(index) * MaxChunkSize
		end := min(start+MaxChunkSize, len(data))
		chunk := s.chunkBuf[:HeaderSize+end-start]
		copy(chunk[:4], Magic[:])
		binary.BigEndian.PutUint32(chunk[4:8], s.sendID)
		binary.BigEndian.PutUint32(chunk[8:12], index)
		binary.BigEndian.PutUint32(chunk[12:16], total)
		copy(chunk[HeaderSize:], data[start:end])
		if err := s.WriteChunk(dc, chunk, deadline, done); err != nil {
			// Drop shared chunk buffer on abort so any still-unwinding dc.Send
			// cannot race with a subsequent write.
			s.chunkBuf = nil
			return err
		}
	}
	return nil
}

// WriteChunk writes one DataChannel message bounded by deadline and done.
func (s *Sender) WriteChunk(dc *webrtc.DataChannel, chunk []byte, deadline time.Time, done <-chan struct{}) error {
	lowCh := s.ensureLowCh()
	var poll *time.Timer
	for dc.BufferedAmount() > SendBufferHigh {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if poll != nil {
				poll.Stop()
			}
			return ErrBackpressure
		}
		wait := min(remaining, fallbackPollPeriod)
		if poll == nil {
			poll = time.NewTimer(wait)
		} else {
			if !poll.Stop() {
				select {
				case <-poll.C:
				default:
				}
			}
			poll.Reset(wait)
		}
		select {
		case <-done:
			poll.Stop()
			return ErrClosed
		case <-lowCh:
		case <-poll.C:
		}
	}
	if poll != nil {
		poll.Stop()
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return ErrBackpressure
	}

	s.startWorker(done)
	reply := make(chan error, 1)
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case s.jobs <- sendJob{dc: dc, chunk: chunk, reply: reply}:
	case <-done:
		return ErrClosed
	case <-timer.C:
		return ErrBackpressure
	}
	select {
	case err := <-reply:
		return err
	case <-done:
		return ErrClosed
	case <-timer.C:
		return ErrBackpressure
	}
}
