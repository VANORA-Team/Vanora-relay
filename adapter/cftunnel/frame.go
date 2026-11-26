package cftunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"vanora-relay/adapter/transport"
)

const (
	frameProof   byte = 0x01
	frameData    byte = 0x02
	frameControl byte = 0x03
	maxChunk          = 16 << 10
	chunkHeader       = 16
	maxChunks         = transport.MaxFrameSize / maxChunk
	frameTimeout      = 30 * time.Second
)

var (
	chunkMagic = []byte{0x00, 'V', 'N', 'F'}
	errFrame   = errors.New("cftunnel: invalid inner frame")
	errBudget  = errors.New("cftunnel: frame assembly budget exhausted")
)

func recordLimit(kind byte) uint32 {
	switch kind {
	case frameProof, frameControl:
		return maxChunk
	case frameData:
		return chunkHeader + maxChunk
	}
	return 0
}

func readRecord(reader io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	size, limit := binary.BigEndian.Uint32(header[1:]), recordLimit(header[0])
	if limit == 0 || size > limit {
		return 0, nil, errFrame
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(reader, payload)
	return header[0], payload, err
}

func writeRecord(writer io.Writer, kind byte, payload []byte) error {
	if limit := recordLimit(kind); limit == 0 || len(payload) > int(limit) {
		return errFrame
	}
	wire := make([]byte, 5, 5+len(payload))
	wire[0] = kind
	binary.BigEndian.PutUint32(wire[1:], uint32(len(payload)))
	wire = append(wire, payload...)
	written, err := writer.Write(wire)
	if err == nil && written != len(wire) {
		return io.ErrShortWrite
	}
	return err
}

func isChunk(payload []byte) bool {
	return len(payload) >= chunkHeader && bytes.HasPrefix(payload, chunkMagic)
}

type assembly struct {
	budget          *AssemblyBudget
	buffer          []byte
	id, next, total uint32
	deadline        time.Time
}

func (a *assembly) reset() {
	a.budget.release(cap(a.buffer))
	*a = assembly{budget: a.budget}
}

func (a *assembly) accept(payload []byte, now time.Time) ([]byte, error) {
	if !isChunk(payload) {
		if a.total != 0 || len(payload) > maxChunk {
			return nil, errFrame
		}
		return payload, nil
	}
	id := binary.BigEndian.Uint32(payload[4:8])
	index := binary.BigEndian.Uint32(payload[8:12])
	total := binary.BigEndian.Uint32(payload[12:16])
	data := payload[chunkHeader:]
	if total == 0 || total > maxChunks || index >= total || len(data) == 0 || len(data) > maxChunk {
		return nil, errFrame
	}
	if a.total == 0 {
		a.id, a.total, a.deadline = id, total, now.Add(frameTimeout)
	}
	if a.id != id || a.total != total || a.next != index || !now.Before(a.deadline) {
		return nil, errFrame
	}
	size := len(a.buffer) + len(data)
	if size > transport.MaxFrameSize {
		return nil, transport.ErrFrameTooLarge
	}
	if size > cap(a.buffer) {
		capacity := min(max(size, 2*cap(a.buffer)), int(total)*maxChunk)
		if !a.budget.acquire(capacity) {
			capacity = size
			if !a.budget.acquire(capacity) {
				return nil, errBudget
			}
		}
		old := a.buffer
		a.buffer = append(make([]byte, 0, capacity), old...)
		a.budget.release(cap(old))
	}
	a.buffer = append(a.buffer, data...)
	a.next++
	if a.next != a.total {
		return nil, nil
	}
	full := a.buffer
	a.reset()
	return full, nil
}
