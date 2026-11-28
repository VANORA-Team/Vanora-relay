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
	frameProof     byte = 0x01
	frameData      byte = 0x02
	frameControl   byte = 0x03
	frameDataPart  byte = 0x04
	frameDataFinal byte = 0x05

	recordHeaderSize = 5
	tlsMaxPlaintext  = 16 << 10
	// maxStreamPayload keeps every inner TLS 1.3 record (5-byte header + payload)
	// within the 16,384-byte RFC 8446 record limit so each write emits exactly
	// one TLS record and one WebSocket binary frame.
	maxStreamPayload = tlsMaxPlaintext - recordHeaderSize

	// Legacy VNF chunk limits retained for backward-compatible reading.
	maxChunk     = 16 << 10
	chunkHeader  = 16
	maxChunks    = transport.MaxFrameSize / maxChunk
	frameTimeout = 30 * time.Second
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
	case frameDataPart, frameDataFinal:
		return maxStreamPayload
	}
	return 0
}

func readRecord(reader io.Reader) (byte, []byte, error) {
	var header [recordHeaderSize]byte
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
	var scratch []byte
	return writeRecordScratch(writer, &scratch, kind, payload)
}

func writeRecordScratch(writer io.Writer, scratch *[]byte, kind byte, payload []byte) error {
	if limit := recordLimit(kind); limit == 0 || len(payload) > int(limit) {
		return errFrame
	}
	need := recordHeaderSize + len(payload)
	if cap(*scratch) < need {
		*scratch = make([]byte, need)
	}
	wire := (*scratch)[:need]
	wire[0] = kind
	binary.BigEndian.PutUint32(wire[1:recordHeaderSize], uint32(len(payload)))
	copy(wire[recordHeaderSize:], payload)
	written, err := writer.Write(wire)
	if err == nil && written != len(wire) {
		return io.ErrShortWrite
	}
	return err
}

func isChunk(payload []byte) bool {
	return len(payload) >= chunkHeader && bytes.HasPrefix(payload, chunkMagic)
}

// assembly reassembles either native TLS-aligned streaming frames
// (frameDataPart/frameDataFinal) or legacy VNF chunked frames using a rope of
// chunk slices, charging exact incremental bytes against AssemblyBudget with
// O(N) total copy cost and zero 1.5x peak spikes.
type assembly struct {
	budget          *AssemblyBudget
	chunks          [][]byte
	totalBytes      int
	reserved        int
	streaming       bool
	id, next, total uint32
	deadline        time.Time
}

func (a *assembly) active() bool {
	return a.streaming || a.total != 0
}

func (a *assembly) reset() {
	if a.reserved > 0 {
		a.budget.release(a.reserved)
	}
	*a = assembly{budget: a.budget}
}

func (a *assembly) pushChunk(data []byte) error {
	size := a.totalBytes + len(data)
	if size > transport.MaxFrameSize {
		return transport.ErrFrameTooLarge
	}
	if !a.budget.acquire(len(data)) {
		return errBudget
	}
	a.reserved += len(data)
	a.chunks = append(a.chunks, data)
	a.totalBytes = size
	return nil
}

func (a *assembly) finalize() []byte {
	if len(a.chunks) == 1 {
		full := a.chunks[0]
		a.reset()
		return full
	}
	full := make([]byte, a.totalBytes)
	offset := 0
	for _, chunk := range a.chunks {
		offset += copy(full[offset:], chunk)
	}
	a.reset()
	return full
}

func (a *assembly) acceptStream(payload []byte, final bool, now time.Time) ([]byte, error) {
	if a.total != 0 {
		return nil, errFrame
	}
	if len(payload) == 0 || len(payload) > maxStreamPayload {
		return nil, errFrame
	}
	if !a.streaming {
		if final {
			return payload, nil
		}
		a.streaming = true
		a.deadline = now.Add(frameTimeout)
	} else if !now.Before(a.deadline) {
		return nil, errFrame
	}
	if err := a.pushChunk(payload); err != nil {
		return nil, err
	}
	if !final {
		return nil, nil
	}
	return a.finalize(), nil
}

func (a *assembly) accept(payload []byte, now time.Time) ([]byte, error) {
	if a.streaming {
		return nil, errFrame
	}
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
	if err := a.pushChunk(data); err != nil {
		return nil, err
	}
	a.next++
	if a.next != a.total {
		return nil, nil
	}
	return a.finalize(), nil
}
