package framing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func makeTestChunk(id, index, total uint32, payload []byte) []byte {
	out := make([]byte, HeaderSize+len(payload))
	copy(out[:4], Magic[:])
	binary.BigEndian.PutUint32(out[4:8], id)
	binary.BigEndian.PutUint32(out[8:12], index)
	binary.BigEndian.PutUint32(out[12:16], total)
	copy(out[HeaderSize:], payload)
	return out
}

func TestAssemblerBudgetTotalMismatchAndBufferRelease(t *testing.T) {
	budget := NewBudget(64 << 10)
	a := NewAssembler(budget)
	now := time.Now()

	// Normal 2-chunk reassembly releases budget when finished.
	part1 := bytes.Repeat([]byte("a"), 1024)
	part2 := bytes.Repeat([]byte("b"), 1024)
	if _, ready, err := a.Accept(makeTestChunk(1, 0, 2, part1), now); err != nil || ready {
		t.Fatalf("part1: ready=%v err=%v", ready, err)
	}
	if budget.Used() != 1024 {
		t.Fatalf("budget used = %d, want 1024", budget.Used())
	}
	got, ready, err := a.Accept(makeTestChunk(1, 1, 2, part2), now)
	if err != nil || !ready || !bytes.Equal(got, append(part1, part2...)) {
		t.Fatalf("part2: ready=%v err=%v len=%d", ready, err, len(got))
	}
	if budget.Used() != 0 {
		t.Fatalf("budget not released after completion: %d", budget.Used())
	}

	// Changing total mid-frame must be rejected and release budget.
	if _, _, err := a.Accept(makeTestChunk(2, 0, 3, part1), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Accept(makeTestChunk(2, 1, 2, part2), now); !errors.Is(err, ErrOutOfSequence) {
		t.Fatalf("total mismatch err = %v, want ErrOutOfSequence", err)
	}
	if budget.Used() != 0 {
		t.Fatalf("budget leaked after mismatch: %d", budget.Used())
	}

	// Exceeding shared budget rejects and releases.
	big := bytes.Repeat([]byte("x"), MaxChunkSize)
	for i := uint32(0); i < 4; i++ {
		if _, _, err := a.Accept(makeTestChunk(3, i, 5, big), now); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	if _, _, err := a.Accept(makeTestChunk(3, 4, 5, big), now); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("budget exhaustion err = %v, want ErrBudgetExceeded", err)
	}
	if budget.Used() != 0 {
		t.Fatalf("budget leaked after exhaustion: %d", budget.Used())
	}

	// Raw frame starting with Magic must be detected by IsChunk so senders chunk it.
	spoof := append(append([]byte(nil), Magic[:]...), bytes.Repeat([]byte{1}, 16)...)
	if !IsChunk(spoof) {
		t.Fatal("IsChunk failed to detect Magic prefix")
	}
}
