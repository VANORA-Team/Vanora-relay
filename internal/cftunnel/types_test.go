package cftunnel

import (
	"errors"
	"fmt"
	"testing"
)

func TestParseOrigin(t *testing.T) {
	for input, expected := range map[string]Origin{
		"localhost:1":     "127.0.0.1:1",
		"127.0.0.1:65535": "127.0.0.1:65535",
		"[::1]:443":       "[::1]:443",
		"localhost:00443": "127.0.0.1:443",
	} {
		if got, err := ParseOrigin(input); err != nil || got != expected {
			t.Errorf("ParseOrigin(%q) = %q, %v; want %q", input, got, err, expected)
		}
	}
	for _, input := range []string{
		"", "localhost", "localhost:0", "localhost:-1", "localhost:+1", "localhost:65536",
		" localhost:2", "localhost:2\n", "localhost:2\x00", "localhost:2/", "localhost:2?", "localhost:2#",
		"user@localhost:2", "http://localhost:2", "127.0.0.2:2", "127.1:2", "0177.0.0.1:2",
		"2130706433:2", "[127.0.0.1]:2", "[0:0:0:0:0:0:0:1]:2", "[::ffff:127.0.0.1]:2", "[::1%lo]:2",
		"::1:2", "0.0.0.0:2", "[::]:2", "locaLhost:2",
	} {
		if got, err := ParseOrigin(input); !errors.Is(err, ErrInvalidOrigin) {
			t.Errorf("ParseOrigin(%q) = %q, %v; want invalid_origin", input, got, err)
		}
	}
}

func TestCodeOf(t *testing.T) {
	for _, err := range []error{ErrInvalidOrigin, ErrGenerationConflict, ErrOperationInProgress, ErrIdempotencyConflict,
		ErrReplayDetected, ErrOwnerQuotaExhausted, ErrAccountCapacity, ErrTunnelSuspended, ErrRecoveryRequired, ErrNotFound, ErrScopeMismatch, ErrFenceLost} {
		if got := CodeOf(fmt.Errorf("wrapped: %w", err)); string(got) != err.Error() {
			t.Fatalf("CodeOf(%v) = %q", err, got)
		}
	}
	if CodeOf(nil) != "" || CodeOf(errors.New("unknown")) != CodeInternal {
		t.Fatal("unexpected default code")
	}
}
