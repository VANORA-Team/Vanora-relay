package dialretry

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestDialRetriesAddressInUseUntilSuccess(t *testing.T) {
	calls := 0
	err := Dial(context.Background(), func() error {
		calls++
		if calls < 3 {
			return Transient("dial", 10048)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after transient failures, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

func TestDialReturnsLastErrorAfterMaxAttempts(t *testing.T) {
	calls := 0
	sentinel := Transient("connectex", 10048)
	err := Dial(context.Background(), func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected final transient error, got %v", err)
	}
	if calls != maxAttempts {
		t.Fatalf("expected %d attempts, got %d", maxAttempts, calls)
	}
}

func TestDialBacksOffBetweenAttempts(t *testing.T) {
	start := time.Now()
	err := Dial(context.Background(), func() error {
		return Transient("dial", 10049)
	})
	if err == nil {
		t.Fatal("expected failure")
	}
	want := time.Duration(0)
	for i := 0; i+1 < maxAttempts; i++ {
		delay := baseDelay << i
		if delay > maxDelay {
			delay = maxDelay
		}
		want += delay
	}
	if elapsed := time.Since(start); elapsed < want {
		t.Fatalf("expected at least %v of backoff, got %v", want, elapsed)
	}
}

func TestDialReturnsPermanentErrorsImmediately(t *testing.T) {
	calls := 0
	refused := Transient("connectex", 10061) // WSAECONNREFUSED: real signal
	pinFailed := errors.New("LAN: desktop public key differs from pairing link")
	var got error
	err := Dial(context.Background(), func() error {
		calls++
		if calls == 1 {
			return refused
		}
		got = pinFailed
		return pinFailed
	})
	if !errors.Is(err, refused) || errors.Is(err, pinFailed) {
		t.Fatalf("expected refused error to pass through, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected no retry on permanent errors, got %d calls", calls)
	}
	if got != nil {
		t.Fatal("fn must not be called again after a permanent error")
	}
}

func TestAddressInUseRecognizesWindowsWinsockErrnos(t *testing.T) {
	// Suppress unused warnings on non-windows builds where syscall values differ.
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{Transient("connectex", 10048), true},
		{Transient("connectex", 10049), true},
		{Transient("connect", syscall.EADDRINUSE), true},
		{Transient("connect", syscall.EADDRNOTAVAIL), true},
		{Transient("connectex", 10061), false},
		{errors.New("no errno inside"), false},
		{nil, false},
	} {
		if got := AddressInUse(tc.err); got != tc.want {
			t.Fatalf("AddressInUse(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
