// Package dialretry retries outbound dials that fail because the operating
// system could not hand the connection an ephemeral source port.
//
// The dynamic port range (Windows: 49152-65535) is shared between listeners
// bound with port 0 and source ports picked for outbound connects, so a
// listener bound moments earlier can collide with the next connectex with
// WSAEADDRINUSE ("Only one usage of each socket address"). The same class
// appears on Unix as EADDRINUSE/EADDRNOTAVAIL when the range is nearly
// exhausted. These failures are transient: retrying lets the kernel pick a
// different source port. Every other dial error is returned untouched so
// real failures (dead peer, refused port, TLS pin mismatch) keep their
// original meaning.
package dialretry

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	maxAttempts = 5
	baseDelay   = 25 * time.Millisecond
	maxDelay    = 200 * time.Millisecond
)

// AddressInUse reports whether err is the transient "no source port
// available for the connect" class. On Windows the winsock values
// WSAEADDRINUSE (10048) and WSAEADDRNOTAVAIL (10049) arrive raw from the
// syscall layer; Go's syscall.EADDRINUSE constant is a separate synthesized
// errno and does not match them.
func AddressInUse(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.EADDRINUSE, syscall.EADDRNOTAVAIL, 10048, 10049:
		return true
	}
	return false
}

// Dial runs fn up to maxAttempts times while it fails with the
// address-reuse class described above, backing off between attempts. It
// returns the first success, the final error, or the pending error when ctx
// is done. fn must be safe to call again after a failed call; each attempt
// is expected to open a fresh connection.
func Dial(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; ; attempt++ {
		err = fn()
		if err == nil || !AddressInUse(err) || attempt+1 >= maxAttempts {
			return err
		}
		delay := baseDelay << attempt
		if delay > maxDelay {
			delay = maxDelay
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
	}
}

// Transient is a helper for tests: it fabricates the dial error class the
// way the runtime reports it (net.OpError wrapping os.SyscallError wrapping
// the raw errno) so callers do not depend on platform errno values.
func Transient(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Err: &os.SyscallError{Syscall: op, Err: errno}}
}
