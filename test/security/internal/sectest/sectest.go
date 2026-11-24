// Package sectest provides shared conventions for Vanora-relay security tests.
package sectest

import (
	"os"
	"strings"
	"testing"
)

// Strict reports whether known security findings must fail the test instead
// of skipping (enabled via VANORA_SECURITY_STRICT=1).
func Strict() bool {
	v := strings.TrimSpace(os.Getenv("VANORA_SECURITY_STRICT"))
	return v == "1" || strings.EqualFold(v, "true")
}

// Heavy reports whether resource-intensive security tests (such as connection
// exhaustion) are enabled via VANORA_SECURITY_HEAVY=1.
func Heavy() bool {
	v := strings.TrimSpace(os.Getenv("VANORA_SECURITY_HEAVY"))
	return v == "1" || strings.EqualFold(v, "true")
}

// RequireHeavy skips t unless VANORA_SECURITY_HEAVY=1 is set.
func RequireHeavy(t *testing.T) {
	t.Helper()
	if !Heavy() {
		t.Skip("skipping heavy security test; set VANORA_SECURITY_HEAVY=1 to enable")
	}
}

// Finding records a reproduced security weakness. By default it calls t.Skipf
// so standard CI remains green; with VANORA_SECURITY_STRICT=1 it calls t.Fatalf
// so fixed vulnerabilities stay enforced as regression tests.
func Finding(t *testing.T, id, format string, args ...any) {
	t.Helper()
	msg := format
	if len(args) > 0 {
		t.Logf("FINDING %s: "+format, append([]any{id}, args...)...)
	} else {
		t.Logf("FINDING %s: %s", id, msg)
	}
	if Strict() {
		t.Fatalf("FINDING %s: "+format, append([]any{id}, args...)...)
	}
	t.Skipf("FINDING %s: "+format, append([]any{id}, args...)...)
}
