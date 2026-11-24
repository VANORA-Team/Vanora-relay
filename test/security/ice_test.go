package security_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"vanora-relay/internal/ice"
	"vanora-relay/test/security/internal/sectest"
)

func TestICEPerVisitorGrantCap(t *testing.T) {
	t.Setenv("STUN_URLS", "local")
	t.Setenv("TURN_PUBLIC_IP", "127.0.0.1")
	t.Setenv("TURN_BIND_IP", "127.0.0.1")
	t.Setenv("TURN_PORT", "0")
	t.Setenv("TURN_TCP", "false")
	t.Setenv("TURN_RELAY_MIN_PORT", "0")
	t.Setenv("TURN_RELAY_MAX_PORT", "0")
	t.Setenv("TURN_MAX_GRANTS", "4")

	srv, err := ice.FromEnv()
	mustOK(t, err)
	defer srv.Close()

	until := time.Now().Add(time.Minute)
	attackerGrants := 0
	for i := 0; i < 4; i++ {
		_, err := srv.Config(fmt.Sprintf("conn-attacker-%d", i), "usr_attacker", until)
		if err == nil {
			attackerGrants++
			continue
		}
		if errors.Is(err, ice.ErrVisitorGrantLimit) || errors.Is(err, ice.ErrTooManyGrants) {
			break
		}
		t.Fatalf("unexpected attacker grant %d error: %v", i, err)
	}
	if attackerGrants >= 4 {
		// All 4 global grants went to a single visitor; victim check below will report VR-SEC-06.
		t.Logf("single visitor acquired all %d global grants", attackerGrants)
	}

	// A separate victim visitor should not be starved by one visitor taking all global grants.
	if _, err := srv.Config("conn-victim-0", "usr_victim", until); errors.Is(err, ice.ErrTooManyGrants) {
		sectest.Finding(t, "VR-SEC-06", "single visitor exhausted global TURN_MAX_GRANTS (no per-visitor grant cap; ice.go:158,187-192)")
	} else if err != nil {
		t.Fatalf("unexpected victim Config error: %v", err)
	}
}
