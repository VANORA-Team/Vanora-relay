package cftunnel

import (
	"testing"
	"time"

	"vanora-relay/internal/membership"
)

func TestOfficialPolicy(t *testing.T) {
	now := time.Unix(1700000000, 0)
	future, past := now.Add(time.Hour), now.Add(-time.Hour)
	for _, test := range []struct {
		name    string
		ent     membership.Entitlement
		slots   int
		self    bool
		visitor bool
	}{
		{"ambiguous legacy denial", membership.Entitlement{}, 0, false, false},
		{"free verified owner", membership.Entitlement{TunnelAllowed: new(true)}, 1, true, false},
		{"active legacy paid", membership.Entitlement{RelayAllowed: true, ValidUntil: future}, 3, true, true},
		{"expired legacy TURN", membership.Entitlement{RelayAllowed: true, ValidUntil: now}, 0, false, false},
		{"expired TURN with verified free slot", membership.Entitlement{RelayAllowed: true, ValidUntil: past, TunnelAllowed: new(true)}, 1, true, false},
		{"overridden paid slots", membership.Entitlement{RelayAllowed: true, ValidUntil: future, MaxTunnels: new(7)}, 7, true, true},
		{"higher slots through tunnel grant", membership.Entitlement{MaxTunnels: new(7), TunnelValidUntil: new(future.Unix())}, 7, true, false},
		{"expired tunnel grant", membership.Entitlement{TunnelAllowed: new(true), MaxTunnels: new(7), TunnelValidUntil: new(past.Unix())}, 0, false, false},
		{"exact expiry denies explicit guest", membership.Entitlement{TunnelConnectAllowed: new(true), TunnelValidUntil: new(now.Unix())}, 0, false, false},
		{"active relay survives expired tunnel grant", membership.Entitlement{RelayAllowed: true, ValidUntil: future, TunnelAllowed: new(true), TunnelValidUntil: new(now.Unix())}, 3, true, true},
		{"no extras without expiry", membership.Entitlement{TunnelAllowed: new(true), MaxTunnels: new(7)}, 1, true, false},
		{"no allocations via explicit zero", membership.Entitlement{TunnelAllowed: new(true), MaxTunnels: new(0)}, 0, true, false},
		{"explicit guest grant", membership.Entitlement{TunnelConnectAllowed: new(true)}, 0, true, true},
		{"explicit guest denial", membership.Entitlement{RelayAllowed: true, ValidUntil: future, TunnelConnectAllowed: new(false)}, 3, false, false},
		{"global tunnel denial", membership.Entitlement{RelayAllowed: true, ValidUntil: future, TunnelAllowed: new(false), TunnelConnectAllowed: new(true)}, 0, false, false},
		{"invalid tunnel fields", membership.Entitlement{RelayAllowed: true, ValidUntil: future, TunnelAllowed: new(true), TunnelFieldsInvalid: true}, 0, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := EvaluateOwnerPolicy(test.ent, now, 1, 3, nil)
			if owner.Allowed != (test.slots != 0) || owner.MaxTunnels != test.slots {
				t.Fatalf("owner policy = %+v, want %d slots", owner, test.slots)
			}
			if got := EvaluateVisitorConnect(test.ent, now, true).Allowed; got != test.self {
				t.Fatalf("self-connect = %t, want %t", got, test.self)
			}
			if got := EvaluateVisitorConnect(test.ent, now, false).Allowed; got != test.visitor {
				t.Fatalf("visitor connect = %t, want %t", got, test.visitor)
			}
		})
	}
}

func TestOwnerOverrideAndSelfHostedPolicy(t *testing.T) {
	now := time.Unix(1700000000, 0)
	paid := membership.Entitlement{RelayAllowed: true, ValidUntil: now.Add(time.Hour)}
	override := OwnerOverride{MaxTunnels: 2, ExpiresAt: now.Add(time.Minute)}
	if got := EvaluateOwnerPolicy(paid, now, 1, 3, &override); got.MaxTunnels != 2 {
		t.Fatalf("override policy = %+v", got)
	}
	if got := EvaluateOwnerPolicy(paid, override.ExpiresAt, 1, 3, &override); got.MaxTunnels != 3 {
		t.Fatalf("expired override policy = %+v", got)
	}
	if got := EvaluateOwnerPolicy(membership.Entitlement{}, now, 1, 3, &override); got.Allowed {
		t.Fatalf("override granted an unverified account: %+v", got)
	}
	if got := EvaluateOwnerPolicy(paid, now, 1, 3, &OwnerOverride{MaxTunnels: 10}); got.MaxTunnels != 10 {
		t.Fatalf("override could not raise quota: %+v", got)
	}
	if got := EvaluateOwnerPolicy(paid, now, 1, 3, &OwnerOverride{}); got.Allowed {
		t.Fatalf("zero override did not freeze quota: %+v", got)
	}
	if !EvaluateSelfOwnerPolicy(true, 16, now, &override).Allowed || EvaluateSelfOwnerPolicy(false, 16, now, &override).Allowed ||
		!EvaluateSelfVisitorConnect(true, true).Allowed || EvaluateSelfVisitorConnect(true, false).Allowed ||
		EvaluateSelfVisitorConnect(false, true).Allowed {
		t.Fatal("self policies must require host allowlisting and visitor pairing")
	}
}
