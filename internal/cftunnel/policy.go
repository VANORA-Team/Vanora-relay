package cftunnel

import (
	"time"

	"vanora-relay/internal/membership"
)

// OwnerOverride is a persisted slot cap. A zero expiry makes it permanent.
// Overrides never grant access to an otherwise ineligible official account.
type OwnerOverride struct {
	MaxTunnels int
	ExpiresAt  time.Time
}

// OwnerQuotaDecision reports the total slots available to an eligible owner.
type OwnerQuotaDecision struct {
	Allowed    bool
	MaxTunnels int
	Reason     ErrorCode
}

// VisitorConnectDecision applies to an already paired visitor or owner.
type VisitorConnectDecision struct {
	Allowed bool
	Reason  ErrorCode
}

// EvaluateOwnerPolicy evaluates a successful membership lookup. Callers must
// reject lookup errors before calling this function.
func EvaluateOwnerPolicy(ent membership.Entitlement, now time.Time, freeSlots, paidDefaultSlots int, override *OwnerOverride) OwnerQuotaDecision {
	relay := ent.RelayAllowed && ent.ValidUntil.After(now)
	tunnelEnd := tunnelEntitlementActive(ent, now)
	if ent.TunnelFieldsInvalid || denied(ent.TunnelAllowed) || !relay && ent.TunnelValidUntil != nil && !tunnelEnd {
		return ownerDecision(0)
	}
	slots := freeSlots
	if ent.MaxTunnels != nil && (relay || tunnelEnd || *ent.MaxTunnels <= freeSlots) {
		slots = *ent.MaxTunnels
	} else if ent.MaxTunnels == nil && relay {
		slots = paidDefaultSlots
	}
	if !relay && !granted(ent.TunnelAllowed) && !(ent.MaxTunnels != nil && tunnelEnd) {
		return ownerDecision(0)
	}
	return ownerDecision(ApplyOwnerOverride(slots, now, override))
}

// EvaluateVisitorConnect requires a fresh, successful lookup. The caller
// establishes device pairing and the relationship between visitor and owner.
func EvaluateVisitorConnect(ent membership.Entitlement, now time.Time, isOwnerSelfConnect bool) VisitorConnectDecision {
	if !ent.TunnelFieldsInvalid && !denied(ent.TunnelAllowed) && !denied(ent.TunnelConnectAllowed) {
		relay := ent.RelayAllowed && ent.ValidUntil.After(now)
		tunnelEnd := tunnelEntitlementActive(ent, now)
		if !relay && ent.TunnelValidUntil != nil && !tunnelEnd {
			return VisitorConnectDecision{Reason: CodeEntitlementDenied}
		}
		if relay || granted(ent.TunnelConnectAllowed) ||
			isOwnerSelfConnect && (granted(ent.TunnelAllowed) || ent.MaxTunnels != nil && tunnelEnd) {
			return VisitorConnectDecision{Allowed: true}
		}
	}
	return VisitorConnectDecision{Reason: CodeEntitlementDenied}
}

// EvaluateSelfOwnerPolicy applies the configured cap to an allowlisted device.
func EvaluateSelfOwnerPolicy(allowlisted bool, slotCap int, now time.Time, override *OwnerOverride) OwnerQuotaDecision {
	if !allowlisted {
		return ownerDecision(0)
	}
	return ownerDecision(ApplyOwnerOverride(slotCap, now, override))
}

func ApplyOwnerOverride(slots int, now time.Time, override *OwnerOverride) int {
	if slots > 0 && override != nil && (override.ExpiresAt.IsZero() || override.ExpiresAt.After(now)) {
		return override.MaxTunnels
	}
	return slots
}

// EvaluateSelfVisitorConnect requires an allowlisted host and verified pairing.
func EvaluateSelfVisitorConnect(hostAllowlisted, paired bool) VisitorConnectDecision {
	if hostAllowlisted && paired {
		return VisitorConnectDecision{Allowed: true}
	}
	return VisitorConnectDecision{Reason: CodeEntitlementDenied}
}

func ownerDecision(slots int) OwnerQuotaDecision {
	if slots <= 0 {
		return OwnerQuotaDecision{Reason: CodeEntitlementDenied}
	}
	return OwnerQuotaDecision{Allowed: true, MaxTunnels: slots}
}

func tunnelEntitlementActive(ent membership.Entitlement, now time.Time) bool {
	return ent.TunnelValidUntil != nil && *ent.TunnelValidUntil > 0 && time.Unix(*ent.TunnelValidUntil, 0).After(now)
}

func denied(value *bool) bool  { return value != nil && !*value }
func granted(value *bool) bool { return value != nil && *value }
