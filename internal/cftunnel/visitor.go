package cftunnel

import (
	"context"
	"time"

	"vanora-relay/internal/identity"
	"vanora-relay/internal/membership"
)

type VisitorRequest struct {
	Host, Visitor           identity.Principal
	HostLease, VisitorLease time.Time
	Generation, Incarnation int64
	Paired                  bool
}

func (s *Service) AuthorizeVisitor(ctx context.Context, req VisitorRequest) (string, time.Time, error) {
	if s.cfg.Mode != ModeManaged || !req.Paired {
		return "", time.Time{}, ErrNotFound
	}
	host := s.deviceBinding(req.Host)
	allocation, err := s.readyAllocation(ctx, host, req.Generation, req.Incarnation)
	if err != nil {
		return "", time.Time{}, err
	}
	var until time.Time
	if s.cfg.Channel.IsSelfHosted() {
		_, allowlisted := s.cfg.SelfDevices[host.DeviceID]
		if !EvaluateSelfVisitorConnect(allowlisted, req.Paired).Allowed {
			return "", time.Time{}, ErrEntitlementDenied
		}
		until = s.now().Add(time.Minute)
	} else {
		ownerEnt, err := s.lookupMembership(ctx, req.Host)
		if err != nil {
			return "", time.Time{}, err
		}
		sameOwner := host.OwnerID == req.Visitor.RemoteUserID()
		visitorEnt := ownerEnt
		if !sameOwner {
			visitorEnt, err = s.lookupMembership(ctx, req.Visitor)
			if err != nil {
				return "", time.Time{}, err
			}
		}
		now := s.now()
		override, err := s.store.GetOwnerOverride(ctx, s.scope.ID, host.OwnerID)
		if err != nil {
			return "", time.Time{}, err
		}
		if !EvaluateOwnerPolicy(ownerEnt, now, s.cfg.FreeSlots, s.cfg.PaidDefaultSlots, override).Allowed ||
			!EvaluateVisitorConnect(visitorEnt, now, sameOwner).Allowed {
			return "", time.Time{}, ErrEntitlementDenied
		}
		until = earliest(now.Add(time.Minute), req.Host.Expires, req.HostLease, req.Visitor.Expires, req.VisitorLease)
		until = ownerEntitlementWindow(until, now, ownerEnt)
		until = visitorEntitlementWindow(until, now, visitorEnt, sameOwner)
	}
	if !until.After(s.now()) {
		return "", time.Time{}, ErrEntitlementDenied
	}
	current, err := s.readyAllocation(ctx, host, req.Generation, req.Incarnation)
	if err != nil || current.Hostname != allocation.Hostname {
		return "", time.Time{}, ErrNotFound
	}
	return current.Hostname, until.UTC(), nil
}

func ownerEntitlementWindow(until, now time.Time, ent membership.Entitlement) time.Time {
	if granted(ent.TunnelAllowed) && ent.TunnelValidUntil == nil {
		return until
	}
	var grantUntil time.Time
	if ent.RelayAllowed && ent.ValidUntil.After(now) {
		grantUntil = ent.ValidUntil
	}
	if tunnelEntitlementActive(ent, now) && (granted(ent.TunnelAllowed) || ent.MaxTunnels != nil) {
		if tunnelUntil := time.Unix(*ent.TunnelValidUntil, 0); tunnelUntil.After(grantUntil) {
			grantUntil = tunnelUntil
		}
	}
	if grantUntil.IsZero() {
		return until
	}
	return earliest(until, grantUntil)
}

func visitorEntitlementWindow(until, now time.Time, ent membership.Entitlement, sameOwner bool) time.Time {
	if ent.TunnelValidUntil == nil && (granted(ent.TunnelConnectAllowed) || sameOwner && granted(ent.TunnelAllowed)) {
		return until
	}
	var grantUntil time.Time
	if ent.RelayAllowed && ent.ValidUntil.After(now) {
		grantUntil = ent.ValidUntil
	}
	if tunnelEntitlementActive(ent, now) && (granted(ent.TunnelConnectAllowed) ||
		sameOwner && (granted(ent.TunnelAllowed) || ent.MaxTunnels != nil)) {
		if tunnelUntil := time.Unix(*ent.TunnelValidUntil, 0); tunnelUntil.After(grantUntil) {
			grantUntil = tunnelUntil
		}
	}
	if grantUntil.IsZero() {
		return until
	}
	return earliest(until, grantUntil)
}

func earliest(until time.Time, times ...time.Time) time.Time {
	for _, bound := range times {
		if bound.Before(until) {
			until = bound
		}
	}
	return until
}

func (s *Service) RefreshVisitorAccess(ctx context.Context, req VisitorRequest) (string, time.Time, error) {
	return s.AuthorizeVisitor(ctx, req)
}

func (s *Service) MintEdgeTicket(ctx context.Context, host identity.Principal, generation, incarnation int64, hostname, jti string) (string, error) {
	if s.cfg.Mode != ModeManaged || !ticketJTIPattern.MatchString(jti) {
		return "", ErrInvalidProof
	}
	a, err := s.readyAllocation(ctx, s.deviceBinding(host), generation, incarnation)
	if err != nil {
		return "", err
	}
	if a.Hostname != hostname {
		return "", ErrNotFound
	}
	if s.cfg.EdgeGate == EdgeDesktopOnly {
		return "", nil
	}
	return s.crypto.MintEdgeTicket(a.Hostname, edgeWebSocketPath, jti, s.now())
}

func (s *Service) readyAllocation(ctx context.Context, binding DeviceBinding, generation, incarnation int64) (Allocation, error) {
	a, err := s.Status(ctx, binding)
	if err != nil {
		return Allocation{}, err
	}
	if a.State != StateReady || a.ManualResumeRequired || a.Generation != generation || a.Incarnation != incarnation {
		return Allocation{}, ErrNotFound
	}
	return a, nil
}

func (s *Service) ReleasedForOwner(ctx context.Context, actor identity.Principal, target string) bool {
	binding := s.deviceBinding(actor)
	if binding.DeviceID != target {
		if !s.cfg.Channel.ChecksEntitlement() {
			return false
		}
		binding.DeviceID, binding.OwnerManaged = target, true
	}
	a, err := s.Status(ctx, binding)
	return err == nil && a.State == StateReleased
}

func (s *Service) deviceBinding(principal identity.Principal) DeviceBinding {
	owner := principal.RemoteUserID()
	if s.cfg.Channel.IsSelfHosted() {
		owner = principal.DeviceID
	}
	return DeviceBinding{DeviceID: principal.DeviceID, OwnerID: owner, DeviceKeyHash: hashHex(principal.PublicKey)}
}

func (s *Service) RecordHostPresence(ctx context.Context, host identity.Principal, runtimeID, socketID, phase string, generation, incarnation, seq int64, canRecover bool) error {
	return s.recordPresence(ctx, s.deviceBinding(host), Presence{
		RuntimeID: runtimeID, SocketID: socketID, Phase: PresencePhase(phase),
		Generation: generation, Seq: seq, CanRecover: canRecover,
	}, incarnation)
}

func (s *Service) recordPresence(ctx context.Context, binding DeviceBinding, p Presence, incarnation int64) error {
	if binding.OwnerManaged {
		return ErrDeviceBinding
	}
	a, err := s.Status(ctx, binding)
	if err != nil {
		return err
	}
	if p.SocketID == "" || p.RuntimeID == "" || p.Generation != a.Generation || p.Seq < 1 ||
		incarnation != 0 && incarnation != a.Incarnation {
		return ErrInvalidClaim
	}
	p.ScopeID, p.AllocationID = a.ScopeID, a.ID
	p.SeenAt = s.now()
	p.ExpiresAt = p.SeenAt.Add(45 * time.Second)
	return s.store.SetPresence(ctx, p)
}
