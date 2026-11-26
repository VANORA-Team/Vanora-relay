package cftunnel

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

type operationWork struct {
	service *Service
	ctx     context.Context
	op      Operation
	a       Allocation
}

type operationFailure struct {
	state AllocationState
	cause error
}

func (e operationFailure) Error() string { return e.cause.Error() }
func (e operationFailure) Unwrap() error { return e.cause }

func (s *Service) RunWorker(ctx context.Context, workerID string) error {
	if workerID == "" {
		return ErrInvalidClaim
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.workWake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(0)
		case <-timer.C:
			processed, err := s.ProcessOne(ctx, workerID)
			if err != nil && ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				s.logger.WarnContext(ctx, "Cloudflare tunnel worker error", "error_code", CodeOf(err))
			}
			delay := s.poll
			if processed && err == nil {
				delay = 0
			}
			timer.Reset(delay)
		}
	}
}

func (s *Service) ProcessOne(ctx context.Context, workerID string) (bool, error) {
	op, err := s.store.AcquireWork(ctx, s.scope.ID, workerID, s.now(), s.lease)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	a, err := s.store.GetByAllocationID(ctx, op.ScopeID, op.AllocationID)
	if err != nil {
		return true, err
	}
	if op.ProtectPresence || op.Type == OpRepair {
		ctx = backgroundCF(ctx)
	}
	work := operationWork{service: s, ctx: ctx, op: op, a: a}
	err = work.run()
	if err == nil {
		return true, nil
	}
	var terminal operationFailure
	if errors.As(err, &terminal) {
		return true, work.complete(terminal.state, terminal.cause)
	}
	delay, limited := cfRateDelay(err)
	if limited || errors.Is(err, ErrCFTransient) {
		now := s.now()
		delay = max(delay, time.Second<<min(8, max(0, op.Attempts-1)))
		err = s.store.ReleaseWork(ctx, op.Fence(), now, boundedTimeAdd(now, delay), CodeOf(err))
		if err == nil {
			s.metrics.operation(op.Type, "retry")
		}
		return true, err
	}
	return true, err
}

func (w *operationWork) run() error {
	switch w.op.Type {
	case OpProvision, OpRecover, OpResume:
		if w.a.State == StatePending {
			return w.provision()
		}
		if w.op.Type == OpResume {
			return w.reconcile()
		}
	case OpReconcile, OpRepair:
		return w.reconcile()
	case OpRelease, OpDisconnect, OpDeprovision:
		return w.cleanup()
	}
	return ErrInvalidTransition
}

func (w *operationWork) complete(state AllocationState, cause error) error {
	if _, err := w.begin("complete"); err != nil {
		return err
	}
	cmd := FinishStepCommand{Fence: w.op.Fence(), Name: "complete", FinalState: state, ErrorCode: CodeOf(cause), Now: w.service.now()}
	if err := w.service.store.FinishStep(w.ctx, cmd); err != nil {
		return err
	}
	outcome := string(state)
	if cause != nil {
		outcome = string(CodeOf(cause))
	}
	if state == StateQuarantined {
		w.service.logger.WarnContext(w.ctx, "Cloudflare tunnel quarantined", "operation_type", w.op.Type, "error_code", CodeOf(cause))
	}
	w.service.metrics.operation(w.op.Type, outcome)
	if w.op.Type == OpRelease && w.op.ProtectPresence && state == StateReleased {
		w.service.metrics.released()
	}
	return nil
}

func (w *operationWork) begin(name string) (Step, error) {
	now := w.service.now()
	if err := w.service.store.RenewWork(w.ctx, w.op.Fence(), now, w.service.lease); err != nil {
		return Step{}, err
	}
	return w.service.store.BeginStep(w.ctx, w.op.Fence(), name, w.service.now())
}

func (w *operationWork) finish(name string, resources *Resources) error {
	cmd := FinishStepCommand{Fence: w.op.Fence(), Name: name, Resources: resources, Now: w.service.now()}
	if err := w.service.store.FinishStep(w.ctx, cmd); err != nil {
		return err
	}
	if resources != nil {
		w.a.Resources = *resources
	}
	return nil
}

func (w *operationWork) write(name string, action func(context.Context) error) error {
	step, err := w.begin(name)
	if err != nil || !step.FinishedAt.IsZero() {
		return err
	}
	ctx, cancel := context.WithTimeout(w.ctx, min(15*time.Second, w.service.lease/2))
	err = action(ctx)
	cancel()
	if err != nil {
		return w.externalFailure(err, step.Retry)
	}
	return w.finish(name, nil)
}

func (w *operationWork) externalFailure(err error, retried bool) error {
	if errors.Is(err, ErrCFRateLimited) {
		return err
	}
	if errors.Is(err, ErrCFTransient) && (!retried || w.op.Attempts < 4) {
		return err
	}
	return operationFailure{StateQuarantined, err}
}

func (w *operationWork) readFailure(err error, safeRollback bool) error {
	if errors.Is(err, ErrCFTransient) || errors.Is(err, ErrCFRateLimited) {
		return err
	}
	if safeRollback {
		final := StateReleased
		if w.op.Type == OpProvision {
			final = StateDisabled
		}
		return operationFailure{final, err}
	}
	return operationFailure{StateQuarantined, err}
}

func (w *operationWork) readAfterWriteFailure(err error, name string) error {
	if errors.Is(err, ErrCFTransient) && w.op.Attempts >= 4 {
		step, stepErr := w.service.store.GetStep(w.ctx, w.op.ID, name)
		if stepErr == nil && step.FinishedAt.IsZero() {
			return operationFailure{StateQuarantined, err}
		}
		if stepErr != nil && !errors.Is(stepErr, ErrNotFound) {
			return stepErr
		}
	}
	return w.readFailure(err, false)
}

func findTunnel(ctx context.Context, cf Cloudflare, name string) (Tunnel, error) {
	const perPage = 50
	var found Tunnel
	for page := 1; ; page++ {
		entries, err := cf.ListTunnels(ctx, TunnelListQuery{Name: name, Page: page, PerPage: perPage})
		if err != nil {
			return Tunnel{}, err
		}
		for _, tunnel := range entries.Tunnels {
			if tunnel.Name != name || !tunnel.DeletedAt.IsZero() {
				continue
			}
			if !validCFSegment(tunnel.ID) || found.ID != "" && found.ID != tunnel.ID {
				return Tunnel{}, ErrCFConflict
			}
			found = tunnel
		}
		if !hasMoreTunnels(entries, page, perPage) {
			return found, nil
		}
	}
}

func hasMoreTunnels(entries TunnelListPage, page, perPage int) bool {
	if len(entries.Tunnels) == 0 {
		return false
	}
	if entries.TotalPages != 0 {
		return page < entries.TotalPages
	}
	return entries.TotalCount > page*perPage
}

func (w *operationWork) provision() error {
	if err := w.ensureTunnel(); err != nil {
		return err
	}
	if err := w.ensureConfiguration(); err != nil {
		return err
	}
	if err := w.ensureDNS(); err != nil {
		return err
	}
	return w.complete(StateReady, nil)
}

func (w *operationWork) ensureTunnel() error {
	if w.a.Resources.TunnelID != "" {
		return nil
	}
	s := w.service
	tunnel, err := findTunnel(w.ctx, s.cf, w.a.TunnelName)
	if err != nil {
		_, stepErr := s.store.GetStep(w.ctx, w.op.ID, "ensure_tunnel")
		if stepErr != nil && !errors.Is(stepErr, ErrNotFound) {
			return stepErr
		}
		if errors.Is(err, ErrCFConflict) || stepErr == nil && w.op.Attempts >= 4 && errors.Is(err, ErrCFTransient) {
			return operationFailure{StateQuarantined, err}
		}
		return w.readFailure(err, errors.Is(stepErr, ErrNotFound))
	}
	step, err := w.begin("ensure_tunnel")
	if err != nil {
		return err
	}
	if tunnel.ID != "" {
		if !step.Retry || !matchesAllocationTunnel(w.a, tunnel) {
			return operationFailure{StateQuarantined, ErrCFConflict}
		}
	} else {
		if step.Retry {
			return operationFailure{StateQuarantined, ErrCFTransient}
		}
		ctx, cancel := context.WithTimeout(w.ctx, min(15*time.Second, s.lease/2))
		tunnel, err = s.cf.CreateTunnel(ctx, w.a.TunnelName, s.crypto.DeriveRotationSecret(w.op.ID, w.a.ID, w.a.Incarnation))
		cancel()
		if err != nil {
			if errors.Is(err, ErrCFRateLimited) {
				if discard := s.store.DiscardStep(w.ctx, w.op.Fence(), step.Name, s.now()); discard != nil {
					return discard
				}
				return err
			}
			if errors.Is(err, ErrCFAuthorization) || errors.Is(err, ErrCFRejected) {
				return w.readFailure(err, true)
			}
			return w.externalFailure(err, false)
		}
		if !matchesAllocationTunnel(w.a, tunnel) {
			return operationFailure{StateQuarantined, ErrCFConflict}
		}
	}
	resources := w.a.Resources
	resources.TunnelID = tunnel.ID
	return w.finish(step.Name, &resources)
}

func (w *operationWork) ensureConfiguration() error {
	cf := w.service.cf
	id := w.a.Resources.TunnelID
	cfg, err := cf.GetConfiguration(w.ctx, id)
	if err != nil && !errors.Is(err, ErrCFConfigNotFound) {
		return w.readAfterWriteFailure(err, "put_config")
	}
	if err == nil && IngressMatches(cfg, w.a.Hostname, w.a.Origin) {
		return nil
	}
	step, err := w.service.store.GetStep(w.ctx, w.op.ID, "put_config")
	if err == nil && !step.FinishedAt.IsZero() {
		return operationFailure{StateQuarantined, ErrCFConflict}
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return w.write("put_config", func(ctx context.Context) error {
		return cf.PutConfiguration(ctx, id, desiredIngress(w.a.Hostname, w.a.Origin))
	})
}

func tunnelDNSTarget(id string) string { return id + ".cfargotunnel.com" }

func dnsTunnelID(target string) (string, bool) {
	id, suffix := strings.CutSuffix(strings.ToLower(strings.TrimSuffix(target, ".")), ".cfargotunnel.com")
	return id, suffix && validCFSegment(id)
}

func (s *Service) ownedDNS(record DNSRecord, hostname string) (string, int64, bool) {
	if record.Type != "CNAME" || record.Hostname != hostname || !validCFSegment(record.ID) {
		return "", 0, false
	}
	id, ok := dnsTunnelID(record.Target)
	if !ok {
		return "", 0, false
	}
	epoch, ok := s.crypto.VerifyDNSMarker(record.Comment, s.scope.ZoneID, hostname, id)
	return id, epoch, ok
}

func (s *Service) dnsMatchesAllocation(record DNSRecord, a Allocation) bool {
	if record.Type != "CNAME" || record.Hostname != a.Hostname || !validCFSegment(record.ID) {
		return false
	}
	if id := a.Resources.TunnelID; id != "" {
		epoch, ok := s.crypto.VerifyDNSMarker(record.Comment, s.scope.ZoneID, a.Hostname, id)
		return ok && epoch == a.Incarnation
	}
	_, epoch, ok := s.ownedDNS(record, a.Hostname)
	return ok && epoch == a.Incarnation
}

func (w *operationWork) ensureDNS() error {
	s := w.service
	records, err := s.cf.ListDNSRecords(w.ctx, w.a.Hostname)
	if err != nil {
		return w.readAfterWriteFailure(err, "ensure_dns")
	}
	tunnelID := w.a.Resources.TunnelID
	var owned []DNSRecord
	for _, record := range records {
		if record.Hostname != w.a.Hostname || (record.Type != "CNAME" && record.Type != "A" && record.Type != "AAAA") {
			continue
		}
		if !s.dnsMatchesAllocation(record, w.a) {
			return operationFailure{StateQuarantined, ErrDNSConflict}
		}
		owned = append(owned, record)
	}
	sort.Slice(owned, func(first, second int) bool {
		checkpoint := w.a.Resources.DNSRecordID
		if owned[first].ID == checkpoint || owned[second].ID == checkpoint {
			return owned[first].ID == checkpoint && owned[second].ID != checkpoint
		}
		return owned[first].ID < owned[second].ID
	})
	for _, duplicate := range owned[min(1, len(owned)):] {
		if err := w.deleteDNS(duplicate); err != nil {
			return err
		}
	}
	desired := DNSRecord{Type: "CNAME", Hostname: w.a.Hostname, Target: tunnelDNSTarget(tunnelID), TTL: 1, Proxied: true,
		Comment: s.crypto.FormatDNSMarker(s.scope.ZoneID, w.a.Hostname, tunnelID, w.a.Incarnation)}
	record := desired
	if len(owned) > 0 {
		desired.ID, record = owned[0].ID, owned[0]
	}
	if len(owned) == 0 || record != desired {
		name := "ensure_dns"
		step, err := w.begin(name)
		if err != nil {
			return err
		}
		if !step.FinishedAt.IsZero() {
			return operationFailure{StateQuarantined, ErrDNSConflict}
		}
		if len(owned) == 0 && step.Retry {
			return operationFailure{StateQuarantined, ErrCFTransient}
		}
		ctx, cancel := context.WithTimeout(w.ctx, min(15*time.Second, s.lease/2))
		if len(owned) == 0 {
			record, err = s.cf.CreateDNSRecord(ctx, desired)
		} else {
			record, err = s.cf.PatchDNSRecord(ctx, desired)
		}
		cancel()
		if err != nil {
			if len(owned) == 0 && errors.Is(err, ErrCFRateLimited) {
				if discard := s.store.DiscardStep(w.ctx, w.op.Fence(), step.Name, s.now()); discard != nil {
					return discard
				}
				return err
			}
			return w.externalFailure(err, step.Retry)
		}
		id, epoch, ok := s.ownedDNS(record, w.a.Hostname)
		if !ok || id != tunnelID || epoch != w.a.Incarnation || record.TTL != 1 || !record.Proxied {
			return operationFailure{StateQuarantined, ErrDNSConflict}
		}
		resources := w.a.Resources
		resources.DNSRecordID = record.ID
		return w.finish(name, &resources)
	}
	if w.a.Resources.DNSRecordID == record.ID {
		return nil
	}
	resources := w.a.Resources
	resources.DNSRecordID = record.ID
	step, err := w.begin("checkpoint_dns:" + record.ID)
	if err != nil {
		return err
	}
	return w.finish(step.Name, &resources)
}

func (w *operationWork) lookupTunnel() (Tunnel, error) {
	var tunnel Tunnel
	var err error
	if w.a.Resources.TunnelID == "" {
		tunnel, err = findTunnel(w.ctx, w.service.cf, w.a.TunnelName)
	} else {
		tunnel, err = w.service.cf.GetTunnel(w.ctx, w.a.Resources.TunnelID)
	}
	if cfMissing(tunnel, err) {
		return Tunnel{}, nil
	}
	if err != nil {
		return Tunnel{}, w.readFailure(err, false)
	}
	if tunnel.ID == "" && w.a.Resources.TunnelID != "" || tunnel.ID != "" && !matchesAllocationTunnel(w.a, tunnel) {
		return Tunnel{}, operationFailure{StateQuarantined, ErrCFConflict}
	}
	return tunnel, nil
}

func (w *operationWork) reconcile() error {
	tunnel, err := w.lookupTunnel()
	if err != nil {
		return err
	}
	if tunnel.ID == "" {
		if err := w.removeOwnedDNS(); err != nil {
			return err
		}
		return w.complete(StateReleased, ErrRecoveryRequired)
	}
	if w.a.Resources.TunnelID == "" {
		step, err := w.begin("checkpoint_tunnel")
		if err != nil {
			return err
		}
		if err := w.finish(step.Name, &Resources{TunnelID: tunnel.ID}); err != nil {
			return err
		}
	}
	if err := w.ensureConfiguration(); err != nil {
		return err
	}
	if err := w.ensureDNS(); err != nil {
		return err
	}
	if w.a.ManualResumeRequired {
		return w.complete(StateSuspended, nil)
	}
	return w.complete(StateReady, nil)
}

func (w *operationWork) removeOwnedDNS() error {
	s := w.service
	records, err := s.cf.ListDNSRecords(w.ctx, w.a.Hostname)
	if err != nil {
		return w.readFailure(err, false)
	}
	for _, record := range records {
		if !s.dnsMatchesAllocation(record, w.a) {
			continue
		}
		if err := w.deleteDNS(record); err != nil {
			return err
		}
	}
	return nil
}

func (w *operationWork) deleteDNS(record DNSRecord) error {
	return w.write("delete_dns:"+record.ID, func(ctx context.Context) error {
		return ignoreMissing(w.service.cf.DeleteDNSRecord(ctx, record.ID))
	})
}

func ignoreMissing(err error) error {
	if errors.Is(err, ErrCFNotFound) {
		return nil
	}
	return err
}

func (w *operationWork) cleanup() error {
	s := w.service
	if w.op.ProtectPresence {
		presence, err := s.store.GetPresence(w.ctx, w.a.ScopeID, w.a.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if presence.Active(s.now()) {
			return w.complete(w.releaseFallback(), ErrPresenceActive)
		}
	}
	tunnel, err := w.lookupTunnel()
	if err != nil {
		return err
	}
	if tunnel.ID != "" {
		if w.op.Type == OpRelease {
			if err := w.releaseTunnel(tunnel); err != nil {
				return err
			}
		} else if err := w.disconnectTunnel(tunnel.ID); err != nil {
			return err
		}
	}
	if w.op.Type == OpDisconnect {
		return w.complete(StateSuspended, nil)
	}
	if err := w.removeOwnedDNS(); err != nil {
		return err
	}
	if w.op.Type == OpDeprovision {
		return w.complete(StateDisabled, nil)
	}
	return w.complete(StateReleased, nil)
}

func (w *operationWork) releaseFallback() AllocationState {
	if w.a.ManualResumeRequired {
		return StateSuspended
	}
	return StateReady
}

func (w *operationWork) releaseTunnel(tunnel Tunnel) error {
	cf := w.service.cf
	if w.op.ProtectPresence && !w.a.ManualResumeRequired {
		now := w.service.now()
		grace := w.service.cfg.Reaper.tunnelGrace(tunnel.Status, !w.a.RecoveryEnabledAt.IsZero())
		if tunnel.Status != w.a.CFStatus || w.a.CFStatusSince.IsZero() ||
			tunnel.Status != TunnelDown && tunnel.Status != TunnelInactive ||
			tunnel.Status == TunnelDown && validReapTime(tunnel.ConnsInactiveAt, tunnel.CreatedAt, now) && tunnel.ConnsInactiveAt.After(now.Add(-grace)) {
			return operationFailure{w.releaseFallback(), ErrCFTunnelInUse}
		}
	}
	connections, err := cf.ListConnections(w.ctx, tunnel.ID)
	if errors.Is(err, ErrCFNotFound) {
		return nil
	}
	if err != nil {
		return w.readFailure(err, false)
	}
	if len(connections) > 0 {
		return operationFailure{w.releaseFallback(), ErrCFTunnelInUse}
	}
	err = w.write("delete_tunnel", func(ctx context.Context) error {
		return ignoreMissing(cf.DeleteTunnel(ctx, tunnel.ID))
	})
	if errors.Is(err, ErrCFTunnelInUse) {
		return operationFailure{w.releaseFallback(), ErrCFTunnelInUse}
	}
	return err
}

func (w *operationWork) disconnectTunnel(id string) error {
	s := w.service
	if err := w.write("rotate_secret", func(ctx context.Context) error {
		return ignoreMissing(s.cf.RotateSecret(ctx, id, s.crypto.DeriveRotationSecret(w.op.ID, w.a.ID, w.a.Incarnation)))
	}); err != nil {
		return err
	}
	if err := w.write("disconnect_all", func(ctx context.Context) error { return ignoreMissing(s.cf.DisconnectAll(ctx, id)) }); err != nil {
		return err
	}
	if w.op.Type == OpDeprovision {
		return w.write("delete_tunnel", func(ctx context.Context) error { return ignoreMissing(s.cf.DeleteTunnel(ctx, id)) })
	}
	return nil
}
