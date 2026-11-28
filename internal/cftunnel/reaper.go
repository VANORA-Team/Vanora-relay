package cftunnel

import (
	"context"
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

const reapPageSize = 50

var reapKinds = [...]string{"down", "inactive", "suspended", "pending", "orphan"}

type SweepResult struct {
	Candidates     map[string]int
	ReleaseClaims  int
	PendingExpired int
	OrphansCleaned int
	Paused         bool
}

type Reaper struct {
	service *Service
	cfg     ReaperConfig
	mu      sync.Mutex
}

func NewReaper(service *Service) *Reaper {
	return &Reaper{service: service, cfg: service.cfg.Reaper}
}

func reaperDefaults(cfg ReaperConfig) ReaperConfig {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.Budget <= 0 {
		cfg.Budget = 30 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2
	}
	if cfg.DownGrace <= 0 {
		cfg.DownGrace = 5 * time.Minute
	}
	if cfg.LegacyGrace <= 0 {
		cfg.LegacyGrace = 7 * 24 * time.Hour
	}
	if cfg.InactiveGrace <= 0 {
		cfg.InactiveGrace = time.Hour
	}
	if cfg.PendingGrace <= 0 {
		cfg.PendingGrace = 15 * time.Minute
	}
	if cfg.OrphanGrace <= 0 {
		cfg.OrphanGrace = 24 * time.Hour
	}
	return cfg
}

func (r *Reaper) Run(ctx context.Context) error {
	if r.cfg.Mode != ReaperActive && r.cfg.Mode != ReaperDryRun {
		return nil
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			_, err := r.SweepOnce(ctx)
			if err != nil && ctx.Err() == nil && !errors.Is(err, ErrCFRateLimited) && !errors.Is(err, ErrGenerationConflict) {
				r.service.logger.WarnContext(ctx, "Cloudflare tunnel sweep interrupted", "error_code", CodeOf(err))
			}
			timer.Reset(r.cfg.Interval + time.Duration(rand.Int64N(max(1, int64(r.cfg.Interval/10)))))
		}
	}
}

func (r *Reaper) SweepOnce(ctx context.Context) (result SweepResult, err error) {
	if r.cfg.Mode != ReaperActive && r.cfg.Mode != ReaperDryRun {
		return result, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(backgroundCF(ctx), r.cfg.Budget)
	defer cancel()
	result.Candidates = make(map[string]int)
	defer func() {
		result.Paused = errors.Is(err, ErrCFRateLimited)
		r.service.metrics.sweep(r.cfg.Mode, result)
	}()
	rotation, err := r.loadCursor(ctx, "reaper")
	if err != nil {
		return result, err
	}
	start, _ := strconv.Atoi(rotation.Cursor)
	if start < 0 || start >= len(reapKinds) {
		start = 0
	}
	now := r.service.now()
	for offset := range reapKinds {
		index := (start + offset) % len(reapKinds)
		kind := reapKinds[index]
		if kind == "orphan" {
			err = r.sweepOrphans(ctx, now, &result)
		} else {
			err = r.sweepAllocations(ctx, kind, now, &result)
		}
		if err != nil {
			return result, err
		}
		rotation.Cursor = strconv.Itoa((index + 1) % len(reapKinds))
		if err := r.saveCursor(ctx, &rotation); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (r *Reaper) loadCursor(ctx context.Context, kind string) (ScanCursor, error) {
	key := r.service.scope.ID
	cursor, err := r.service.store.LoadScan(ctx, key, kind)
	if errors.Is(err, ErrNotFound) {
		return ScanCursor{ScopeID: key, Kind: kind}, nil
	}
	return cursor, err
}

func (r *Reaper) saveCursor(ctx context.Context, cursor *ScanCursor) error {
	previous := cursor.UpdatedAt
	now := r.service.now()
	if !now.After(cursor.UpdatedAt) {
		now = cursor.UpdatedAt.Add(time.Nanosecond)
	}
	cursor.UpdatedAt = now
	return r.service.store.SaveScan(ctx, *cursor, previous)
}

func (r *Reaper) sweepAllocations(ctx context.Context, kind string, now time.Time, result *SweepResult) error {
	s := r.service
	cursor, err := r.loadCursor(ctx, kind)
	if err != nil {
		return err
	}
	limit := reapPageSize
	if gate, ok := s.cf.(*GatedCloudflare); ok && (kind == "down" || kind == "inactive") {
		limit = min(limit, max(1, int(r.cfg.Budget.Seconds()*float64(gate.background.Limit())/5)))
	}
	page, err := s.store.ListReapCandidates(ctx, s.scope.ID, cursor.Cursor, limit)
	if err != nil {
		return err
	}
	if kind == "down" || kind == "inactive" {
		group, requests := errgroup.WithContext(ctx)
		group.SetLimit(r.cfg.Concurrency)
		for index, entry := range page {
			if requests.Err() != nil {
				break
			}
			if entry.Presence != nil && entry.Presence.Active(now) {
				continue
			}
			if entry.Allocation.State == StateReady && entry.Allocation.Observation.ObservedAt.Before(now) {
				group.Go(func() error {
					return r.observe(requests, now, &page[index].Allocation)
				})
			}
		}
		if err := group.Wait(); err != nil {
			return err
		}
	}
	for _, entry := range page {
		if err := r.considerAllocation(ctx, kind, entry, now, result); err != nil {
			return err
		}
	}
	cursor.Cursor = ""
	if len(page) == limit {
		cursor.Cursor = page[len(page)-1].Allocation.ID
	}
	return r.saveCursor(ctx, &cursor)
}

func (r *Reaper) observe(ctx context.Context, now time.Time, a *Allocation) error {
	s := r.service
	tunnel, err := s.cf.GetTunnel(ctx, a.Resources.TunnelID)
	observation := CloudflareObservation{Generation: a.Generation, ObservedAt: now, DNSExists: a.Observation.DNSExists}
	if !cfMissing(tunnel, err) {
		if err != nil {
			return err
		}
		if !matchesAllocationTunnel(*a, tunnel) {
			a.CFStatus = ""
			return nil
		}
		observation.TunnelExists = true
		switch tunnel.Status {
		case TunnelDown, TunnelInactive, TunnelHealthy, TunnelDegraded:
			observation.Status = tunnel.Status
		}
		if tunnel.Status == TunnelDown && validReapTime(tunnel.ConnsInactiveAt, tunnel.CreatedAt, now) {
			floor := a.ReadyAt
			if a.CFStatus != TunnelDown {
				floor = laterTime(floor, a.Observation.ObservedAt)
			}
			observation.StatusSince = laterTime(tunnel.ConnsInactiveAt, floor)
		}
		if tunnel.Status == TunnelInactive && validReapTime(tunnel.CreatedAt, time.Time{}, now) {
			observation.StatusSince = laterTime(tunnel.CreatedAt, a.ReadyAt)
		}
		if observation.StatusSince.IsZero() && a.CFStatus == observation.Status {
			observation.StatusSince = a.CFStatusSince
		}
		if observation.StatusSince.IsZero() {
			observation.StatusSince = now
		}
	}
	err = s.store.UpdateCloudflareObservation(ctx, a.ScopeID, a.ID, observation)
	if errors.Is(err, ErrGenerationConflict) || errors.Is(err, ErrInvalidTransition) {
		a.CFStatus = ""
		return nil
	}
	if err == nil {
		a.CFStatus, a.CFStatusSince = observation.Status, observation.StatusSince
	}
	return err
}

func validReapTime(value, created, now time.Time) bool {
	return !value.IsZero() && !value.Before(created) && !value.After(now)
}

func laterTime(first, second time.Time) time.Time {
	if first.After(second) {
		return first
	}
	return second
}

func (r *Reaper) considerAllocation(ctx context.Context, kind string, entry ReapCandidate, now time.Time, result *SweepResult) error {
	s := r.service
	a := entry.Allocation
	if entry.Presence != nil && entry.Presence.Active(now) {
		return nil
	}
	dry := r.cfg.Mode == ReaperDryRun
	if kind == "pending" {
		if a.State != StatePending || a.UpdatedAt.After(now.Add(-r.cfg.PendingGrace)) {
			return nil
		}
		expired, err := s.store.ExpirePending(ctx, a.AllocationKey, a.Generation, now, now.Add(-r.cfg.PendingGrace), dry)
		if expired {
			result.Candidates[kind]++
			if !dry {
				result.PendingExpired++
			}
		}
		return err
	}
	eligible := false
	switch kind {
	case "suspended":
		eligible = a.State == StateSuspended && !a.UpdatedAt.After(now.Add(-r.cfg.LegacyGrace))
	case "down", "inactive":
		grace := r.cfg.tunnelGrace(TunnelStatus(kind), !a.RecoveryEnabledAt.IsZero())
		eligible = a.State == StateReady && a.CFStatus == TunnelStatus(kind) &&
			!a.CFStatusSince.IsZero() && !a.CFStatusSince.After(now.Add(-grace))
	}
	if !eligible {
		return nil
	}
	result.Candidates[kind]++
	if dry {
		return nil
	}
	_, err := s.store.Claim(ctx, ClaimCommand{AllocationKey: a.AllocationKey, OwnerID: a.OwnerID, DeviceKeyHash: a.DeviceKeyHash,
		Type: OpRelease, IfGeneration: a.Generation, ProtectPresence: true, Now: now}, ClaimPolicy{})
	switch {
	case err == nil:
		result.ReleaseClaims++
		s.WakeWorker()
	case errors.Is(err, ErrGenerationConflict), errors.Is(err, ErrInvalidTransition), errors.Is(err, ErrOperationInProgress),
		errors.Is(err, ErrPresenceActive):
		return nil
	}
	return err
}

func (cfg ReaperConfig) tunnelGrace(status TunnelStatus, canRecover bool) time.Duration {
	if status == TunnelInactive {
		return cfg.InactiveGrace
	}
	if canRecover {
		return cfg.DownGrace
	}
	return cfg.LegacyGrace
}

func (r *Reaper) sweepOrphans(ctx context.Context, now time.Time, result *SweepResult) error {
	cursor, err := r.loadCursor(ctx, "orphan")
	if err != nil {
		return err
	}
	if cursor.Cycle == 0 {
		cursor.Cycle = 1
	}
	stage, position, _ := strings.Cut(cursor.Cursor, ":")
	if stage == "" || stage == "tunnel" {
		page, managed, _ := strings.Cut(position, ":")
		next, _ := strconv.Atoi(page)
		count, _ := strconv.Atoi(managed)
		more, count, err := r.scanOrphanTunnels(ctx, max(1, next), count, cursor.Cycle, now)
		if err != nil {
			return err
		}
		if more {
			cursor.Cursor = "tunnel:" + strconv.Itoa(max(1, next)+1) + ":" + strconv.Itoa(count)
			return r.saveCursor(ctx, &cursor)
		}
		if err := r.refreshUnmanaged(ctx, count); err != nil {
			return err
		}
		stage, position, cursor.Cursor = "dns", "1", "dns:1"
		if err := r.saveCursor(ctx, &cursor); err != nil {
			return err
		}
	}
	if stage == "dns" {
		page, _ := strconv.Atoi(position)
		more, err := r.scanOrphanDNS(ctx, max(1, page), cursor.Cycle, now)
		if err != nil {
			return err
		}
		if more {
			cursor.Cursor = "dns:" + strconv.Itoa(max(1, page)+1)
			return r.saveCursor(ctx, &cursor)
		}
		position, cursor.Cursor = "", "clean"
		if err := r.saveCursor(ctx, &cursor); err != nil {
			return err
		}
	}
	kind, resource, _ := strings.Cut(position, ":")
	orphans, err := r.service.store.ListDueOrphansAfter(ctx, cursor.ScopeID, now, cursor.Cycle, kind, resource, reapPageSize)
	if err != nil {
		return err
	}
	for _, orphan := range orphans {
		if !orphan.FirstSeenAt.After(now.Add(-r.cfg.OrphanGrace)) {
			if err := r.considerOrphan(ctx, orphan, now, result); err != nil {
				return err
			}
		}
		cursor.Cursor = "clean:" + orphan.Kind + ":" + orphan.ResourceID
		if err := r.saveCursor(ctx, &cursor); err != nil {
			return err
		}
	}
	if len(orphans) == reapPageSize {
		return nil
	}
	cursor.Cursor = ""
	cursor.Cycle++
	return r.saveCursor(ctx, &cursor)
}

func (r *Reaper) scanOrphanTunnels(ctx context.Context, page, managed int, cycle int64, now time.Time) (bool, int, error) {
	s := r.service
	prefix := s.scope.Namespace[:min(10, len(s.scope.Namespace))]
	list, err := s.cf.ListTunnels(ctx, TunnelListQuery{IncludePrefix: "vr-" + prefix, Page: page, PerPage: reapPageSize})
	if err != nil {
		return false, managed, err
	}
	for _, tunnel := range list.Tunnels {
		if !validCFSegment(tunnel.ID) || !tunnel.DeletedAt.IsZero() {
			continue
		}
		if _, _, ok := s.crypto.VerifyTunnelName(s.scope.Namespace, tunnel.Name); !ok {
			continue
		}
		active, err := r.linkedTunnel(ctx, tunnel.ID, tunnel.Name)
		if err != nil {
			return false, managed, err
		}
		if active {
			managed++
			continue
		}
		if err := r.observeOrphan(ctx, "tunnel", tunnel.ID, tunnel.Name, cycle, now); err != nil {
			return false, managed, err
		}
	}
	return hasMoreTunnels(list, page, reapPageSize), managed, nil
}

func (r *Reaper) refreshUnmanaged(ctx context.Context, managed int) error {
	s := r.service
	account, err := s.cf.ListTunnels(ctx, TunnelListQuery{Page: 1, PerPage: 1})
	if err != nil {
		return err
	}
	if r.cfg.Mode == ReaperActive && (account.TotalCount > 0 || len(account.Tunnels) == 0) {
		return s.store.UpdateUnmanagedCount(ctx, s.scope.ID, max(0, account.TotalCount-managed))
	}
	return nil
}

func (r *Reaper) scanOrphanDNS(ctx context.Context, page int, cycle int64, now time.Time) (bool, error) {
	s := r.service
	list, err := s.cf.ListMarkedDNSRecords(ctx, page, reapPageSize)
	if err != nil {
		return false, err
	}
	for _, record := range list.Records {
		label, domain, _ := strings.Cut(record.Hostname, ".")
		id, epoch, verified := s.ownedDNS(record, record.Hostname)
		if !verified || domain != s.scope.BaseDomain || !tunnelLabelPattern.MatchString(label) {
			continue
		}
		active, err := r.linkedTunnel(ctx, id, s.crypto.DeriveTunnelName(s.scope.Namespace, label, epoch))
		if err != nil {
			return false, err
		}
		if !active {
			if err := r.observeOrphan(ctx, "dns", record.ID, record.Hostname+"|"+record.Comment, cycle, now); err != nil {
				return false, err
			}
		}
	}
	return page < list.TotalPages && len(list.Records) != 0, nil
}

func (r *Reaper) linkedTunnel(ctx context.Context, id, name string) (bool, error) {
	s := r.service
	_, err := s.store.GetByTunnelID(ctx, s.scope.ID, id)
	if errors.Is(err, ErrNotFound) {
		_, err = s.store.GetByTunnelName(ctx, s.scope.ID, name)
	}
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (r *Reaper) observeOrphan(ctx context.Context, kind, id, marker string, cycle int64, now time.Time) error {
	s := r.service
	return s.store.UpsertOrphan(ctx, Orphan{ScopeID: s.scope.ID, Kind: kind, ResourceID: id, Marker: marker,
		FirstSeenAt: now, LastSeenAt: now, NextAttemptAt: now.Add(r.cfg.OrphanGrace), LastCycle: cycle})
}

func (r *Reaper) considerOrphan(ctx context.Context, orphan Orphan, now time.Time, result *SweepResult) error {
	var remove, absent bool
	var err error
	switch orphan.Kind {
	case "tunnel":
		remove, absent, err = r.orphanTunnel(ctx, orphan)
	case "dns":
		remove, absent, err = r.orphanDNS(ctx, orphan, now)
	}
	if err != nil || !remove && !absent {
		return err
	}
	if remove {
		result.Candidates["orphan_"+orphan.Kind]++
	}
	if r.cfg.Mode == ReaperDryRun {
		return nil
	}
	err = r.service.store.ResolveOrphan(ctx, orphan.ScopeID, orphan.Kind, orphan.ResourceID, orphan.LastSeenAt, now)
	if errors.Is(err, ErrGenerationConflict) {
		return nil
	}
	if err == nil && remove {
		result.OrphansCleaned++
	}
	return err
}

func (r *Reaper) orphanTunnel(ctx context.Context, orphan Orphan) (remove, absent bool, err error) {
	s := r.service
	tunnel, err := s.cf.GetTunnel(ctx, orphan.ResourceID)
	if cfMissing(tunnel, err) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	if _, _, verified := s.crypto.VerifyTunnelName(s.scope.Namespace, tunnel.Name); !verified ||
		tunnel.Name != orphan.Marker || tunnel.ID != orphan.ResourceID {
		return false, false, nil
	}
	active, err := r.linkedTunnel(ctx, tunnel.ID, tunnel.Name)
	if err != nil || active {
		return false, false, err
	}
	connections, err := s.cf.ListConnections(ctx, tunnel.ID)
	if errors.Is(err, ErrCFNotFound) {
		return false, true, nil
	}
	if err != nil || len(connections) > 0 {
		return false, false, err
	}
	if r.cfg.Mode == ReaperActive {
		err = ignoreMissing(s.cf.DeleteTunnel(ctx, tunnel.ID))
		if errors.Is(err, ErrCFTunnelInUse) {
			return false, false, nil
		}
	}
	return true, false, err
}

func (r *Reaper) orphanDNS(ctx context.Context, orphan Orphan, now time.Time) (remove, absent bool, err error) {
	s := r.service
	hostname, marker, ok := strings.Cut(orphan.Marker, "|")
	if !ok {
		return false, false, nil
	}
	records, err := s.cf.ListDNSRecords(ctx, hostname)
	if err != nil {
		return false, false, err
	}
	for _, record := range records {
		if record.ID != orphan.ResourceID {
			continue
		}
		id, epoch, owned := s.ownedDNS(record, hostname)
		label, domain, _ := strings.Cut(hostname, ".")
		if !owned || record.Comment != marker || domain != s.scope.BaseDomain || !tunnelLabelPattern.MatchString(label) {
			return false, false, nil
		}
		active, err := r.linkedTunnel(ctx, id, s.crypto.DeriveTunnelName(s.scope.Namespace, label, epoch))
		if err != nil || active {
			return false, false, err
		}
		tunnel, err := s.cf.GetTunnel(ctx, id)
		if !cfMissing(tunnel, err) {
			if err == nil && r.cfg.Mode == ReaperDryRun {
				parent, err := s.store.GetOrphan(ctx, s.scope.ID, "tunnel", id)
				if errors.Is(err, ErrNotFound) {
					return false, false, nil
				}
				if err != nil || !parent.ResolvedAt.IsZero() || parent.SeenCycles < 2 ||
					parent.FirstSeenAt.After(now.Add(-r.cfg.OrphanGrace)) || parent.NextAttemptAt.After(now) {
					return false, false, err
				}
				removable, _, err := r.orphanTunnel(ctx, parent)
				return removable, false, err
			}
			return false, false, err
		}
		if r.cfg.Mode == ReaperActive {
			err = ignoreMissing(s.cf.DeleteDNSRecord(ctx, record.ID))
			return true, false, err
		}
		return true, false, nil
	}
	return false, true, nil
}
