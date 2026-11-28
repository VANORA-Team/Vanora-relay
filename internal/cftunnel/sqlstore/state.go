package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"vanora-relay/internal/cftunnel"
)

func (s *Store) SetPresence(ctx context.Context, p cftunnel.Presence) error {
	if stamp(p.SeenAt) <= 0 || stamp(p.ExpiresAt) <= stamp(p.SeenAt) || p.Seq < 0 ||
		(p.Phase != cftunnel.PresenceStarting && p.Phase != cftunnel.PresenceListening && p.Phase != cftunnel.PresenceStopping) {
		return cftunnel.ErrInvalidClaim
	}
	return s.transact(ctx, func(tx *sql.Tx) error {
		a, err := s.getByID(ctx, tx, p.ScopeID, p.AllocationID, true)
		if err != nil {
			return err
		}
		if a.Generation != p.Generation {
			return cftunnel.ErrGenerationConflict
		}
		switch a.State {
		case cftunnel.StateReady, cftunnel.StatePending, cftunnel.StateReconciling:
		case cftunnel.StateReleased, cftunnel.StateSuspended, cftunnel.StateDisabled:
			p.CanRecover = false
		default:
			return cftunnel.ErrInvalidTransition
		}
		result, err := tx.ExecContext(ctx, s.bind(`INSERT INTO cf_presence
			(scope_id, allocation_id, generation, seen_at, expires_at, socket_id, runtime_id, phase, can_recover, seq)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (scope_id, allocation_id) DO UPDATE SET generation = excluded.generation,
				seen_at = excluded.seen_at, expires_at = excluded.expires_at, socket_id = excluded.socket_id,
				runtime_id = excluded.runtime_id, phase = excluded.phase, can_recover = excluded.can_recover, seq = excluded.seq
			WHERE (cf_presence.runtime_id = excluded.runtime_id AND excluded.seq > cf_presence.seq
				AND excluded.seen_at >= cf_presence.seen_at)
				OR (cf_presence.runtime_id <> excluded.runtime_id AND excluded.seen_at > cf_presence.seen_at)`),
			p.ScopeID, p.AllocationID, p.Generation, stamp(p.SeenAt), stamp(p.ExpiresAt), p.SocketID, p.RuntimeID,
			p.Phase, flag(p.CanRecover), p.Seq)
		if err != nil || !p.CanRecover {
			return err
		}
		accepted, err := result.RowsAffected()
		if err != nil || accepted == 0 {
			return err
		}
		return s.markRecoveryEnabled(ctx, tx, a.AllocationKey, a.Generation, p.SeenAt)
	})
}

func (s *Store) GetPresence(ctx context.Context, scopeID, allocationID string) (cftunnel.Presence, error) {
	return s.getPresence(ctx, s.db, scopeID, allocationID)
}

func (s *Store) getPresence(ctx context.Context, db queryRower, scopeID, allocationID string) (cftunnel.Presence, error) {
	p := cftunnel.Presence{ScopeID: scopeID, AllocationID: allocationID}
	var seen, expires int64
	var canRecover int
	err := db.QueryRowContext(ctx, s.bind(`SELECT p.generation, p.seen_at, p.expires_at, p.socket_id, p.runtime_id, p.phase, p.can_recover, p.seq
		FROM cf_presence p JOIN cf_allocation a
			ON a.scope_id = p.scope_id AND a.id = p.allocation_id AND a.generation = p.generation
		WHERE p.scope_id = ? AND p.allocation_id = ?`), scopeID, allocationID).
		Scan(&p.Generation, &seen, &expires, &p.SocketID, &p.RuntimeID, &p.Phase, &canRecover, &p.Seq)
	if err != nil {
		return cftunnel.Presence{}, notFound(err)
	}
	p.SeenAt, p.ExpiresAt = instant(seen), instant(expires)
	p.CanRecover = canRecover != 0
	return p, nil
}

func (s *Store) MarkRecoveryEnabled(ctx context.Context, key cftunnel.AllocationKey, generation int64, now time.Time) error {
	return s.transact(ctx, func(tx *sql.Tx) error {
		return s.markRecoveryEnabled(ctx, tx, key, generation, now)
	})
}

func (s *Store) markRecoveryEnabled(ctx context.Context, tx *sql.Tx, key cftunnel.AllocationKey, generation int64, now time.Time) error {
	if stamp(now) <= 0 {
		return cftunnel.ErrInvalidClaim
	}
	result, err := tx.ExecContext(ctx, s.bind(`UPDATE cf_allocation
		SET recovery_enabled_at = CASE WHEN recovery_enabled_at = 0 THEN ? ELSE recovery_enabled_at END
		WHERE scope_id = ? AND device_id = ? AND generation = ? AND state IN ('ready', 'pending', 'reconciling')`),
		stamp(now), key.ScopeID, key.DeviceID, generation)
	return affected(result, err, cftunnel.ErrGenerationConflict)
}

func (s *Store) ConsumeProof(ctx context.Context, proof cftunnel.ProofUse, now time.Time) error {
	return s.transact(ctx, func(tx *sql.Tx) error {
		if err := s.checkScope(ctx, tx, proof.ScopeID, false); err != nil {
			return err
		}
		return s.consumeProof(ctx, tx, proof, now)
	})
}

func (s *Store) consumeProof(ctx context.Context, tx *sql.Tx, proof cftunnel.ProofUse, now time.Time) error {
	now = s.now(now)
	expires := stamp(proof.ExpiresAt)
	if proof.Nonce == "" || stamp(now) <= 0 || expires <= stamp(now) {
		return cftunnel.ErrInvalidProof
	}
	result, err := tx.ExecContext(ctx, s.bind(`INSERT INTO cf_proof_use (scope_id, nonce, expires_at)
		VALUES (?, ?, ?) ON CONFLICT (scope_id, nonce) DO NOTHING`), proof.ScopeID, proof.Nonce, expires)
	return affected(result, err, cftunnel.ErrReplayDetected)
}

func (s *Store) LoadPause(ctx context.Context, scopeID, bucket string) (time.Time, error) {
	var until int64
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT until_at FROM cf_api_pause WHERE scope_id = ? AND bucket = ?`),
		scopeID, bucket).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return instant(until), err
}

func (s *Store) ExtendPause(ctx context.Context, scopeID, bucket string, until time.Time) error {
	if scopeID == "" || bucket == "" || stamp(until) <= 0 {
		return cftunnel.ErrInvalidClaim
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO cf_api_pause (scope_id, bucket, until_at) VALUES (?, ?, ?)
		ON CONFLICT (scope_id, bucket) DO UPDATE SET until_at = excluded.until_at
		WHERE cf_api_pause.until_at < excluded.until_at`), scopeID, bucket, stamp(until))
	return err
}

func (s *Store) ListReapCandidates(ctx context.Context, scopeID, afterID string, limit int) ([]cftunnel.ReapCandidate, error) {
	if limit < 1 {
		return nil, cftunnel.ErrInvalidClaim
	}
	columns := "a." + strings.ReplaceAll(strings.Join(strings.Fields(allocationColumns), " "), ", ", ", a.")
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+columns+`, p.seen_at, p.expires_at,
		p.socket_id, p.runtime_id, p.phase, p.can_recover, p.seq
		FROM cf_allocation a LEFT JOIN cf_presence p
			ON p.scope_id = a.scope_id AND p.allocation_id = a.id AND p.generation = a.generation
		WHERE a.scope_id = ? AND a.id > ? AND a.budget_held = 1 ORDER BY a.id LIMIT ?`), scopeID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []cftunnel.ReapCandidate
	for rows.Next() {
		var seen, expires sql.NullInt64
		var socket, runtime, phase sql.NullString
		var canRecover, seq sql.NullInt64
		a, err := scanAllocation(rows, &seen, &expires, &socket, &runtime, &phase, &canRecover, &seq)
		if err != nil {
			return nil, err
		}
		candidate := cftunnel.ReapCandidate{Allocation: a}
		if seen.Valid {
			candidate.Presence = &cftunnel.Presence{ScopeID: a.ScopeID, AllocationID: a.ID, Generation: a.Generation,
				SeenAt: instant(seen.Int64), ExpiresAt: instant(expires.Int64), SocketID: socket.String, RuntimeID: runtime.String,
				Phase: cftunnel.PresencePhase(phase.String), CanRecover: canRecover.Int64 != 0, Seq: seq.Int64}
		}
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

func (s *Store) UpdateCloudflareObservation(ctx context.Context, scopeID, allocationID string, observation cftunnel.CloudflareObservation) error {
	if stamp(observation.ObservedAt) <= 0 {
		return cftunnel.ErrInvalidClaim
	}
	return s.transact(ctx, func(tx *sql.Tx) error {
		a, err := s.getByID(ctx, tx, scopeID, allocationID, true)
		if err != nil {
			return err
		}
		if a.Generation != observation.Generation {
			return cftunnel.ErrGenerationConflict
		}
		if !a.BudgetHeld {
			return cftunnel.ErrInvalidTransition
		}
		if !observation.ObservedAt.After(a.Observation.ObservedAt) {
			return nil
		}
		since := a.CFStatusSince
		if observation.Status != a.CFStatus || since.IsZero() || observation.StatusSince.After(since) {
			since = observation.StatusSince
			if since.IsZero() {
				since = observation.ObservedAt
			}
		}
		if observation.Status == "" {
			since = time.Time{}
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE cf_allocation SET observed_at = ?, tunnel_exists = ?, dns_exists = ?,
			cf_status = ?, cf_status_since = ? WHERE scope_id = ? AND id = ?`), stamp(observation.ObservedAt),
			flag(observation.TunnelExists), flag(observation.DNSExists), observation.Status, stamp(since), scopeID, allocationID)
		return err
	})
}

func (s *Store) UpsertOrphan(ctx context.Context, o cftunnel.Orphan) error {
	if o.ScopeID == "" || o.Kind == "" || o.ResourceID == "" || o.Marker == "" || !o.ResolvedAt.IsZero() ||
		stamp(o.FirstSeenAt) <= 0 || o.LastSeenAt.Before(o.FirstSeenAt) || o.NextAttemptAt.Before(o.FirstSeenAt) || o.LastCycle < 0 {
		return cftunnel.ErrInvalidClaim
	}
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO cf_orphan
		(scope_id, kind, resource_id, marker, first_seen_at, last_seen_at, next_attempt_at, last_cycle)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (scope_id, kind, resource_id) DO UPDATE SET
			marker = excluded.marker,
			first_seen_at = CASE WHEN cf_orphan.resolved_at <> 0 OR cf_orphan.marker <> excluded.marker
				THEN excluded.first_seen_at ELSE cf_orphan.first_seen_at END,
			last_seen_at = excluded.last_seen_at,
			next_attempt_at = CASE WHEN cf_orphan.resolved_at <> 0 OR cf_orphan.marker <> excluded.marker
				THEN excluded.next_attempt_at ELSE cf_orphan.next_attempt_at END,
			seen_cycles = CASE WHEN cf_orphan.resolved_at <> 0 OR cf_orphan.marker <> excluded.marker
				THEN 1 WHEN cf_orphan.last_cycle < excluded.last_cycle THEN cf_orphan.seen_cycles + 1 ELSE cf_orphan.seen_cycles END,
			last_cycle = CASE WHEN cf_orphan.last_cycle < excluded.last_cycle THEN excluded.last_cycle ELSE cf_orphan.last_cycle END,
			resolved_at = 0
		WHERE cf_orphan.last_cycle <= excluded.last_cycle AND cf_orphan.last_seen_at <= excluded.last_seen_at
			AND cf_orphan.resolved_at < excluded.last_seen_at`),
		o.ScopeID, o.Kind, o.ResourceID, o.Marker, stamp(o.FirstSeenAt), stamp(o.LastSeenAt), stamp(o.NextAttemptAt), o.LastCycle)
	return err
}

func (s *Store) ListDueOrphans(ctx context.Context, scopeID string, now time.Time, limit int) ([]cftunnel.Orphan, error) {
	return s.ListDueOrphansAfter(ctx, scopeID, now, 0, "", "", limit)
}

func (s *Store) GetOrphan(ctx context.Context, scopeID, kind, resourceID string) (cftunnel.Orphan, error) {
	var resolved int64
	return scanOrphan(s.db.QueryRowContext(ctx, s.bind(`SELECT kind, resource_id, marker, first_seen_at, last_seen_at,
		next_attempt_at, seen_cycles, last_cycle, resolved_at FROM cf_orphan WHERE scope_id = ? AND kind = ? AND resource_id = ?`),
		scopeID, kind, resourceID), scopeID, &resolved)
}

func (s *Store) ListDueOrphansAfter(ctx context.Context, scopeID string, now time.Time, cycle int64, afterKind, afterID string, limit int) ([]cftunnel.Orphan, error) {
	if limit < 1 || stamp(now) <= 0 {
		return nil, cftunnel.ErrInvalidClaim
	}
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT kind, resource_id, marker, first_seen_at, last_seen_at, next_attempt_at, seen_cycles, last_cycle
		FROM cf_orphan WHERE scope_id = ? AND next_attempt_at <= ? AND resolved_at = 0 AND seen_cycles >= 2
		AND (? = 0 OR last_cycle <= ?) AND (? = '' OR kind < ? OR (kind = ? AND resource_id > ?))
		ORDER BY kind DESC, resource_id LIMIT ?`), scopeID, stamp(now), cycle, cycle, afterKind, afterKind, afterKind, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orphans []cftunnel.Orphan
	for rows.Next() {
		orphan, err := scanOrphan(rows, scopeID, nil)
		if err != nil {
			return nil, err
		}
		orphans = append(orphans, orphan)
	}
	return orphans, rows.Err()
}

func scanOrphan(row scanner, scopeID string, resolved *int64) (cftunnel.Orphan, error) {
	orphan := cftunnel.Orphan{ScopeID: scopeID}
	var first, last, next int64
	dest := []any{&orphan.Kind, &orphan.ResourceID, &orphan.Marker, &first, &last, &next, &orphan.SeenCycles, &orphan.LastCycle}
	if resolved != nil {
		dest = append(dest, resolved)
	}
	err := row.Scan(dest...)
	orphan.FirstSeenAt, orphan.LastSeenAt, orphan.NextAttemptAt = instant(first), instant(last), instant(next)
	if resolved != nil {
		orphan.ResolvedAt = instant(*resolved)
	}
	return orphan, notFound(err)
}

func (s *Store) ResolveOrphan(ctx context.Context, scopeID, kind, resourceID string, seenAt, now time.Time) error {
	if stamp(seenAt) <= 0 || now.Before(seenAt) {
		return cftunnel.ErrInvalidClaim
	}
	result, err := s.db.ExecContext(ctx, s.bind(`UPDATE cf_orphan SET resolved_at = ?
		WHERE scope_id = ? AND kind = ? AND resource_id = ? AND last_seen_at = ? AND resolved_at = 0`),
		stamp(now), scopeID, kind, resourceID, stamp(seenAt))
	return affected(result, err, cftunnel.ErrGenerationConflict)
}

func (s *Store) LoadScan(ctx context.Context, scopeID, kind string) (cftunnel.ScanCursor, error) {
	cursor := cftunnel.ScanCursor{ScopeID: scopeID, Kind: kind}
	var updated int64
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT cursor_value, updated_at, cycle FROM cf_scan WHERE scope_id = ? AND kind = ?`),
		scopeID, kind).Scan(&cursor.Cursor, &updated, &cursor.Cycle)
	if err != nil {
		return cftunnel.ScanCursor{}, notFound(err)
	}
	cursor.UpdatedAt = instant(updated)
	return cursor, nil
}

func (s *Store) SaveScan(ctx context.Context, cursor cftunnel.ScanCursor, previousUpdate time.Time) error {
	if cursor.ScopeID == "" || cursor.Kind == "" || !cursor.UpdatedAt.After(previousUpdate) || stamp(cursor.UpdatedAt) <= 0 {
		return cftunnel.ErrInvalidClaim
	}
	if previousUpdate.IsZero() {
		result, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO cf_scan
			(scope_id, kind, cursor_value, updated_at, cycle) VALUES (?, ?, ?, ?, ?) ON CONFLICT (scope_id, kind) DO NOTHING`),
			cursor.ScopeID, cursor.Kind, cursor.Cursor, stamp(cursor.UpdatedAt), cursor.Cycle)
		return affected(result, err, cftunnel.ErrGenerationConflict)
	}
	result, err := s.db.ExecContext(ctx, s.bind(`UPDATE cf_scan SET cursor_value = ?, updated_at = ?, cycle = ?
		WHERE scope_id = ? AND kind = ? AND updated_at = ?`), cursor.Cursor, stamp(cursor.UpdatedAt), cursor.Cycle,
		cursor.ScopeID, cursor.Kind, stamp(previousUpdate))
	return affected(result, err, cftunnel.ErrGenerationConflict)
}

func (s *Store) SetOwnerOverride(ctx context.Context, scopeID, ownerID string, override *cftunnel.OwnerOverride) error {
	if scopeID == "" || ownerID == "" {
		return cftunnel.ErrInvalidClaim
	}
	var slots, expires any
	if override != nil {
		if override.MaxTunnels < 0 || override.MaxTunnels > 10000 || stamp(override.ExpiresAt) < 0 {
			return cftunnel.ErrInvalidClaim
		}
		slots, expires = override.MaxTunnels, stamp(override.ExpiresAt)
	}
	return s.transact(ctx, func(tx *sql.Tx) error {
		if err := s.checkScope(ctx, tx, scopeID, false); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO cf_owner (scope_id, id, override_slots, override_expires_at)
			VALUES (?, ?, ?, ?) ON CONFLICT (scope_id, id) DO UPDATE SET override_slots = excluded.override_slots,
			override_expires_at = excluded.override_expires_at`), scopeID, ownerID, slots, expires)
		return err
	})
}

func (s *Store) GetOwnerOverride(ctx context.Context, scopeID, ownerID string) (*cftunnel.OwnerOverride, error) {
	return scanOverride(s.db.QueryRowContext(ctx, s.bind(`SELECT override_slots, override_expires_at
		FROM cf_owner WHERE scope_id = ? AND id = ?`), scopeID, ownerID))
}

func scanOverride(row scanner) (*cftunnel.OwnerOverride, error) {
	var slots, expires sql.NullInt64
	err := row.Scan(&slots, &expires)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !slots.Valid {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &cftunnel.OwnerOverride{MaxTunnels: int(slots.Int64), ExpiresAt: instant(expires.Int64)}, nil
}

func (s *Store) PruneExpired(ctx context.Context, scopeID string, now time.Time) error {
	if stamp(now) <= 0 {
		return cftunnel.ErrInvalidClaim
	}
	return s.transact(ctx, func(tx *sql.Tx) error {
		if err := s.checkScope(ctx, tx, scopeID, false); err != nil {
			return err
		}
		expiredRows := []string{
			`DELETE FROM cf_proof_use WHERE scope_id = ? AND expires_at <= ?`,
			`DELETE FROM cf_noop_request WHERE scope_id = ? AND expires_at <= ?`,
			`DELETE FROM cf_idempotency WHERE scope_id = ? AND expires_at <= ? AND EXISTS
				(SELECT 1 FROM cf_operation WHERE id = cf_idempotency.operation_id AND completed_at <> 0)`,
			`DELETE FROM cf_presence WHERE scope_id = ? AND expires_at <= ?`,
			`DELETE FROM cf_api_pause WHERE scope_id = ? AND until_at <= ?`,
		}
		for _, query := range expiredRows {
			if _, err := tx.ExecContext(ctx, s.bind(query), scopeID, stamp(now)); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM cf_operation WHERE scope_id = ? AND completed_at <> 0
			AND completed_at <= ? AND NOT EXISTS
				(SELECT 1 FROM cf_idempotency WHERE scope_id = cf_operation.scope_id AND operation_id = cf_operation.id)`),
			scopeID, stamp(now.Add(-24*time.Hour)))
		return err
	})
}
