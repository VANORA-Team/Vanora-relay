package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"time"

	"vanora-relay/internal/cftunnel"
)

const scopeColumns = `id, channel, ca_public_key_sha256, allowed_issuer, membership_origin, control_origin,
	account_id, zone_id, base_domain, namespace, master_key_sha256, unmanaged_count`

// EnsureScope persists the scope once, then checks its immutable coordinates.
func (s *Store) EnsureScope(ctx context.Context, scope cftunnel.Scope) error {
	return s.transact(ctx, func(tx *sql.Tx) error {
		stored, err := s.lockScopeConfig(ctx, tx, scope.ID)
		if errors.Is(err, sql.ErrNoRows) {
			_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO cf_scope (`+scopeColumns+`)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`),
				scope.ID, scope.Channel, scope.CAPublicKeySHA256, scope.AllowedIssuer, scope.MembershipOrigin,
				scope.ControlOrigin, scope.AccountID, scope.ZoneID, scope.BaseDomain, scope.Namespace,
				scope.MasterKeySHA256, scope.UnmanagedCount)
			if err != nil {
				return err
			}
			stored, err = s.lockScopeConfig(ctx, tx, scope.ID)
		}
		stored.UnmanagedCount = scope.UnmanagedCount
		if errors.Is(err, sql.ErrNoRows) || err == nil && stored != scope {
			return cftunnel.ErrScopeMismatch
		}
		return err
	})
}

func (s *Store) lockScopeConfig(ctx context.Context, tx *sql.Tx, scopeID string) (cftunnel.Scope, error) {
	var scope cftunnel.Scope
	err := tx.QueryRowContext(ctx, s.bind(s.forUpdate("SELECT "+scopeColumns+" FROM cf_scope WHERE id = ?")), scopeID).
		Scan(&scope.ID, &scope.Channel, &scope.CAPublicKeySHA256, &scope.AllowedIssuer, &scope.MembershipOrigin,
			&scope.ControlOrigin, &scope.AccountID, &scope.ZoneID, &scope.BaseDomain, &scope.Namespace,
			&scope.MasterKeySHA256, &scope.UnmanagedCount)
	return scope, err
}

func (s *Store) checkScope(ctx context.Context, tx *sql.Tx, scopeID string, lock bool) error {
	query := "SELECT id FROM cf_scope WHERE id = ?"
	if lock && s.postgres {
		query += " FOR NO KEY UPDATE"
	}
	var id string
	return notFound(tx.QueryRowContext(ctx, s.bind(query), scopeID).Scan(&id))
}

func (s *Store) lockOwner(ctx context.Context, tx *sql.Tx, scopeID, ownerID string) (*cftunnel.OwnerOverride, error) {
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO cf_owner (scope_id, id) VALUES (?, ?)
		ON CONFLICT (scope_id, id) DO NOTHING`), scopeID, ownerID)
	if err != nil {
		return nil, err
	}
	return scanOverride(tx.QueryRowContext(ctx, s.bind(s.forUpdate(`SELECT override_slots, override_expires_at
		FROM cf_owner WHERE scope_id = ? AND id = ?`)), scopeID, ownerID))
}

const allocationColumns = `scope_id, id, device_id, owner_id, device_key_hash, generation, incarnation,
	state, origin, hostname, tunnel_name, tunnel_id, dns_record_id, budget_held, manual_resume_required,
	observed_at, tunnel_exists, dns_exists, updated_at, ready_at, recovery_enabled_at, released_at, cf_status, cf_status_since`

func scanAllocation(row scanner, extra ...any) (cftunnel.Allocation, error) {
	var a cftunnel.Allocation
	var held, manual, tunnelExists, dnsExists int
	var observed, updated, ready, recovery, released, since int64
	fields := []any{&a.ScopeID, &a.ID, &a.DeviceID, &a.OwnerID, &a.DeviceKeyHash, &a.Generation, &a.Incarnation,
		&a.State, &a.Origin, &a.Hostname, &a.TunnelName, &a.Resources.TunnelID, &a.Resources.DNSRecordID, &held, &manual,
		&observed, &tunnelExists, &dnsExists, &updated, &ready, &recovery, &released, &a.CFStatus, &since}
	err := row.Scan(append(fields, extra...)...)
	a.BudgetHeld, a.ManualResumeRequired = held != 0, manual != 0
	a.UpdatedAt = instant(updated)
	a.ReadyAt, a.RecoveryEnabledAt, a.ReleasedAt, a.CFStatusSince = instant(ready), instant(recovery), instant(released), instant(since)
	if observed != 0 {
		a.Observation = cftunnel.CloudflareObservation{
			Generation: a.Generation, ObservedAt: instant(observed), TunnelExists: tunnelExists != 0, DNSExists: dnsExists != 0,
			Status: a.CFStatus, StatusSince: a.CFStatusSince,
		}
	}
	return a, notFound(err)
}

func (s *Store) Get(ctx context.Context, key cftunnel.AllocationKey) (cftunnel.Allocation, error) {
	return s.get(ctx, s.db, key, false)
}

func (s *Store) get(ctx context.Context, db queryRower, key cftunnel.AllocationKey, lock bool) (cftunnel.Allocation, error) {
	query := "SELECT " + allocationColumns + " FROM cf_allocation WHERE scope_id = ? AND device_id = ?"
	if lock {
		query = s.forUpdate(query)
	}
	return scanAllocation(db.QueryRowContext(ctx, s.bind(query), key.ScopeID, key.DeviceID))
}

func (s *Store) GetByAllocationID(ctx context.Context, scopeID, allocationID string) (cftunnel.Allocation, error) {
	return s.getByID(ctx, s.db, scopeID, allocationID, false)
}

func (s *Store) GetByTunnelName(ctx context.Context, scopeID, tunnelName string) (cftunnel.Allocation, error) {
	return scanAllocation(s.db.QueryRowContext(ctx, s.bind("SELECT "+allocationColumns+
		" FROM cf_allocation WHERE scope_id = ? AND tunnel_name = ? AND budget_held = 1"), scopeID, tunnelName))
}

func (s *Store) GetByTunnelID(ctx context.Context, scopeID, tunnelID string) (cftunnel.Allocation, error) {
	return scanAllocation(s.db.QueryRowContext(ctx, s.bind("SELECT "+allocationColumns+
		" FROM cf_allocation WHERE scope_id = ? AND tunnel_id = ? AND budget_held = 1"), scopeID, tunnelID))
}

func (s *Store) UpdateUnmanagedCount(ctx context.Context, scopeID string, count int) error {
	result, err := s.db.ExecContext(ctx, s.bind("UPDATE cf_scope SET unmanaged_count = ? WHERE id = ?"), count, scopeID)
	return affected(result, err, cftunnel.ErrNotFound)
}

func (s *Store) getByID(ctx context.Context, db queryRower, scopeID, allocationID string, lock bool) (cftunnel.Allocation, error) {
	query := "SELECT " + allocationColumns + " FROM cf_allocation WHERE scope_id = ? AND id = ?"
	if lock {
		query = s.forUpdate(query)
	}
	return scanAllocation(db.QueryRowContext(ctx, s.bind(query), scopeID, allocationID))
}

func (s *Store) Claim(ctx context.Context, command cftunnel.ClaimCommand, policy cftunnel.ClaimPolicy) (cftunnel.Operation, error) {
	if command.ScopeID == "" || command.DeviceID == "" || command.OwnerID == "" || command.DeviceKeyHash == "" ||
		command.IfGeneration < 0 || stamp(command.Now) <= 0 || command.IdempotencyTTL < 0 ||
		(command.IdempotencyKey == "") != (command.BodyHash == "") || policy.OwnerSlots < 0 || policy.AccountCap < 0 {
		return cftunnel.Operation{}, cftunnel.ErrInvalidClaim
	}
	var op cftunnel.Operation
	if s.postgres && strings.ContainsRune(command.IdempotencyKey, 0) {
		command.IdempotencyKey = "\x01" + base64.RawURLEncoding.EncodeToString([]byte(command.IdempotencyKey))
	}
	err := s.transact(ctx, func(tx *sql.Tx) error {
		var err error
		op, err = s.claim(ctx, tx, command, policy)
		return err
	})
	if err != nil {
		return cftunnel.Operation{}, err
	}
	return op, nil
}

func (s *Store) claim(ctx context.Context, tx *sql.Tx, cmd cftunnel.ClaimCommand, policy cftunnel.ClaimPolicy) (cftunnel.Operation, error) {
	var op cftunnel.Operation
	budgetClaim := cmd.Type == cftunnel.OpProvision || cmd.Type == cftunnel.OpRecover || cmd.Type == cftunnel.OpResume
	if err := s.checkScope(ctx, tx, cmd.ScopeID, budgetClaim); err != nil {
		return op, err
	}
	override, err := s.lockOwner(ctx, tx, cmd.ScopeID, cmd.OwnerID)
	if err != nil {
		return op, err
	}
	cmd.Now = s.now(cmd.Now)
	if cmd.Proof != nil {
		if cmd.Proof.ScopeID != cmd.ScopeID {
			return op, cftunnel.ErrScopeMismatch
		}
		if err := s.consumeProof(ctx, tx, *cmd.Proof, cmd.Now); err != nil {
			return op, err
		}
	}
	if cmd.IdempotencyKey != "" {
		op, err = s.existingClaim(ctx, tx, cmd)
		if !errors.Is(err, cftunnel.ErrNotFound) {
			return op, err
		}
	}
	current, err := s.get(ctx, tx, cmd.AllocationKey, true)
	if err != nil && !errors.Is(err, cftunnel.ErrNotFound) {
		return op, err
	}
	initialRetry := cmd.IfGeneration == 0 && cmd.Type == cftunnel.OpProvision && current.ID != ""
	if current.Generation != cmd.IfGeneration && !initialRetry {
		return op, cftunnel.ErrGenerationConflict
	}
	if current.ID != "" {
		if current.OwnerID != cmd.OwnerID || current.DeviceKeyHash != cmd.DeviceKeyHash {
			return op, cftunnel.ErrDeviceBinding
		}
		var existing string
		err = tx.QueryRowContext(ctx, s.bind(s.forUpdate(`SELECT id FROM cf_operation
			WHERE scope_id = ? AND allocation_id = ? AND completed_at = 0`)), cmd.ScopeID, current.ID).Scan(&existing)
		if !errors.Is(err, sql.ErrNoRows) {
			if err == nil {
				err = cftunnel.OperationInProgressError{OperationID: existing}
			}
			return op, err
		}
	}
	if initialRetry {
		return op, cftunnel.ErrGenerationConflict
	}
	if cmd.AllowNoop && isNoop(current, cmd) {
		switch cmd.Type {
		case cftunnel.OpProvision, cftunnel.OpReconcile, cftunnel.OpRecover, cftunnel.OpResume:
			if cftunnel.ApplyOwnerOverride(policy.OwnerSlots, cmd.Now, override) <= 0 {
				return op, cftunnel.ErrOwnerQuotaExhausted
			}
		}
		if cmd.IdempotencyKey != "" {
			_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO cf_noop_request
				(scope_id, owner_id, request_key, body_hash, allocation_id, generation, expires_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`), cmd.ScopeID, cmd.OwnerID, cmd.IdempotencyKey, cmd.BodyHash,
				current.ID, current.Generation, stamp(cmd.Now.Add(idempotencyLifetime(cmd))))
			if err != nil {
				return op, err
			}
		}
		return noopOperation(cmd, current.ID, current.Generation), nil
	}
	next, err := claimTransition(current, cmd)
	if err != nil {
		return op, err
	}
	if cmd.Type == cftunnel.OpRelease && cmd.ProtectPresence {
		presence, err := s.getPresence(ctx, tx, current.ScopeID, current.ID)
		if err != nil && !errors.Is(err, cftunnel.ErrNotFound) {
			return op, err
		}
		if presence.Active(cmd.Now) {
			return op, cftunnel.ErrPresenceActive
		}
	}
	if next.BudgetHeld && !current.BudgetHeld {
		if !budgetClaim {
			return op, cftunnel.ErrInvalidTransition
		}
		if err := s.checkCapacity(ctx, tx, cmd, policy, override); err != nil {
			return op, err
		}
	}
	if current.BudgetHeld && (cmd.Type == cftunnel.OpResume || cmd.Type == cftunnel.OpReconcile) &&
		cftunnel.ApplyOwnerOverride(policy.OwnerSlots, cmd.Now, override) <= 0 {
		return op, cftunnel.ErrOwnerQuotaExhausted
	}
	if err := s.saveAllocation(ctx, tx, next); err != nil {
		return op, err
	}
	presenceQuery := `DELETE FROM cf_presence WHERE generation < ? AND scope_id = ? AND allocation_id = ?`
	if cmd.Type == cftunnel.OpRelease {
		presenceQuery = `UPDATE cf_presence SET generation = ? WHERE scope_id = ? AND allocation_id = ?`
	}
	if _, err := tx.ExecContext(ctx, s.bind(presenceQuery), next.Generation, next.ScopeID, next.ID); err != nil {
		return op, err
	}
	return s.recordClaim(ctx, tx, cmd, current, next, cmd.Type == cftunnel.OpDeprovision && !next.BudgetHeld)
}

func isNoop(a cftunnel.Allocation, cmd cftunnel.ClaimCommand) bool {
	switch cmd.Type {
	case cftunnel.OpProvision, cftunnel.OpReconcile, cftunnel.OpRecover, cftunnel.OpResume:
		return a.State == cftunnel.StateReady && !a.ManualResumeRequired && a.Origin == cmd.Origin
	case cftunnel.OpRelease:
		return a.State == cftunnel.StateReleased
	case cftunnel.OpDisconnect:
		return a.State == cftunnel.StateSuspended
	case cftunnel.OpDeprovision:
		return a.State == cftunnel.StateDisabled
	default:
		return false
	}
}

func (s *Store) recordClaim(ctx context.Context, tx *sql.Tx, cmd cftunnel.ClaimCommand, current, next cftunnel.Allocation, completed bool) (cftunnel.Operation, error) {
	op := cftunnel.Operation{
		ID: rand.Text(), ScopeID: next.ScopeID, AllocationID: next.ID,
		Type: cmd.Type, Generation: next.Generation, CreatedAt: cmd.Now.UTC(),
		PreviousState: current.State, PreviousManualResume: current.ManualResumeRequired,
		ProtectPresence: cmd.ProtectPresence, CanRecover: cmd.CanRecover,
	}
	if completed {
		op.CompletedAt = op.CreatedAt
	}
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO cf_operation
		(id, scope_id, allocation_id, operation_type, generation, created_at, completed_at, previous_state, previous_manual_resume, protect_presence, can_recover)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		op.ID, op.ScopeID, op.AllocationID, op.Type, op.Generation, stamp(op.CreatedAt), stamp(op.CompletedAt), op.PreviousState,
		flag(op.PreviousManualResume), flag(op.ProtectPresence), flag(op.CanRecover))
	if err != nil {
		return op, err
	}
	if cmd.IdempotencyKey != "" {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO cf_idempotency
			(scope_id, owner_id, request_key, body_hash, operation_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)`),
			cmd.ScopeID, cmd.OwnerID, cmd.IdempotencyKey, cmd.BodyHash, op.ID, stamp(cmd.Now.Add(idempotencyLifetime(cmd))))
	}
	return op, err
}

func idempotencyLifetime(cmd cftunnel.ClaimCommand) time.Duration {
	if cmd.IdempotencyTTL == 0 {
		return 24 * time.Hour
	}
	return cmd.IdempotencyTTL
}

func noopOperation(cmd cftunnel.ClaimCommand, allocationID string, generation int64) cftunnel.Operation {
	return cftunnel.Operation{ScopeID: cmd.ScopeID, AllocationID: allocationID, Generation: generation,
		Type: cmd.Type, CreatedAt: cmd.Now.UTC(), CompletedAt: cmd.Now.UTC()}
}

func (s *Store) existingClaim(ctx context.Context, tx *sql.Tx, cmd cftunnel.ClaimCommand) (cftunnel.Operation, error) {
	var op cftunnel.Operation
	var bodyHash, operationID string
	var expires, completed int64
	err := tx.QueryRowContext(ctx, s.bind(`SELECT idem.body_hash, idem.operation_id, idem.expires_at, op.completed_at
		FROM cf_idempotency idem JOIN cf_operation op ON op.scope_id = idem.scope_id AND op.id = idem.operation_id
		WHERE idem.scope_id = ? AND idem.owner_id = ? AND idem.request_key = ?`),
		cmd.ScopeID, cmd.OwnerID, cmd.IdempotencyKey).Scan(&bodyHash, &operationID, &expires, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return s.existingNoop(ctx, tx, cmd)
	}
	if err != nil {
		return op, notFound(err)
	}
	if expires <= stamp(cmd.Now) && completed != 0 {
		_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM cf_idempotency WHERE scope_id = ? AND owner_id = ? AND request_key = ?`),
			cmd.ScopeID, cmd.OwnerID, cmd.IdempotencyKey)
		if err != nil {
			return op, err
		}
		return op, cftunnel.ErrNotFound
	}
	if bodyHash != cmd.BodyHash {
		return op, cftunnel.ErrIdempotencyConflict
	}
	op, err = s.getOperation(ctx, tx, cmd.ScopeID, operationID, false)
	if err != nil {
		return op, err
	}
	allocation, err := s.getByID(ctx, tx, cmd.ScopeID, op.AllocationID, false)
	if err != nil {
		return op, err
	}
	if allocation.DeviceID != cmd.DeviceID || allocation.OwnerID != cmd.OwnerID || allocation.DeviceKeyHash != cmd.DeviceKeyHash {
		return op, cftunnel.ErrDeviceBinding
	}
	return op, nil
}

func (s *Store) existingNoop(ctx context.Context, tx *sql.Tx, cmd cftunnel.ClaimCommand) (cftunnel.Operation, error) {
	var allocationID, bodyHash, deviceID, keyHash string
	var generation, expires int64
	err := tx.QueryRowContext(ctx, s.bind(`SELECT n.allocation_id, n.body_hash, n.generation, n.expires_at, a.device_id, a.device_key_hash
		FROM cf_noop_request n JOIN cf_allocation a ON a.scope_id = n.scope_id AND a.id = n.allocation_id
		WHERE n.scope_id = ? AND n.owner_id = ? AND n.request_key = ?`),
		cmd.ScopeID, cmd.OwnerID, cmd.IdempotencyKey).Scan(&allocationID, &bodyHash, &generation, &expires, &deviceID, &keyHash)
	if err != nil {
		return cftunnel.Operation{}, notFound(err)
	}
	if expires <= stamp(cmd.Now) {
		_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM cf_noop_request WHERE scope_id = ? AND owner_id = ? AND request_key = ?`),
			cmd.ScopeID, cmd.OwnerID, cmd.IdempotencyKey)
		if err != nil {
			return cftunnel.Operation{}, err
		}
		return cftunnel.Operation{}, cftunnel.ErrNotFound
	}
	if bodyHash != cmd.BodyHash {
		return cftunnel.Operation{}, cftunnel.ErrIdempotencyConflict
	}
	if deviceID != cmd.DeviceID || keyHash != cmd.DeviceKeyHash {
		return cftunnel.Operation{}, cftunnel.ErrDeviceBinding
	}
	return noopOperation(cmd, allocationID, generation), nil
}

func claimTransition(current cftunnel.Allocation, cmd cftunnel.ClaimCommand) (cftunnel.Allocation, error) {
	if current.Generation == math.MaxInt64 {
		return current, cftunnel.ErrGenerationConflict
	}
	next := current
	switch cmd.Type {
	case cftunnel.OpProvision:
		if current.State == cftunnel.StateReleased {
			return current, cftunnel.ErrRecoveryRequired
		}
		if current.State != "" && current.State != cftunnel.StateDisabled {
			return current, cftunnel.ErrInvalidTransition
		}
		next.State = cftunnel.StatePending
		next.ManualResumeRequired = false
	case cftunnel.OpRecover:
		if current.State == cftunnel.StateDisabled {
			return current, cftunnel.ErrInvalidTransition
		}
		if current.ManualResumeRequired {
			return current, cftunnel.ErrTunnelSuspended
		}
		if current.State != cftunnel.StateReleased {
			return current, cftunnel.ErrInvalidTransition
		}
		next.State = cftunnel.StatePending
	case cftunnel.OpResume:
		if !current.ManualResumeRequired || current.State != cftunnel.StateSuspended && current.State != cftunnel.StateReleased {
			return current, cftunnel.ErrInvalidTransition
		}
		next.State = cftunnel.StatePending
		if current.BudgetHeld {
			next.State = cftunnel.StateReconciling
		}
		next.ManualResumeRequired = false
	case cftunnel.OpReconcile, cftunnel.OpRepair:
		if current.State != cftunnel.StateReady && !(cmd.Type == cftunnel.OpRepair && current.State == cftunnel.StateQuarantined) {
			return current, cftunnel.ErrInvalidTransition
		}
		if !current.ManualResumeRequired {
			next.State = cftunnel.StateReconciling
		}
	case cftunnel.OpRelease:
		if current.State != cftunnel.StateReady && current.State != cftunnel.StateSuspended {
			return current, cftunnel.ErrInvalidTransition
		}
		next.State = cftunnel.StateReleasing
	case cftunnel.OpDisconnect:
		if current.State != cftunnel.StateReady {
			return current, cftunnel.ErrInvalidTransition
		}
		next.State = cftunnel.StateDisconnecting
		next.ManualResumeRequired = true
	case cftunnel.OpDeprovision:
		if !current.BudgetHeld {
			if current.State != cftunnel.StateReleased {
				return current, cftunnel.ErrInvalidTransition
			}
			next.State, next.Generation, next.UpdatedAt = cftunnel.StateDisabled, next.Generation+1, cmd.Now
			next.RecoveryEnabledAt = time.Time{}
			return next, nil
		}
		next.State = cftunnel.StateDeprovisioning
	default:
		return current, cftunnel.ErrInvalidClaim
	}
	if current.ID == "" {
		next.ID = rand.Text()
		next.AllocationKey = cmd.AllocationKey
		next.OwnerID = cmd.OwnerID
		next.DeviceKeyHash = cmd.DeviceKeyHash
	}
	if !current.BudgetHeld {
		if cmd.Hostname == "" || cmd.TunnelName == "" || cmd.Origin == "" {
			return current, cftunnel.ErrInvalidClaim
		}
		next.Hostname, next.TunnelName = cmd.Hostname, cmd.TunnelName
		next.Incarnation++
		next.ReadyAt, next.ReleasedAt, next.CFStatusSince = time.Time{}, time.Time{}, time.Time{}
		next.CFStatus = ""
	} else if cmd.Hostname != "" && cmd.Hostname != current.Hostname || cmd.TunnelName != "" && cmd.TunnelName != current.TunnelName {
		return current, cftunnel.ErrInvalidClaim
	}
	if cmd.Origin != "" {
		origin, err := cftunnel.ParseOrigin(cmd.Origin.String())
		if err != nil {
			return current, err
		}
		next.Origin = origin
	}
	next.Generation++
	next.BudgetHeld = true
	next.Observation = cftunnel.CloudflareObservation{}
	next.UpdatedAt = cmd.Now
	return next, nil
}

func (s *Store) checkCapacity(ctx context.Context, tx *sql.Tx, cmd cftunnel.ClaimCommand, policy cftunnel.ClaimPolicy, override *cftunnel.OwnerOverride) error {
	counts, err := s.countSlots(ctx, tx, cmd.ScopeID, cmd.OwnerID)
	if err != nil {
		return err
	}
	ownerSlots := cftunnel.ApplyOwnerOverride(policy.OwnerSlots, cmd.Now, override)
	if counts.OwnerHeld >= ownerSlots {
		return cftunnel.ErrOwnerQuotaExhausted
	}
	if counts.UnmanagedCount >= policy.AccountCap || counts.ScopeHeld >= policy.AccountCap-counts.UnmanagedCount {
		return cftunnel.ErrAccountCapacity
	}
	return nil
}

func (s *Store) CountSlots(ctx context.Context, scopeID, ownerID string) (cftunnel.SlotCounts, error) {
	return s.countSlots(ctx, s.db, scopeID, ownerID)
}

func (s *Store) countSlots(ctx context.Context, query queryRower, scopeID, ownerID string) (cftunnel.SlotCounts, error) {
	var counts cftunnel.SlotCounts
	err := query.QueryRowContext(ctx, s.bind(`SELECT
		(SELECT COUNT(*) FROM cf_allocation WHERE scope_id = scope.id AND owner_id = ? AND budget_held = 1),
		(SELECT COUNT(*) FROM cf_allocation WHERE scope_id = scope.id AND budget_held = 1),
		scope.unmanaged_count FROM cf_scope scope WHERE scope.id = ?`), ownerID, scopeID).
		Scan(&counts.OwnerHeld, &counts.ScopeHeld, &counts.UnmanagedCount)
	return counts, notFound(err)
}

func (s *Store) saveAllocation(ctx context.Context, tx *sql.Tx, a cftunnel.Allocation) error {
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO cf_allocation (`+allocationColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (scope_id, id) DO UPDATE SET generation = excluded.generation, incarnation = excluded.incarnation,
		state = excluded.state, origin = excluded.origin, hostname = excluded.hostname, tunnel_name = excluded.tunnel_name,
		tunnel_id = excluded.tunnel_id, dns_record_id = excluded.dns_record_id, budget_held = excluded.budget_held,
		manual_resume_required = excluded.manual_resume_required, observed_at = excluded.observed_at,
		tunnel_exists = excluded.tunnel_exists, dns_exists = excluded.dns_exists, updated_at = excluded.updated_at,
		ready_at = excluded.ready_at, recovery_enabled_at = excluded.recovery_enabled_at,
		released_at = excluded.released_at, cf_status = excluded.cf_status, cf_status_since = excluded.cf_status_since`),
		a.ScopeID, a.ID, a.DeviceID, a.OwnerID, a.DeviceKeyHash, a.Generation, a.Incarnation, a.State, a.Origin,
		a.Hostname, a.TunnelName, a.Resources.TunnelID, a.Resources.DNSRecordID, flag(a.BudgetHeld), flag(a.ManualResumeRequired),
		stamp(a.Observation.ObservedAt), flag(a.Observation.TunnelExists), flag(a.Observation.DNSExists), stamp(a.UpdatedAt),
		stamp(a.ReadyAt), stamp(a.RecoveryEnabledAt), stamp(a.ReleasedAt), a.CFStatus, stamp(a.CFStatusSince))
	return err
}
