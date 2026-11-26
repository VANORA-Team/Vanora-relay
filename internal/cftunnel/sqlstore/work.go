package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"vanora-relay/internal/cftunnel"
)

const operationColumns = `id, scope_id, allocation_id, operation_type, generation, worker_id, worker_epoch,
	lease_until, created_at, completed_at, next_attempt_at, attempts, error_code, previous_state,
	previous_manual_resume, protect_presence, can_recover`

func scanOperation(row scanner) (cftunnel.Operation, error) {
	var op cftunnel.Operation
	var lease, created, completed, next int64
	var previousManual, protect, recoverable int
	err := row.Scan(&op.ID, &op.ScopeID, &op.AllocationID, &op.Type, &op.Generation, &op.WorkerID, &op.WorkerEpoch,
		&lease, &created, &completed, &next, &op.Attempts, &op.ErrorCode, &op.PreviousState, &previousManual, &protect, &recoverable)
	op.LeaseUntil, op.CreatedAt, op.CompletedAt = instant(lease), instant(created), instant(completed)
	op.NextAttemptAt = instant(next)
	op.PreviousManualResume, op.ProtectPresence, op.CanRecover = previousManual != 0, protect != 0, recoverable != 0
	return op, notFound(err)
}

func (s *Store) getOperation(ctx context.Context, db queryRower, scopeID, operationID string, lock bool) (cftunnel.Operation, error) {
	query := "SELECT " + operationColumns + " FROM cf_operation WHERE scope_id = ? AND id = ?"
	if lock {
		query = s.forUpdate(query)
	}
	return scanOperation(db.QueryRowContext(ctx, s.bind(query), scopeID, operationID))
}

func (s *Store) GetOperation(ctx context.Context, scopeID, operationID string) (cftunnel.Operation, error) {
	return s.getOperation(ctx, s.db, scopeID, operationID, false)
}

func (s *Store) AcquireWork(ctx context.Context, scopeID, workerID string, now time.Time, lease time.Duration) (cftunnel.Operation, error) {
	if scopeID == "" || workerID == "" || stamp(now) <= 0 || stamp(now.Add(lease)) <= stamp(now) {
		return cftunnel.Operation{}, cftunnel.ErrInvalidClaim
	}
	var op cftunnel.Operation
	err := s.transact(ctx, func(tx *sql.Tx) error {
		now = s.now(now)
		query := `SELECT ` + operationColumns + ` FROM cf_operation op
			WHERE scope_id = ? AND completed_at = 0 AND lease_until <= ? AND created_at <= ? AND next_attempt_at <= ?
			AND EXISTS (SELECT 1 FROM cf_allocation a WHERE a.scope_id = op.scope_id
				AND a.id = op.allocation_id AND a.generation = op.generation)
			ORDER BY created_at, id LIMIT 1`
		if s.postgres {
			query += " FOR UPDATE SKIP LOCKED"
		}
		var err error
		op, err = scanOperation(tx.QueryRowContext(ctx, s.bind(query), scopeID, stamp(now), stamp(now), stamp(now)))
		if err != nil {
			return err
		}
		op.WorkerID, op.WorkerEpoch, op.LeaseUntil = workerID, op.WorkerEpoch+1, now.Add(lease).UTC()
		op.Attempts++
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE cf_operation SET worker_id = ?, worker_epoch = ?, lease_until = ?, attempts = ?
			WHERE scope_id = ? AND id = ?`), op.WorkerID, op.WorkerEpoch, stamp(op.LeaseUntil), op.Attempts, op.ScopeID, op.ID)
		return err
	})
	if err != nil {
		return cftunnel.Operation{}, err
	}
	return op, nil
}

func (s *Store) ReleaseWork(ctx context.Context, fence cftunnel.Fence, now, nextAttemptAt time.Time, code cftunnel.ErrorCode) error {
	return s.transact(ctx, func(tx *sql.Tx) error {
		if _, _, err := s.fencedAllocation(ctx, tx, fence, now); err != nil {
			return err
		}
		if !nextAttemptAt.After(s.now(now)) {
			return cftunnel.ErrInvalidClaim
		}
		_, err := tx.ExecContext(ctx, s.bind(`UPDATE cf_operation SET lease_until = 0, next_attempt_at = ?, error_code = ?
			WHERE scope_id = ? AND id = ?`), stamp(nextAttemptAt), code, fence.ScopeID, fence.OperationID)
		return err
	})
}

func (s *Store) fencedAllocation(ctx context.Context, tx *sql.Tx, fence cftunnel.Fence, now time.Time) (cftunnel.Allocation, cftunnel.Operation, error) {
	if stamp(now) <= 0 || fence.WorkerEpoch < 1 || fence.Generation < 1 {
		return cftunnel.Allocation{}, cftunnel.Operation{}, cftunnel.ErrFenceLost
	}
	a, err := s.getByID(ctx, tx, fence.ScopeID, fence.AllocationID, true)
	if errors.Is(err, cftunnel.ErrNotFound) || err == nil && a.Generation != fence.Generation {
		return a, cftunnel.Operation{}, cftunnel.ErrFenceLost
	}
	if err != nil {
		return a, cftunnel.Operation{}, err
	}
	op, err := s.getOperation(ctx, tx, fence.ScopeID, fence.OperationID, true)
	now = s.now(now)
	if errors.Is(err, cftunnel.ErrNotFound) || err == nil &&
		(op.Fence() != fence || !op.CompletedAt.IsZero() || !op.LeaseUntil.After(now) || now.Before(op.CreatedAt)) {
		return a, op, cftunnel.ErrFenceLost
	}
	return a, op, err
}

func (s *Store) RenewWork(ctx context.Context, fence cftunnel.Fence, now time.Time, lease time.Duration) error {
	until := stamp(now.Add(lease))
	if until <= stamp(now) {
		return cftunnel.ErrInvalidClaim
	}
	return s.transact(ctx, func(tx *sql.Tx) error {
		_, op, err := s.fencedAllocation(ctx, tx, fence, now)
		if err != nil {
			return err
		}
		until = stamp(s.now(now).Add(lease))
		if until <= stamp(op.LeaseUntil) {
			return nil
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE cf_operation SET lease_until = ? WHERE scope_id = ? AND id = ?`),
			until, fence.ScopeID, fence.OperationID)
		return err
	})
}

func (s *Store) BeginStep(ctx context.Context, fence cftunnel.Fence, name string, now time.Time) (cftunnel.Step, error) {
	if name == "" {
		return cftunnel.Step{}, cftunnel.ErrInvalidClaim
	}
	var step cftunnel.Step
	err := s.transact(ctx, func(tx *sql.Tx) error {
		if _, _, err := s.fencedAllocation(ctx, tx, fence, now); err != nil {
			return err
		}
		previous, err := s.getStep(ctx, tx, fence.OperationID, name)
		if err != nil && !errors.Is(err, cftunnel.ErrNotFound) {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO cf_step (operation_id, name, worker_epoch, started_at)
			VALUES (?, ?, ?, ?) ON CONFLICT (operation_id, name) DO UPDATE SET
			worker_epoch = excluded.worker_epoch, started_at = excluded.started_at
			WHERE cf_step.finished_at = 0 AND cf_step.worker_epoch < excluded.worker_epoch`),
			fence.OperationID, name, fence.WorkerEpoch, stamp(now))
		if err != nil {
			return err
		}
		step, err = s.getStep(ctx, tx, fence.OperationID, name)
		step.Retry = previous.WorkerEpoch > 0 && previous.WorkerEpoch < fence.WorkerEpoch && previous.FinishedAt.IsZero()
		return err
	})
	if err != nil {
		return cftunnel.Step{}, err
	}
	return step, nil
}

func (s *Store) GetStep(ctx context.Context, operationID, name string) (cftunnel.Step, error) {
	return s.getStep(ctx, s.db, operationID, name)
}

func (s *Store) getStep(ctx context.Context, db queryRower, operationID, name string) (cftunnel.Step, error) {
	var step cftunnel.Step
	var started, finished int64
	err := db.QueryRowContext(ctx, s.bind(`SELECT operation_id, name, worker_epoch, started_at, finished_at, result
		FROM cf_step WHERE operation_id = ? AND name = ?`), operationID, name).
		Scan(&step.OperationID, &step.Name, &step.WorkerEpoch, &started, &finished, &step.Result)
	step.StartedAt, step.FinishedAt = instant(started), instant(finished)
	return step, notFound(err)
}

func (s *Store) DiscardStep(ctx context.Context, fence cftunnel.Fence, name string, now time.Time) error {
	return s.transact(ctx, func(tx *sql.Tx) error {
		if _, _, err := s.fencedAllocation(ctx, tx, fence, now); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM cf_step
			WHERE operation_id = ? AND name = ? AND worker_epoch = ? AND finished_at = 0`), fence.OperationID, name, fence.WorkerEpoch)
		return affected(result, err, cftunnel.ErrFenceLost)
	})
}

func (s *Store) FinishStep(ctx context.Context, cmd cftunnel.FinishStepCommand) error {
	return s.transact(ctx, func(tx *sql.Tx) error {
		a, op, err := s.fencedAllocation(ctx, tx, cmd.Fence, cmd.Now)
		if err != nil {
			return err
		}
		step, err := s.getStep(ctx, tx, op.ID, cmd.Name)
		if err != nil {
			return err
		}
		if !step.FinishedAt.IsZero() {
			if step.Result != cmd.Result || cmd.FinalState != "" {
				return cftunnel.ErrInvalidTransition
			}
			return nil
		}
		if step.WorkerEpoch != cmd.WorkerEpoch || cmd.Now.Before(step.StartedAt) {
			return cftunnel.ErrFenceLost
		}
		if cmd.Resources != nil {
			a.Resources = *cmd.Resources
		}
		if cmd.FinalState != "" {
			if err := finishAllocation(&a, op, cmd.FinalState, cmd.Now); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, s.bind(`UPDATE cf_operation SET completed_at = ?, lease_until = 0, next_attempt_at = 0, error_code = ?
				WHERE scope_id = ? AND id = ?`), stamp(cmd.Now), cmd.ErrorCode, op.ScopeID, op.ID)
			if err != nil {
				return err
			}
		}
		if cmd.Resources != nil || cmd.FinalState != "" {
			a.UpdatedAt = cmd.Now
			if err := s.saveAllocation(ctx, tx, a); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE cf_step SET finished_at = ?, result = ? WHERE operation_id = ? AND name = ?`),
			stamp(cmd.Now), cmd.Result, op.ID, step.Name)
		return err
	})
}

func finishAllocation(a *cftunnel.Allocation, op cftunnel.Operation, final cftunnel.AllocationState, now time.Time) error {
	var allowed bool
	switch op.Type {
	case cftunnel.OpRelease:
		allowed = final == cftunnel.StateReleased ||
			final == cftunnel.StateReady && !a.ManualResumeRequired ||
			final == cftunnel.StateSuspended && a.ManualResumeRequired
	case cftunnel.OpDisconnect:
		allowed = final == cftunnel.StateSuspended
	case cftunnel.OpDeprovision:
		allowed = final == cftunnel.StateDisabled
	case cftunnel.OpReconcile, cftunnel.OpRepair:
		allowed = final == cftunnel.StateReady && !a.ManualResumeRequired ||
			final == cftunnel.StateReleased || final == cftunnel.StateSuspended && a.ManualResumeRequired
	case cftunnel.OpProvision:
		allowed = final == cftunnel.StateReady || final == cftunnel.StateDisabled || final == cftunnel.StateReleased
	case cftunnel.OpRecover:
		allowed = final == cftunnel.StateReady || final == cftunnel.StateReleased
	case cftunnel.OpResume:
		allowed = final == cftunnel.StateReady || final == cftunnel.StateReleased ||
			final == cftunnel.StateSuspended && op.PreviousState == cftunnel.StateSuspended
	}
	if !allowed && final != cftunnel.StateQuarantined {
		return cftunnel.ErrInvalidTransition
	}
	a.State = final
	if op.Type == cftunnel.OpResume && final != cftunnel.StateReady {
		a.ManualResumeRequired = op.PreviousManualResume
	}
	if final == cftunnel.StateReleased || final == cftunnel.StateDisabled {
		a.Origin, a.Hostname, a.TunnelName = "", "", ""
		a.Resources = cftunnel.Resources{}
		a.Observation = cftunnel.CloudflareObservation{}
		a.BudgetHeld = false
		a.ReleasedAt = now
		a.CFStatus, a.CFStatusSince = "", time.Time{}
	}
	if final == cftunnel.StateReady {
		if a.ReadyAt.IsZero() || op.Type == cftunnel.OpResume {
			a.ReadyAt = now
		}
		if op.CanRecover && a.RecoveryEnabledAt.IsZero() {
			a.RecoveryEnabledAt = now
		}
	}
	if op.Type == cftunnel.OpDeprovision && final == cftunnel.StateDisabled {
		a.RecoveryEnabledAt = time.Time{}
	}
	return nil
}

func (s *Store) ExpirePending(ctx context.Context, key cftunnel.AllocationKey, generation int64, now, staleBefore time.Time, dryRun bool) (bool, error) {
	var expired bool
	err := s.transact(ctx, func(tx *sql.Tx) error {
		a, err := s.get(ctx, tx, key, true)
		if err != nil {
			return err
		}
		if a.Generation != generation || a.State != cftunnel.StatePending || a.Resources != (cftunnel.Resources{}) {
			return nil
		}
		op, err := scanOperation(tx.QueryRowContext(ctx, s.bind(s.forUpdate("SELECT "+operationColumns+
			" FROM cf_operation WHERE scope_id = ? AND allocation_id = ? AND completed_at = 0")), key.ScopeID, a.ID))
		if errors.Is(err, cftunnel.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		now = s.now(now)
		if op.CreatedAt.After(staleBefore) || op.LeaseUntil.After(now) {
			return nil
		}
		presence, err := s.getPresence(ctx, tx, a.ScopeID, a.ID)
		if err != nil && !errors.Is(err, cftunnel.ErrNotFound) {
			return err
		}
		if presence.Active(now) {
			return nil
		}
		var writes int
		if err := tx.QueryRowContext(ctx, s.bind("SELECT COUNT(*) FROM cf_step WHERE operation_id = ?"), op.ID).Scan(&writes); err != nil || writes != 0 {
			return err
		}
		expired = true
		if dryRun {
			return nil
		}
		final := cftunnel.StateReleased
		if op.PreviousState == cftunnel.StateDisabled {
			final = cftunnel.StateDisabled
		}
		if err := finishAllocation(&a, op, final, now); err != nil {
			return err
		}
		a.UpdatedAt = now
		if err := s.saveAllocation(ctx, tx, a); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE cf_operation SET completed_at = ?, lease_until = 0,
			next_attempt_at = 0, error_code = ? WHERE id = ?`), stamp(now), cftunnel.CodePendingExpired, op.ID)
		return err
	})
	return expired && err == nil, err
}
