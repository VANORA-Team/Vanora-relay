package sqlstore

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vanora-relay/internal/cftunnel"
)

func TestSQLitePhase1AMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	scope := seedPhase1ASchema(t, &Store{db: db})
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLite(t.Context(), path, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	testMigratedPhase1A(t, store, scope)
}

func seedPhase1ASchema(t *testing.T, store *Store) string {
	t.Helper()
	ctx := t.Context()
	lines := strings.Split(schema, "\n")
	columnNames := " ready_at recovery_enabled_at released_at cf_status cf_status_since socket_id runtime_id phase can_recover seq attempts error_code previous_state previous_manual_resume protect_presence cycle seen_cycles last_cycle "
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case strings.Contains(columnNames, " "+fields[0]+" "), strings.Contains(line, "CREATE UNIQUE INDEX cf_allocation_tunnel_name"),
			strings.Contains(line, "next_attempt_at BIGINT NOT NULL DEFAULT 0"):
			lines[index] = ""
		case strings.Contains(line, "CONSTRAINT cf_allocation_manual_gate"):
			lines[index] = "    CHECK (state NOT IN ('pending', 'ready', 'reconciling', 'released') OR manual_resume_required = 0),"
		case strings.Contains(line, "CONSTRAINT cf_operation_lease_gate"):
			lines[index] = "    CHECK ((lease_until > 0) = (worker_epoch > 0 AND completed_at = 0))"
		case strings.Contains(line, "CREATE INDEX cf_operation_work"):
			lines[index] = strings.Replace(line, ", next_attempt_at", "", 1)
		}
	}
	for statement := range strings.SplitSeq(strings.Join(lines, "\n"), ";") {
		if statement = strings.TrimSpace(statement); statement != "" {
			if _, err := store.db.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE cf_schema_migrations (version INTEGER PRIMARY KEY CHECK (version > 0))`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO cf_schema_migrations (version) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	scope := testScope(2)
	_, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO cf_scope (`+scopeColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		scope.ID, scope.Channel, scope.CAPublicKeySHA256, scope.AllowedIssuer, scope.MembershipOrigin, scope.ControlOrigin,
		scope.AccountID, scope.ZoneID, scope.BaseDomain, scope.Namespace, scope.MasterKeySHA256, scope.UnmanagedCount)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO cf_owner (scope_id, id) VALUES (?, 'owner')`,
		`INSERT INTO cf_allocation (scope_id, id, device_id, owner_id, device_key_hash, generation, incarnation, state, origin, hostname,
			tunnel_name, tunnel_id, dns_record_id, budget_held, manual_resume_required, updated_at)
			VALUES (?, 'allocation', 'device', 'owner', 'key-device', 2, 1, 'suspended', '127.0.0.1:4321', 'host.example',
			    'old-name', 'tunnel', 'dns', 1, 1, 1780000000000000000)`,
		`INSERT INTO cf_operation (id, scope_id, allocation_id, operation_type, generation, worker_id, worker_epoch, created_at, completed_at)
			VALUES ('legacy-operation', ?, 'allocation', 'disconnect', 2, 'worker', 1, 1780000000000000000, 1780000000000000000)`,
		`INSERT INTO cf_idempotency (scope_id, owner_id, request_key, body_hash, operation_id, expires_at)
			VALUES (?, 'owner', 'legacy-request', 'legacy-hash', 'legacy-operation', 1780100000000000000)`,
	} {
		if _, err := store.db.ExecContext(ctx, store.bind(statement), scope.ID); err != nil {
			t.Fatal(err)
		}
	}
	return scope.ID
}

func testMigratedPhase1A(t *testing.T, store *Store, scope string) {
	t.Helper()
	ctx := t.Context()
	key := cftunnel.AllocationKey{ScopeID: scope, DeviceID: "device"}
	before := allocation(t, store, key)
	if before.State != cftunnel.StateSuspended || !before.ManualResumeRequired || before.Resources.TunnelID != "tunnel" {
		t.Fatalf("legacy resource lost in migration: %+v", before)
	}
	command := transition(before, cftunnel.OpDisconnect, testNow)
	command.IdempotencyKey, command.BodyHash = "legacy-request", "legacy-hash"
	if op := claim(t, store, command, basePolicy); op.ID != "legacy-operation" {
		t.Fatalf("legacy operation replay = %s", op.ID)
	}
	now := testNow.Add(time.Minute)
	claim(t, store, transition(before, cftunnel.OpRelease, now), basePolicy)
	op, err := store.AcquireWork(ctx, scope, "new-worker", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	retry := now.Add(time.Minute)
	if err := store.ReleaseWork(ctx, op.Fence(), now, retry, cftunnel.ErrCFRateLimited); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireWork(ctx, scope, "another-worker", retry.Add(-time.Nanosecond), time.Minute); !errors.Is(err, cftunnel.ErrNotFound) {
		t.Fatalf("operation bypassed persisted retry time: %v", err)
	}
	complete(t, store, scope, retry, cftunnel.StateReleased, nil)
	after := allocation(t, store, key)
	if after.State != cftunnel.StateReleased || !after.ManualResumeRequired || after.BudgetHeld || !after.ReleasedAt.Equal(retry) {
		t.Fatalf("migrated constraint did not preserve manual gate: %+v", after)
	}
}
