package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"

	"vanora-relay/internal/cftunnel"
)

var testNow = time.Unix(1780000000, 0).UTC()
var basePolicy = cftunnel.ClaimPolicy{OwnerSlots: 3, AccountCap: 30}
var testOptions = Options{Clock: func() time.Time { return testNow }, MaxOpenConns: 20}

func TestSQLiteStore(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "private dir", "state.sqlite")
	first, err := OpenSQLite(ctx, path, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	if second, err := OpenSQLite(ctx, path, Options{}); err == nil {
		_ = second.Close()
		t.Fatal("second SQLite process obtained the same file lock")
	}
	var journal string
	if err := first.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal mode = %q, %v", journal, err)
	}
	for pragma, want := range map[string]int{"synchronous": 2, "foreign_keys": 1, "busy_timeout": 5000} {
		var got int
		if err := first.db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil || got != want {
			t.Fatalf("PRAGMA %s = %d, %v; want %d", pragma, got, err, want)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLite(ctx, path, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runStoreTests(t, store)
}

func TestPostgresStore(t *testing.T) {
	dsn := os.Getenv("VANORA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("VANORA_TEST_PG_DSN is unset")
	}
	cfg, err := cftunnel.ParsePostgresDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = admin.Close() })
	namespace := "cf_test_" + strings.ToLower(rand.Text())
	if _, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+namespace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, "DROP SCHEMA "+namespace+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if strings.HasPrefix(dsn, "postgresql://") || strings.HasPrefix(dsn, "postgres://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid PostgreSQL test URL")
		}
		query := parsed.Query()
		query.Set("search_path", namespace)
		parsed.RawQuery = query.Encode()
		dsn = parsed.String()
	} else {
		dsn += " search_path=" + namespace
	}
	legacyConfig, err := cftunnel.ParsePostgresDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	legacy := stdlib.OpenDB(*legacyConfig)
	scope := seedPhase1ASchema(t, &Store{db: legacy, postgres: true})
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := OpenPostgres(t.Context(), dsn, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("phase 1A migration", func(t *testing.T) {
		testMigratedPhase1A(t, first, scope)
	})
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenPostgres(t.Context(), dsn, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runStoreTests(t, store)
	t.Run("skip locked", func(t *testing.T) {
		scope := ensureTestScope(t, store, 0)
		first := claim(t, store, provision(scope, "owner", "device-first"), basePolicy)
		secondCmd := provision(scope, "owner", "device-second")
		secondCmd.Now = testNow.Add(time.Second)
		second := claim(t, store, secondCmd, basePolicy)
		tx, err := store.db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := store.getOperation(t.Context(), tx, scope, first.ID, true); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		op, err := store.AcquireWork(ctx, scope, "worker", secondCmd.Now, time.Minute)
		if err != nil || op.ID != second.ID {
			t.Fatalf("AcquireWork with locked candidate = %s, %v; want %s", op.ID, err, second.ID)
		}
	})
}

func TestPostgresPlaceholderTranslation(t *testing.T) {
	raw := `SELECT '?', "?", 'it''s?', ?, 'x', ?, ?`
	if got, want := (&Store{postgres: true}).bind(raw), `SELECT '?', "?", 'it''s?', $1, 'x', $2, $3`; got != want {
		t.Fatalf("PostgreSQL bind = %q; want %q", got, want)
	}
	if got := (&Store{}).bind(raw); got != raw {
		t.Fatalf("SQLite bind = %q; want %q", got, raw)
	}
}

func TestSQLiteRejectsRequestsWithStaleClock(t *testing.T) {
	now := testNow
	store, err := OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"), Options{Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	scope := ensureTestScope(t, store, 0)
	claim(t, store, provision(scope, "owner", "device"), basePolicy)
	op := acquire(t, store, scope, "worker", now, time.Second)
	if _, err := store.BeginStep(t.Context(), op.Fence(), "cloud", now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	err = store.FinishStep(t.Context(), cftunnel.FinishStepCommand{Fence: op.Fence(), Name: "cloud", Now: testNow})
	if !errors.Is(err, cftunnel.ErrFenceLost) {
		t.Fatalf("expired worker with stale request timestamp wrote a step: %v", err)
	}
	proof := cftunnel.ProofUse{ScopeID: scope, Nonce: "expired", ExpiresAt: testNow.Add(time.Second)}
	if err := store.ConsumeProof(t.Context(), proof, testNow); !errors.Is(err, cftunnel.ErrInvalidProof) {
		t.Fatalf("expired proof with stale request timestamp accepted: %v", err)
	}
}

func runStoreTests(t *testing.T, store *Store) {
	t.Helper()
	t.Run("schema and scope", func(t *testing.T) { testSchemaAndScope(t, store) })
	t.Run("same device", func(t *testing.T) { testConcurrentDevice(t, store) })
	t.Run("quota", func(t *testing.T) { testConcurrentQuota(t, store) })
	t.Run("work fence and lifecycle", func(t *testing.T) { testWorkAndLifecycle(t, store) })
	t.Run("work priority", func(t *testing.T) { testWorkPriority(t, store) })
	t.Run("reconcile repair and recovery", func(t *testing.T) { testRecovery(t, store) })
	t.Run("proof idempotency and pruning", func(t *testing.T) { testProofAndPrune(t, store) })
	t.Run("observations", func(t *testing.T) { testObservations(t, store) })
}

func testWorkPriority(t *testing.T, store *Store) {
	scope := ensureTestScope(t, store, 0)
	var ready []cftunnel.Allocation
	for _, device := range []string{"release", "repair", "disconnect"} {
		create := provision(scope, device, device)
		claim(t, store, create, basePolicy)
		complete(t, store, scope, testNow, cftunnel.StateReady, &cftunnel.Resources{
			TunnelID: device + "-tunnel", DNSRecordID: device + "-dns",
		})
		ready = append(ready, allocation(t, store, create.AllocationKey))
	}
	release := transition(ready[0], cftunnel.OpRelease, testNow.Add(time.Second))
	release.ProtectPresence = true
	releaseOp := claim(t, store, release, basePolicy)
	repairOp := claim(t, store, transition(ready[1], cftunnel.OpRepair, testNow.Add(2*time.Second)), basePolicy)
	create := provision(scope, "new", "new")
	create.Now = testNow.Add(3 * time.Second)
	provisionOp := claim(t, store, create, basePolicy)
	disconnectOp := claim(t, store, transition(ready[2], cftunnel.OpDisconnect, testNow.Add(4*time.Second)), basePolicy)
	for _, want := range []cftunnel.Operation{disconnectOp, provisionOp, releaseOp, repairOp} {
		got := acquire(t, store, scope, "worker", testNow.Add(5*time.Second), time.Minute)
		if got.ID != want.ID {
			t.Fatalf("work item %s acquired before %s", got.Type, want.Type)
		}
	}
}

func testSchemaAndScope(t *testing.T, store *Store) {
	ctx := t.Context()
	var version, versions int
	if err := store.db.QueryRowContext(ctx, "SELECT MAX(version), COUNT(*) FROM cf_schema_migrations").
		Scan(&version, &versions); err != nil || version != 3 || versions != 3 {
		t.Fatalf("migration = %d of %d, %v", version, versions, err)
	}
	scope := testScope(2)
	if err := store.EnsureScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureScope(ctx, scope); err != nil {
		t.Fatalf("scope is not idempotent: %v", err)
	}
	for _, change := range []func(*cftunnel.Scope){
		func(s *cftunnel.Scope) { s.Channel = "global" },
		func(s *cftunnel.Scope) { s.Channel = "self" },
		func(s *cftunnel.Scope) { s.CAPublicKeySHA256 = "other" },
		func(s *cftunnel.Scope) { s.AllowedIssuer = "https://other.example" },
		func(s *cftunnel.Scope) { s.MembershipOrigin = "https://other.example" },
		func(s *cftunnel.Scope) { s.ControlOrigin = "https://other.example" },
		func(s *cftunnel.Scope) { s.AccountID = "other" },
		func(s *cftunnel.Scope) { s.ZoneID = "other" },
		func(s *cftunnel.Scope) { s.BaseDomain = "other.example" },
		func(s *cftunnel.Scope) { s.Namespace = "other" },
		func(s *cftunnel.Scope) { s.MasterKeySHA256 = "other" },
		func(s *cftunnel.Scope) { s.ID = "same-account-and-namespace" },
	} {
		changed := scope
		change(&changed)
		if err := store.EnsureScope(ctx, changed); !errors.Is(err, cftunnel.ErrScopeMismatch) {
			t.Fatalf("altered scope %+v: %v", changed, err)
		}
	}
	if err := store.UpdateUnmanagedCount(ctx, scope.ID, 3); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureScope(ctx, scope); err != nil {
		t.Fatalf("mutable unmanaged count caused a scope mismatch: %v", err)
	}
	op := claim(t, store, provision(scope.ID, "owner", "device"), basePolicy)
	for _, set := range []string{
		"manual_resume_required = 2",
		"manual_resume_required = 1",
		"state = 'ready'",
		"dns_record_id = 'the-dns-record'",
		"state = 'suspended'",
		"state = 'disconnecting'",
		"state = 'released', budget_held = 0",
		"state = 'disabled', budget_held = 0",
		"budget_held = 0",
		"incarnation = generation + 1",
		"state = 'invalid'",
	} {
		_, err := store.db.ExecContext(ctx, store.bind("UPDATE cf_allocation SET "+set+" WHERE id = ?"), op.AllocationID)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "check constraint") {
			t.Errorf("schema accepted %q, or returned unexpected error: %v", set, err)
		}
	}
	_, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO cf_operation (id, scope_id, allocation_id, operation_type, generation, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`), "another", scope.ID, op.AllocationID, cftunnel.OpProvision, op.Generation+1, stamp(testNow))
	if err == nil {
		t.Error("schema accepted two unfinished operations for one allocation")
	}
}

func testConcurrentDevice(t *testing.T, store *Store) {
	scope := ensureTestScope(t, store, 0)
	cmd := provision(scope, "owner", "device")
	var original cftunnel.Operation
	for _, result := range concurrentClaims(t, store, 16, basePolicy, func(_ int) cftunnel.ClaimCommand { return cmd }) {
		if result.err == nil && original.ID == "" {
			original = result.op
			continue
		}
		if !errors.Is(result.err, cftunnel.ErrOperationInProgress) {
			t.Fatalf("concurrent initial claim = %+v, %v", result.op, result.err)
		}
	}
	if original.ID == "" {
		t.Fatal("no operation created")
	}
	cmd = provision(scope, "owner", "idempotent-device")
	cmd.IdempotencyKey, cmd.BodyHash = "shared-key", "shared-digest"
	var reused string
	for _, result := range concurrentClaims(t, store, 16, basePolicy, func(_ int) cftunnel.ClaimCommand { return cmd }) {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if reused == "" {
			reused = result.op.ID
		}
		if result.op.ID != reused {
			t.Fatal("identical claims created multiple operations")
		}
	}
	var open int
	if err := store.db.QueryRowContext(t.Context(), store.bind("SELECT COUNT(*) FROM cf_operation WHERE scope_id = ? AND completed_at = 0"),
		scope).Scan(&open); err != nil || open != 2 {
		t.Fatalf("open operations = %d, %v; want two for two devices", open, err)
	}
}

func testConcurrentQuota(t *testing.T, store *Store) {
	for _, slots := range []int{1, 3} {
		scope := ensureTestScope(t, store, 0)
		results := concurrentClaims(t, store, 16, cftunnel.ClaimPolicy{OwnerSlots: slots, AccountCap: 30}, func(index int) cftunnel.ClaimCommand {
			return provision(scope, "owner", fmt.Sprintf("device-%d", index))
		})
		checkQuotaResults(t, results, slots, cftunnel.ErrOwnerQuotaExhausted)
		counts, err := store.CountSlots(t.Context(), scope, "owner")
		if err != nil || counts.OwnerHeld != slots || counts.ScopeHeld != slots {
			t.Fatalf("owner slot counts = %+v, %v; want %d", counts, err, slots)
		}
	}
	scope := ensureTestScope(t, store, 6)
	results := concurrentClaims(t, store, 16, cftunnel.ClaimPolicy{OwnerSlots: 1, AccountCap: 10}, func(index int) cftunnel.ClaimCommand {
		return provision(scope, fmt.Sprintf("owner-%d", index), fmt.Sprintf("device-%d", index))
	})
	checkQuotaResults(t, results, 4, cftunnel.ErrAccountCapacity)
	counts, err := store.CountSlots(t.Context(), scope, "other")
	if err != nil || counts.ScopeHeld+counts.UnmanagedCount != 10 {
		t.Fatalf("scope slot counts = %+v, %v", counts, err)
	}
	if err := store.SetOwnerOverride(t.Context(), scope, "overridden", &cftunnel.OwnerOverride{MaxTunnels: 0}); err != nil {
		t.Fatal(err)
	}
	if override, err := store.GetOwnerOverride(t.Context(), scope, "overridden"); err != nil || override == nil || override.MaxTunnels != 0 {
		t.Fatalf("override = %+v, %v", override, err)
	}
	if _, err := store.Claim(t.Context(), provision(scope, "overridden", "new-device"), basePolicy); !errors.Is(err, cftunnel.ErrOwnerQuotaExhausted) {
		t.Fatalf("claim with zero-slot override = %v", err)
	}
	overrideScope := ensureTestScope(t, store, 0)
	if err := store.SetOwnerOverride(t.Context(), overrideScope, "boosted", &cftunnel.OwnerOverride{MaxTunnels: 10}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(t.Context(), provision(overrideScope, "boosted", "denied"), cftunnel.ClaimPolicy{AccountCap: 2}); !errors.Is(err, cftunnel.ErrOwnerQuotaExhausted) {
		t.Fatalf("override resurrected ineligible owner: %v", err)
	}
	policy := cftunnel.ClaimPolicy{OwnerSlots: 1, AccountCap: 2}
	claim(t, store, provision(overrideScope, "boosted", "first"), policy)
	claim(t, store, provision(overrideScope, "boosted", "second"), policy)
	if _, err := store.Claim(t.Context(), provision(overrideScope, "boosted", "third"), policy); !errors.Is(err, cftunnel.ErrAccountCapacity) {
		t.Fatalf("override bypassed the account cap: %v", err)
	}
}

func testWorkAndLifecycle(t *testing.T, store *Store) {
	ctx := t.Context()
	scope := ensureTestScope(t, store, 0)
	create := provision(scope, "owner", "device")
	op := claim(t, store, create, basePolicy)
	old := acquire(t, store, scope, "first", testNow, time.Second)
	if old.ID != op.ID || old.WorkerEpoch != 1 {
		t.Fatalf("first worker got %+v", old)
	}
	if _, err := store.BeginStep(ctx, old.Fence(), "cloud", testNow); err != nil {
		t.Fatal(err)
	}
	newTime := testNow.Add(time.Second)
	if err := store.RenewWork(ctx, old.Fence(), newTime, time.Minute); !errors.Is(err, cftunnel.ErrFenceLost) {
		t.Fatalf("expired lease renewed: %v", err)
	}
	current := acquire(t, store, scope, "second", newTime, time.Minute)
	if current.ID != old.ID || current.WorkerEpoch != 2 {
		t.Fatalf("reacquired work = %+v", current)
	}
	if err := store.RenewWork(ctx, current.Fence(), newTime, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*cftunnel.Fence){
		func(f *cftunnel.Fence) { f.ScopeID = "different" },
		func(f *cftunnel.Fence) { f.AllocationID = "different" },
		func(f *cftunnel.Fence) { f.OperationID = "different" },
		func(f *cftunnel.Fence) { f.Generation++ },
		func(f *cftunnel.Fence) { f.WorkerEpoch-- },
	} {
		stale := current.Fence()
		alter(&stale)
		if _, err := store.BeginStep(ctx, stale, "cloud", newTime); !errors.Is(err, cftunnel.ErrFenceLost) {
			t.Errorf("BeginStep accepted stale fence %+v: %v", stale, err)
		}
		if err := store.FinishStep(ctx, cftunnel.FinishStepCommand{Fence: stale, Name: "cloud", Now: newTime}); !errors.Is(err, cftunnel.ErrFenceLost) {
			t.Errorf("FinishStep accepted stale fence %+v: %v", stale, err)
		}
	}
	step, err := store.BeginStep(ctx, current.Fence(), "cloud", newTime)
	if err != nil || step.WorkerEpoch != current.WorkerEpoch {
		t.Fatalf("reopened step = %+v, %v", step, err)
	}
	finish := cftunnel.FinishStepCommand{Fence: current.Fence(), Name: step.Name, FinalState: cftunnel.StateReady, Now: newTime}
	if err := store.FinishStep(ctx, finish); err == nil {
		t.Fatal("ready commit accepted missing Cloudflare resources")
	}
	finish.Resources = &cftunnel.Resources{TunnelID: "tunnel", DNSRecordID: "dns"}
	if err := store.FinishStep(ctx, finish); err != nil {
		t.Fatal(err)
	}
	ready := allocation(t, store, create.AllocationKey)
	if ready.State != cftunnel.StateReady || ready.Resources != *finish.Resources || ready.Generation != 1 || ready.Incarnation != 1 {
		t.Fatalf("ready allocation = %+v", ready)
	}
	cmd := transition(ready, cftunnel.OpDisconnect, newTime.Add(time.Second))
	cmd.DeviceKeyHash = "other-key"
	if _, err := store.Claim(ctx, cmd, basePolicy); !errors.Is(err, cftunnel.ErrDeviceBinding) {
		t.Fatalf("device takeover claim = %v", err)
	}
	cmd.DeviceKeyHash = ready.DeviceKeyHash
	cmd.OwnerID = "another-owner"
	if _, err := store.Claim(ctx, cmd, basePolicy); !errors.Is(err, cftunnel.ErrDeviceBinding) {
		t.Fatalf("owner takeover claim = %v", err)
	}
	cmd.OwnerID = ready.OwnerID
	cmd.IfGeneration++
	if _, err := store.Claim(ctx, cmd, basePolicy); !errors.Is(err, cftunnel.ErrGenerationConflict) {
		t.Fatalf("wrong generation claim = %v", err)
	}
	cmd.IfGeneration--
	claim(t, store, cmd, basePolicy)
	complete(t, store, scope, cmd.Now, cftunnel.StateSuspended, nil)
	suspended := allocation(t, store, create.AllocationKey)
	if suspended.State != cftunnel.StateSuspended || !suspended.ManualResumeRequired || !suspended.BudgetHeld {
		t.Fatalf("suspended allocation = %+v", suspended)
	}
	if _, err := store.Claim(ctx, transition(suspended, cftunnel.OpRecover, cmd.Now), basePolicy); !errors.Is(err, cftunnel.ErrTunnelSuspended) {
		t.Fatalf("automatic suspended recovery = %v", err)
	}
	if _, err := store.BeginStep(ctx, current.Fence(), "cloud", cmd.Now); !errors.Is(err, cftunnel.ErrFenceLost) {
		t.Fatalf("previous generation step = %v", err)
	}
	cmd = transition(suspended, cftunnel.OpRelease, cmd.Now.Add(time.Second))
	claim(t, store, cmd, basePolicy)
	complete(t, store, scope, cmd.Now, cftunnel.StateReleased, nil)
	reaped := allocation(t, store, create.AllocationKey)
	if reaped.BudgetHeld || !reaped.ManualResumeRequired || reaped.Origin != "" || reaped.Hostname != "" ||
		reaped.TunnelName != "" || reaped.Resources != (cftunnel.Resources{}) {
		t.Fatalf("released allocation leaked resources or lost manual gate: %+v", reaped)
	}
	if _, err := store.Claim(ctx, transition(reaped, cftunnel.OpRecover, cmd.Now), basePolicy); !errors.Is(err, cftunnel.ErrTunnelSuspended) {
		t.Fatalf("automatic suspended recovery after release = %v", err)
	}
	cmd = transition(reaped, cftunnel.OpResume, cmd.Now.Add(time.Second))
	cmd.Origin, cmd.Hostname, cmd.TunnelName = create.Origin, create.Hostname, "new-tunnel"
	claim(t, store, cmd, basePolicy)
	complete(t, store, scope, cmd.Now, cftunnel.StateReady, finish.Resources)
	resumed := allocation(t, store, create.AllocationKey)
	if resumed.ManualResumeRequired || resumed.Incarnation != 2 || !resumed.BudgetHeld {
		t.Fatalf("resumed allocation = %+v", resumed)
	}
	cmd = transition(resumed, cftunnel.OpRelease, cmd.Now.Add(time.Second))
	claim(t, store, cmd, cftunnel.ClaimPolicy{})
	complete(t, store, scope, cmd.Now, cftunnel.StateReleased, nil)
	released := allocation(t, store, create.AllocationKey)
	if released.BudgetHeld || released.ManualResumeRequired || released.Origin != "" || released.Resources != (cftunnel.Resources{}) {
		t.Fatalf("released allocation = %+v", released)
	}
}

func testProofAndPrune(t *testing.T, store *Store) {
	ctx := t.Context()
	scope := ensureTestScope(t, store, 0)
	cmd := provision(scope, "owner", "device")
	proof := cftunnel.ProofUse{ScopeID: scope, Nonce: "one-use", ExpiresAt: testNow.Add(time.Minute)}
	cmd.Proof = &proof
	cmd.IdempotencyKey, cmd.BodyHash, cmd.IdempotencyTTL = "key", "original-digest", time.Minute
	op := claim(t, store, cmd, basePolicy)
	if _, err := store.Claim(ctx, cmd, basePolicy); !errors.Is(err, cftunnel.ErrReplayDetected) {
		t.Fatalf("same proof accepted: %v", err)
	}
	if err := store.ConsumeProof(ctx, proof, testNow); !errors.Is(err, cftunnel.ErrReplayDetected) {
		t.Fatalf("standalone nonce accepted: %v", err)
	}
	conflict := cmd
	conflict.Proof, conflict.BodyHash = nil, "different-digest"
	if _, err := store.Claim(ctx, conflict, basePolicy); !errors.Is(err, cftunnel.ErrIdempotencyConflict) {
		t.Fatalf("same key, different body = %v", err)
	}
	later := testNow.Add(48 * time.Hour)
	if err := store.PruneExpired(ctx, scope, later); err != nil {
		t.Fatal(err)
	}
	cmd.Proof, cmd.Now = nil, later
	if replay := claim(t, store, cmd, basePolicy); replay.ID != op.ID {
		t.Fatalf("pruned open operation's idempotency: got %s; want %s", replay.ID, op.ID)
	}
	var proofs int
	if err := store.db.QueryRowContext(ctx, store.bind("SELECT COUNT(*) FROM cf_proof_use WHERE scope_id = ?"), scope).
		Scan(&proofs); err != nil || proofs != 0 {
		t.Fatalf("expired proof count = %d, %v", proofs, err)
	}
	complete(t, store, scope, later, cftunnel.StateReady, &cftunnel.Resources{TunnelID: "tunnel", DNSRecordID: "dns"})
	if err := store.PruneExpired(ctx, scope, later.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.getOperation(ctx, store.db, scope, op.ID, false); !errors.Is(err, cftunnel.ErrNotFound) {
		t.Fatalf("completed expired operation was retained: %v", err)
	}
}

func testRecovery(t *testing.T, store *Store) {
	scope := ensureTestScope(t, store, 0)
	create := provision(scope, "owner", "device")
	claim(t, store, create, basePolicy)
	resources := &cftunnel.Resources{TunnelID: "tunnel", DNSRecordID: "dns"}
	complete(t, store, scope, create.Now, cftunnel.StateReady, resources)
	now := create.Now
	for _, kind := range []cftunnel.OperationType{cftunnel.OpReconcile, cftunnel.OpRepair} {
		now = now.Add(time.Second)
		ready := allocation(t, store, create.AllocationKey)
		cmd := transition(ready, kind, now)
		cmd.Origin = "localhost:443"
		claim(t, store, cmd, basePolicy)
		if current := allocation(t, store, create.AllocationKey); current.State != cftunnel.StateReconciling ||
			current.Origin != "127.0.0.1:443" || current.Incarnation != ready.Incarnation {
			t.Fatalf("%s allocation = %+v", kind, current)
		}
		complete(t, store, scope, now, cftunnel.StateReady, nil)
	}
	ready := allocation(t, store, create.AllocationKey)
	now = now.Add(time.Second)
	claim(t, store, transition(ready, cftunnel.OpDeprovision, now), basePolicy)
	complete(t, store, scope, now, cftunnel.StateDisabled, nil)
	disabled := allocation(t, store, create.AllocationKey)
	if disabled.ManualResumeRequired {
		t.Fatal("automatic deprovisioning unexpectedly requires manual resume")
	}
	now = now.Add(time.Second)
	if _, err := store.Claim(t.Context(), transition(disabled, cftunnel.OpRecover, now), basePolicy); !errors.Is(err, cftunnel.ErrInvalidTransition) {
		t.Fatalf("automatic recovery of disabled allocation = %v", err)
	}
	register := transition(disabled, cftunnel.OpProvision, now)
	register.Origin, register.Hostname, register.TunnelName = create.Origin, create.Hostname, "incarnation-2"
	claim(t, store, register, basePolicy)
	complete(t, store, scope, now, cftunnel.StateReady, resources)
	now = now.Add(time.Second)
	claim(t, store, transition(allocation(t, store, create.AllocationKey), cftunnel.OpRelease, now), basePolicy)
	complete(t, store, scope, now, cftunnel.StateReleased, nil)
	now = now.Add(time.Second)
	released := allocation(t, store, create.AllocationKey)
	if _, err := store.Claim(t.Context(), transition(released, cftunnel.OpProvision, now), basePolicy); !errors.Is(err, cftunnel.ErrRecoveryRequired) {
		t.Fatalf("provision of released allocation = %v", err)
	}
	recover := transition(released, cftunnel.OpRecover, now)
	recover.Origin, recover.Hostname, recover.TunnelName = create.Origin, create.Hostname, "incarnation-3"
	if _, err := store.Claim(t.Context(), recover, cftunnel.ClaimPolicy{}); !errors.Is(err, cftunnel.ErrOwnerQuotaExhausted) {
		t.Fatalf("recover bypassed quota: %v", err)
	}
	op := claim(t, store, recover, basePolicy)
	complete(t, store, scope, now, cftunnel.StateQuarantined, nil)
	quarantine := allocation(t, store, create.AllocationKey)
	if !quarantine.BudgetHeld || quarantine.Incarnation != 3 || quarantine.State != cftunnel.StateQuarantined {
		t.Fatalf("quarantined allocation = %+v", quarantine)
	}
	if got, err := store.GetOperation(t.Context(), scope, op.ID); err != nil || got.CompletedAt.IsZero() {
		t.Fatalf("completed operation = %+v, %v", got, err)
	}
}

func testObservations(t *testing.T, store *Store) {
	ctx := t.Context()
	scope := ensureTestScope(t, store, 0)
	cmd := provision(scope, "owner", "device")
	op := claim(t, store, cmd, basePolicy)
	complete(t, store, scope, testNow, cftunnel.StateReady, &cftunnel.Resources{TunnelID: "tunnel", DNSRecordID: "dns"})
	later := testNow.Add(time.Minute)
	presence := cftunnel.Presence{ScopeID: scope, AllocationID: op.AllocationID, Generation: op.Generation,
		SeenAt: later, ExpiresAt: later.Add(time.Minute), SocketID: "socket", RuntimeID: "runtime", Phase: cftunnel.PresenceStarting, Seq: 1}
	if err := store.SetPresence(ctx, presence); err != nil {
		t.Fatal(err)
	}
	stale := presence
	stale.SeenAt = testNow
	if err := store.SetPresence(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetPresence(ctx, scope, op.AllocationID); err != nil || got != presence {
		t.Fatalf("presence = %+v, %v", got, err)
	}
	observation := cftunnel.CloudflareObservation{Generation: op.Generation, ObservedAt: later, TunnelExists: true, DNSExists: true}
	if err := store.UpdateCloudflareObservation(ctx, scope, op.AllocationID, observation); err != nil {
		t.Fatal(err)
	}
	observation.Generation++
	if err := store.UpdateCloudflareObservation(ctx, scope, op.AllocationID, observation); !errors.Is(err, cftunnel.ErrGenerationConflict) {
		t.Fatalf("accepted stale observation = %v", err)
	}
	candidates, err := store.ListReapCandidates(ctx, scope, "", 1)
	if err != nil || len(candidates) != 1 || candidates[0].Presence == nil || *candidates[0].Presence != presence ||
		!candidates[0].Allocation.Observation.DNSExists {
		t.Fatalf("candidates = %+v, %v", candidates, err)
	}
	if rest, err := store.ListReapCandidates(ctx, scope, op.AllocationID, 1); err != nil || len(rest) != 0 {
		t.Fatalf("candidate cursor = %+v, %v", rest, err)
	}
	for _, until := range []time.Time{later, testNow} {
		if err := store.ExtendPause(ctx, scope, "dns", until); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := store.LoadPause(ctx, scope, "dns"); err != nil || !got.Equal(later) {
		t.Fatalf("monotonic pause = %v, %v", got, err)
	}
	cursor := cftunnel.ScanCursor{ScopeID: scope, Kind: "dns", Cursor: "page-2", UpdatedAt: later}
	if err := store.SaveScan(ctx, cursor, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveScan(ctx, cftunnel.ScanCursor{ScopeID: scope, Kind: "dns", UpdatedAt: testNow}, time.Time{}); !errors.Is(err, cftunnel.ErrGenerationConflict) {
		t.Fatal(err)
	}
	if got, err := store.LoadScan(ctx, scope, "dns"); err != nil || got != cursor {
		t.Fatalf("cursor = %+v, %v", got, err)
	}
	orphan := cftunnel.Orphan{ScopeID: scope, Kind: "dns", ResourceID: "orphan", Marker: "marker",
		FirstSeenAt: testNow, LastSeenAt: testNow, NextAttemptAt: later, LastCycle: 1}
	if err := store.UpsertOrphan(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	refresh := orphan
	refresh.FirstSeenAt, refresh.LastSeenAt, refresh.NextAttemptAt = later, later, later.Add(time.Minute)
	refresh.LastCycle = 2
	if err := store.UpsertOrphan(ctx, refresh); err != nil {
		t.Fatal(err)
	}
	due, err := store.ListDueOrphans(ctx, scope, later, 3)
	if err != nil || len(due) != 1 || due[0].FirstSeenAt != testNow || due[0].LastSeenAt != later {
		t.Fatalf("due orphans = %+v, %v", due, err)
	}
	if err := store.ResolveOrphan(ctx, scope, orphan.Kind, orphan.ResourceID, testNow, later); !errors.Is(err, cftunnel.ErrGenerationConflict) {
		t.Fatalf("resolving stale orphan = %v", err)
	}
	if err := store.ResolveOrphan(ctx, scope, orphan.Kind, orphan.ResourceID, later, later); err != nil {
		t.Fatal(err)
	}
	if due, err := store.ListDueOrphans(ctx, scope, later, 3); err != nil || len(due) != 0 {
		t.Fatalf("resolved orphan visible = %+v, %v", due, err)
	}
}

func testScope(unmanaged int) cftunnel.Scope {
	id := rand.Text()
	return cftunnel.Scope{
		ID: id, Channel: "cn", CAPublicKeySHA256: "ca-digest", AllowedIssuer: "https://issuer.example",
		MembershipOrigin: "https://members.example", ControlOrigin: "https://control.example",
		AccountID: id, ZoneID: "zone", BaseDomain: "tunnel.example", Namespace: "cn",
		MasterKeySHA256: "master-digest", UnmanagedCount: unmanaged,
	}
}

func ensureTestScope(t *testing.T, s *Store, unmanaged int) string {
	t.Helper()
	scope := testScope(unmanaged)
	if err := s.EnsureScope(t.Context(), scope); err != nil {
		t.Fatal(err)
	}
	return scope.ID
}

func provision(scope, owner, device string) cftunnel.ClaimCommand {
	return cftunnel.ClaimCommand{
		AllocationKey: cftunnel.AllocationKey{ScopeID: scope, DeviceID: device},
		OwnerID:       owner, DeviceKeyHash: "key-" + device, Type: cftunnel.OpProvision,
		Origin: "127.0.0.1:4321", Hostname: device + ".tunnel.example", TunnelName: "tunnel-" + device, Now: testNow,
	}
}

func transition(a cftunnel.Allocation, kind cftunnel.OperationType, now time.Time) cftunnel.ClaimCommand {
	return cftunnel.ClaimCommand{
		AllocationKey: a.AllocationKey, OwnerID: a.OwnerID, DeviceKeyHash: a.DeviceKeyHash,
		Type: kind, IfGeneration: a.Generation, Now: now,
	}
}

func claim(t *testing.T, s *Store, cmd cftunnel.ClaimCommand, policy cftunnel.ClaimPolicy) cftunnel.Operation {
	t.Helper()
	op, err := s.Claim(t.Context(), cmd, policy)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func allocation(t *testing.T, s *Store, key cftunnel.AllocationKey) cftunnel.Allocation {
	t.Helper()
	a, err := s.Get(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func acquire(t *testing.T, s *Store, scope, worker string, now time.Time, lease time.Duration) cftunnel.Operation {
	t.Helper()
	op, err := s.AcquireWork(t.Context(), scope, worker, now, lease)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func complete(t *testing.T, s *Store, scope string, now time.Time, final cftunnel.AllocationState, resources *cftunnel.Resources) {
	t.Helper()
	op := acquire(t, s, scope, "worker", now, time.Minute)
	if _, err := s.BeginStep(t.Context(), op.Fence(), "finish", now); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishStep(t.Context(), cftunnel.FinishStepCommand{
		Fence: op.Fence(), Name: "finish", Now: now, FinalState: final, Resources: resources,
	}); err != nil {
		t.Fatal(err)
	}
}

type claimResult struct {
	op  cftunnel.Operation
	err error
}

func concurrentClaims(t *testing.T, store *Store, total int, policy cftunnel.ClaimPolicy, command func(int) cftunnel.ClaimCommand) []claimResult {
	t.Helper()
	start := make(chan struct{})
	var done sync.WaitGroup
	results := make([]claimResult, total)
	for index := range total {
		done.Go(func() {
			<-start
			results[index].op, results[index].err = store.Claim(t.Context(), command(index), policy)
		})
	}
	close(start)
	done.Wait()
	return results
}

func checkQuotaResults(t *testing.T, results []claimResult, slots int, expected error) {
	t.Helper()
	successes := 0
	for _, result := range results {
		if result.err == nil {
			successes++
		} else if !errors.Is(result.err, expected) {
			t.Fatalf("concurrent claim got %v; want %v", result.err, expected)
		}
	}
	if successes != slots {
		t.Fatalf("concurrent claims: got %d slots; want %d", successes, slots)
	}
}
