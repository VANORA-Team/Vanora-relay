// Package sqlstore persists tunnel state with SQLite or PostgreSQL.
package sqlstore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"vanora-relay/internal/cftunnel"
)

//go:embed schema.sql
var schema string

// Options configures database pooling and the server clock. SQLite always
// uses one connection. Clock defaults to time.Now.
type Options struct {
	MaxOpenConns int
	Clock        func() time.Time
}

// Store enforces the tunnel state machine in database transactions.
type Store struct {
	db        *sql.DB
	postgres  bool
	fileLock  *flock.Flock
	clock     func() time.Time
	closeOnce sync.Once
	closeErr  error
}

var _ cftunnel.Store = (*Store)(nil)

// OpenSQLite creates or migrates a persistent database and holds its sidecar
// lock until Close. All transactions use BEGIN IMMEDIATE.
func OpenSQLite(ctx context.Context, path string, opts Options) (*Store, error) {
	if err := cftunnel.ValidateSQLitePath(path); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	abs = filepath.Join(dir, filepath.Base(abs))
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			abs, err = filepath.EvalSymlinks(abs)
			if err != nil {
				return nil, err
			}
			info, err = os.Stat(abs)
			if err != nil {
				return nil, err
			}
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("cftunnel: SQLite database must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	lock := flock.New(abs + ".lock")
	locked, err := lock.TryLock()
	if err != nil || !locked {
		_ = lock.Close()
		if err == nil {
			err = errors.New("database is locked by another process")
		}
		return nil, fmt.Errorf("cftunnel: lock SQLite database: %w", err)
	}
	dbFile, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil {
		err = dbFile.Close()
	}
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	dsn := (&url.URL{Scheme: "file", Path: uriPath, RawQuery: "_txlock=immediate" +
		"&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return open(ctx, &Store{db: db, fileLock: lock, clock: opts.Clock})
}

// OpenPostgres opens a validated PostgreSQL DSN and applies schema migrations.
func OpenPostgres(ctx context.Context, dsn string, opts Options) (*Store, error) {
	cfg, err := cftunnel.ParsePostgresDSN(dsn)
	if err != nil {
		return nil, err
	}
	db := stdlib.OpenDB(*cfg)
	if opts.MaxOpenConns > 0 {
		db.SetMaxOpenConns(opts.MaxOpenConns)
	}
	return open(ctx, &Store{db: db, postgres: true, clock: opts.Clock})
}

func open(ctx context.Context, s *Store) (*Store, error) {
	if s.clock == nil {
		s.clock = time.Now
	}
	if err := s.migrate(ctx); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func (s *Store) now(requested time.Time) time.Time {
	if current := s.clock(); current.After(requested) {
		return current
	}
	return requested
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.db.Close()
		if s.fileLock != nil {
			s.closeErr = errors.Join(s.closeErr, s.fileLock.Close())
		}
	})
	return s.closeErr
}

func (s *Store) migrate(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if !s.postgres {
		if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
			return err
		}
		defer conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA foreign_keys = ON")
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.migrateTransaction(ctx, tx); err != nil {
		return err
	}
	if !s.postgres {
		var violations int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_foreign_key_check").Scan(&violations); err != nil {
			return err
		}
		if violations != 0 {
			return errors.New("cftunnel: migration foreign key check failed")
		}
	}
	return tx.Commit()
}

func (s *Store) migrateTransaction(ctx context.Context, tx *sql.Tx) error {
	if s.postgres {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(764584093528207193)"); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS cf_schema_migrations (
			version INTEGER PRIMARY KEY CHECK (version > 0)
		)`); err != nil {
		return err
	}
	var version int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM cf_schema_migrations").Scan(&version); err != nil {
		return err
	}
	switch version {
	case 0:
		for statement := range strings.SplitSeq(schema, ";") {
			if statement = strings.TrimSpace(statement); statement != "" {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return fmt.Errorf("cftunnel: migration 1: %w", err)
				}
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO cf_schema_migrations (version) VALUES (1), (2)"); err != nil {
			return err
		}
	case 1:
		if err := s.upgradePhase1A(ctx, tx); err != nil {
			return fmt.Errorf("cftunnel: migration 2: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO cf_schema_migrations (version) VALUES (2)"); err != nil {
			return err
		}
	case 2:
	case 3:
		return nil
	default:
		return fmt.Errorf("cftunnel: unsupported schema version %d", version)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE cf_noop_request (
		scope_id TEXT NOT NULL,
		owner_id TEXT NOT NULL,
		request_key TEXT NOT NULL,
		body_hash TEXT NOT NULL,
		allocation_id TEXT NOT NULL,
		generation BIGINT NOT NULL,
		expires_at BIGINT NOT NULL,
		PRIMARY KEY (scope_id, owner_id, request_key),
		FOREIGN KEY (scope_id, owner_id) REFERENCES cf_owner (scope_id, id),
		FOREIGN KEY (scope_id, allocation_id) REFERENCES cf_allocation (scope_id, id)
	)`); err != nil {
		return fmt.Errorf("cftunnel: migration 3: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "CREATE INDEX cf_noop_request_expiry ON cf_noop_request (scope_id, expires_at)"); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO cf_schema_migrations (version) VALUES (3)")
	return err
}

func (s *Store) upgradePhase1A(ctx context.Context, tx *sql.Tx) error {
	tables := []struct {
		name       string
		columns    string
		predicate  string
		constraint string
	}{
		{"cf_allocation", "ready_at recovery_enabled_at released_at cf_status cf_status_since", "%manual_resume_required%released%", "cf_allocation_manual_gate"},
		{"cf_operation", "next_attempt_at attempts error_code previous_state previous_manual_resume protect_presence can_recover", "%lease_until%worker_epoch%", "cf_operation_lease_gate"},
		{"cf_presence", "socket_id runtime_id phase can_recover seq", "", ""},
		{"cf_scan", "cycle", "", ""},
		{"cf_orphan", "seen_cycles last_cycle", "", ""},
	}
	statements := strings.Split(schema, ";")
	for _, table := range tables {
		var create string
		for _, statement := range statements {
			if statement = strings.TrimSpace(statement); strings.HasPrefix(statement, "CREATE TABLE "+table.name+" (") {
				create = statement
				break
			}
		}
		if create == "" {
			return fmt.Errorf("schema table missing: %s", table.name)
		}
		if !s.postgres && table.constraint != "" {
			oldColumns := allocationColumns
			if table.name == "cf_operation" {
				oldColumns = operationColumns
			}
			oldColumns, _, _ = strings.Cut(oldColumns, ", "+strings.Fields(table.columns)[0])
			temp := table.name + "_v2"
			for _, statement := range []string{
				strings.Replace(create, "CREATE TABLE "+table.name, "CREATE TABLE "+temp, 1),
				"INSERT INTO " + temp + " (" + oldColumns + ") SELECT " + oldColumns + " FROM " + table.name,
				"DROP TABLE " + table.name,
				"ALTER TABLE " + temp + " RENAME TO " + table.name,
			} {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return err
				}
			}
			for _, statement := range statements {
				statement = strings.TrimSpace(statement)
				if (strings.HasPrefix(statement, "CREATE INDEX ") || strings.HasPrefix(statement, "CREATE UNIQUE INDEX ")) &&
					strings.Contains(statement, " ON "+table.name+" (") {
					if _, err := tx.ExecContext(ctx, statement); err != nil {
						return err
					}
				}
			}
			continue
		}
		for _, column := range strings.Fields(table.columns) {
			if err := addSchemaDefinition(ctx, tx, table.name, create, column+" ", "COLUMN "); err != nil {
				return err
			}
		}
		if table.constraint != "" {
			var old string
			match := table.predicate
			if table.name == "cf_allocation" {
				match = "%released%manual_resume_required%"
			}
			err := tx.QueryRowContext(ctx, `SELECT quote_ident(conname) FROM pg_constraint
				WHERE conrelid = $1::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE $2`, table.name, match).Scan(&old)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "ALTER TABLE "+table.name+" DROP CONSTRAINT "+old); err != nil {
				return err
			}
			if err := addSchemaDefinition(ctx, tx, table.name, create, "CONSTRAINT "+table.constraint+" ", ""); err != nil {
				return err
			}
		}
	}
	if s.postgres {
		if _, err := tx.ExecContext(ctx, "DROP INDEX cf_operation_work"); err != nil {
			return err
		}
		for _, statement := range statements {
			statement = strings.TrimSpace(statement)
			if strings.HasPrefix(statement, "CREATE INDEX cf_operation_work ") ||
				strings.HasPrefix(statement, "CREATE UNIQUE INDEX cf_allocation_tunnel_name ") {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return err
				}
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cf_allocation SET ready_at = updated_at WHERE state = 'ready'`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE cf_operation SET previous_manual_resume = 1,
		previous_state = CASE WHEN EXISTS (SELECT 1 FROM cf_allocation a
			WHERE a.scope_id = cf_operation.scope_id AND a.id = cf_operation.allocation_id AND a.tunnel_id <> '')
			THEN 'suspended' ELSE 'released' END
		WHERE completed_at = 0 AND operation_type = 'resume'`)
	return err
}

func addSchemaDefinition(ctx context.Context, tx *sql.Tx, table, create, prefix, kind string) error {
	for line := range strings.SplitSeq(create, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			_, err := tx.ExecContext(ctx, "ALTER TABLE "+table+" ADD "+kind+strings.TrimSuffix(line, ","))
			return err
		}
	}
	return fmt.Errorf("schema definition missing: %s.%s", table, prefix)
}

func (s *Store) transact(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// bind translates placeholders in the store's static SQL. A literal question
// mark inside quoted SQL stays literal.
func (s *Store) bind(query string) string {
	if !s.postgres {
		return query
	}
	var out strings.Builder
	var quote byte
	parameter := 0
	for index := range len(query) {
		char := query[index]
		switch {
		case quote != 0:
			if char == quote {
				quote = 0
			}
		case char == '\'' || char == '"':
			quote = char
		case char == '?':
			parameter++
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(parameter))
			continue
		}
		out.WriteByte(char)
	}
	return out.String()
}

func (s *Store) forUpdate(query string) string {
	if s.postgres {
		return query + " FOR UPDATE"
	}
	return query
}

type scanner interface {
	Scan(...any) error
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func affected(result sql.Result, err, noRows error) error {
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return noRows
	}
	return err
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return cftunnel.ErrNotFound
	}
	return err
}

func stamp(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
}

func instant(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

func flag(value bool) int {
	if value {
		return 1
	}
	return 0
}
