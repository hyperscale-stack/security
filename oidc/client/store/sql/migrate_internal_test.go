// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// schemaTables are the tables of Schema, in the order it creates them.
var schemaTables = []string{"oidc_client_transactions"}

// TestMigrationLock pins the statement Migrate runs first on each engine:
// on PostgreSQL, the transaction-level advisory lock the package
// documentation names — the first eight bytes of SHA-256 of
// "github.com/hyperscale-stack/security/oidc/client/store/sql.Migrate",
// big-endian, as a bigint — and none on MySQL and SQLite, which serialize
// the creation of a table themselves.
func TestMigrationLock(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte("github.com/hyperscale-stack/security/oidc/client/store/sql.Migrate"))
	key := strconv.FormatInt(int64(binary.BigEndian.Uint64(sum[:8])), 10)

	assert.Equal(t, "-3346565968272468758", key)
	assert.Equal(t, "SELECT pg_advisory_xact_lock("+key+")", Postgres.migrationLock())
	assert.Empty(t, MySQL.migrationLock())
	assert.Empty(t, SQLite.migrationLock())
}

// lockingStore returns a store over a new SQLite database file whose
// dialect — a mock — names lock as its migration lock, so that Migrate
// takes the path it takes on PostgreSQL: lock first, then the schema, in
// one transaction. The pool has several connections, so that a statement
// run outside the transaction waits for its write lock — and fails after
// the busy timeout — instead of deadlocking a single connection.
func lockingStore(t *testing.T, lock string) (*Store, *sql.DB) {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "migrate.db") + "?_pragma=busy_timeout(1000)&_pragma=foreign_keys(1)"

	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = db.Close() })

	d := NewMockDialect(t)
	d.EXPECT().migrationLock().Return(lock)

	return &Store{db: db, dialect: d}, db
}

// execAll runs every statement on db.
func execAll(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()

	for _, stmt := range stmts {
		_, err := db.ExecContext(t.Context(), stmt)
		require.NoError(t, err, stmt)
	}
}

// tables lists the tables of db in the order they were created.
func tables(t *testing.T, db *sql.DB) []string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY rowid`)
	require.NoError(t, err)

	defer func() { _ = rows.Close() }()

	var names []string

	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))

		names = append(names, name)
	}

	require.NoError(t, rows.Err())

	return names
}

// TestMigrateTakesTheLockFirst runs the locked path: the lock statement —
// here one creating a probe table — runs before the schema, and the
// transaction commits.
func TestMigrateTakesTheLockFirst(t *testing.T) {
	t.Parallel()

	store, db := lockingStore(t, `CREATE TABLE migration_lock_probe (taken INTEGER)`)

	require.NoError(t, store.Migrate(t.Context()))
	assert.Equal(t, append([]string{"migration_lock_probe"}, schemaTables...), tables(t, db))
}

// TestMigrateFailedLockCreatesNothing: a lock that cannot be taken stops
// Migrate before any table is created.
func TestMigrateFailedLockCreatesNothing(t *testing.T) {
	t.Parallel()

	store, db := lockingStore(t, `SELECT no_such_function()`)

	err := store.Migrate(t.Context())
	require.ErrorContains(t, err, "sqlstore: migrate: ")
	require.ErrorContains(t, err, "no_such_function")
	assert.Empty(t, tables(t, db))
}

// TestMigrateRollsBackAFailedSchema: when a statement of the schema fails,
// the whole transaction is rolled back — the lock statement's probe table
// and the tables created before it included.
func TestMigrateRollsBackAFailedSchema(t *testing.T) {
	t.Parallel()

	store, db := lockingStore(t, `CREATE TABLE migration_lock_probe (taken INTEGER)`)

	// An index named like the last table makes its CREATE TABLE fail.
	last := schemaTables[len(schemaTables)-1]
	execAll(t, db, `CREATE TABLE blocker (x INTEGER)`, `CREATE INDEX `+last+` ON blocker (x)`)

	err := store.Migrate(t.Context())
	require.ErrorContains(t, err, "sqlstore: migrate: ")
	require.ErrorContains(t, err, "already an index named "+last)
	assert.Equal(t, []string{"blocker"}, tables(t, db))
}

// TestMigrateReleasesAFailedTransaction: a Migrate that fails under a
// context that never ends — the usual call at boot — still ends its
// transaction and gives its connection back. Left open, the transaction
// would keep the connection checked out (on PostgreSQL, "idle in
// transaction (aborted)") for the life of the pool, one more at every
// retry. On a one-connection pool, the next Migrate, once the cause is
// gone, goes through.
func TestMigrateReleasesAFailedTransaction(t *testing.T) {
	t.Parallel()

	store, db := lockingStore(t, `CREATE TABLE migration_lock_probe (taken INTEGER)`)
	db.SetMaxOpenConns(1)

	last := schemaTables[len(schemaTables)-1]
	execAll(t, db, `CREATE TABLE blocker (x INTEGER)`, `CREATE INDEX `+last+` ON blocker (x)`)

	require.Error(t, store.Migrate(context.Background()))
	require.Zero(t, db.Stats().InUse, "the failed Migrate gave its connection back")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx, `DROP INDEX `+last)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
}

// TestMigrateReportsAFailedCommit: a COMMIT that fails — here on a deferred
// foreign key the lock statement violates — fails Migrate.
func TestMigrateReportsAFailedCommit(t *testing.T) {
	t.Parallel()

	store, db := lockingStore(t, `INSERT INTO child (parent_id) VALUES (42)`)
	execAll(t, db,
		`CREATE TABLE parent (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE child (parent_id INTEGER REFERENCES parent (id) DEFERRABLE INITIALLY DEFERRED)`)

	err := store.Migrate(t.Context())
	require.ErrorContains(t, err, "sqlstore: migrate: commit: ")
	require.ErrorContains(t, err, "FOREIGN KEY constraint failed")
}

// TestMigrateReportsAFailedBegin: a transaction that cannot begin fails
// Migrate.
func TestMigrateReportsAFailedBegin(t *testing.T) {
	t.Parallel()

	store, db := lockingStore(t, `SELECT 1`)
	require.NoError(t, db.Close())

	require.ErrorContains(t, store.Migrate(t.Context()), "sqlstore: migrate: begin: ")
}
