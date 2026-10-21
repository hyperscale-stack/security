// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	moderncsqlite "modernc.org/sqlite"
)

// fakeLocks stands in for MySQL's GET_LOCK and RELEASE_LOCK on SQLite: the
// lock name picks the server's answer, and every call is recorded.
var fakeLocks = struct {
	sync.Mutex

	calls []string
}{}

// The lock names of the fake and the answer they get.
const (
	lockGranted      = "granted"       // GET_LOCK 1, RELEASE_LOCK 1
	lockTimedOut     = "timed-out"     // GET_LOCK 0
	lockNull         = "null"          // GET_LOCK NULL
	lockFails        = "fails"         // GET_LOCK errors
	lockReleaseFails = "release-fails" // GET_LOCK 1, RELEASE_LOCK 0
)

func init() {
	moderncsqlite.MustRegisterScalarFunction("GET_LOCK", 2, func(_ *moderncsqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		name, _ := args[0].(string)
		record(fmt.Sprintf("GET_LOCK(%s, %v)", name, args[1]))

		switch name {
		case lockTimedOut:
			return int64(0), nil
		case lockNull:
			return nil, nil
		case lockFails:
			return nil, errors.New("lock service down")
		default:
			return int64(1), nil
		}
	})
	moderncsqlite.MustRegisterScalarFunction("RELEASE_LOCK", 1, func(_ *moderncsqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		name, _ := args[0].(string)
		record("RELEASE_LOCK(" + name + ")")

		if name == lockReleaseFails {
			return int64(0), nil
		}

		return int64(1), nil
	})
}

func record(call string) {
	fakeLocks.Lock()
	defer fakeLocks.Unlock()

	fakeLocks.calls = append(fakeLocks.calls, call)
}

// lockCalls returns the recorded calls naming lock.
func lockCalls(lock string) []string {
	fakeLocks.Lock()
	defer fakeLocks.Unlock()

	var calls []string

	for _, c := range fakeLocks.calls {
		if strings.HasPrefix(c, "GET_LOCK("+lock+", ") || c == "RELEASE_LOCK("+lock+")" {
			calls = append(calls, c)
		}
	}

	return calls
}

// namedLockStore returns a store over a new SQLite database file whose
// dialect — a mock — names lock as its named migration lock, so that
// Migrate takes the MySQL path: lock, tables, check, release, on one
// connection. check is what the deployment check returns.
func namedLockStore(t *testing.T, lock string, check error) (*Store, *sql.DB) {
	t.Helper()

	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "named.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	d := NewMockDialect(t)
	d.EXPECT().namedMigrationLock().Return(lock)
	d.EXPECT().tableOptions().Return("").Maybe()
	d.EXPECT().checkDeployment(mock.Anything, mock.AnythingOfType("*sql.Conn")).Return(check).Maybe()

	return &Store{db: db, dialect: d}, db
}

// TestMigrateUnderNamedLock: Migrate takes the named lock, waiting as long
// as its context allows, creates the tables, runs the deployment check on
// the connection holding the lock, and releases it — after a failed check
// too.
func TestMigrateUnderNamedLock(t *testing.T) {
	store, db := namedLockStore(t, lockGranted, nil)

	require.NoError(t, store.Migrate(context.Background()))
	assert.Equal(t, schemaTables, tables(t, db))
	assert.Equal(t, []string{
		fmt.Sprintf("GET_LOCK(%s, %d)", lockGranted, lockWaitForever), "RELEASE_LOCK(" + lockGranted + ")",
	}, lockCalls(lockGranted))
	assert.Equal(t, 1, db.Stats().Idle, "the connection goes back to the pool")

	unmet := fmt.Errorf("%w: table oidc_client_transactions uses the MyISAM engine, not InnoDB", ErrDeploymentRequirement)
	failing, _ := namedLockStore(t, lockGranted+"-check", unmet)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.ErrorIs(t, failing.Migrate(ctx), unmet)
	assert.Equal(t, []string{
		"GET_LOCK(" + lockGranted + "-check, 30)", "RELEASE_LOCK(" + lockGranted + "-check)",
	}, lockCalls(lockGranted+"-check"), "the wait follows the deadline; a failed check releases the lock")
}

// TestMigrateNamedLockRefused: a lock the server does not grant — timed
// out, NULL, an error — stops Migrate before any table is created, and
// nothing is released.
func TestMigrateNamedLockRefused(t *testing.T) {
	for lock, want := range map[string]string{
		lockTimedOut: "sqlstore: migrate: lock timed-out: context deadline exceeded",
		lockNull:     "sqlstore: migrate: lock null: not granted",
		lockFails:    "sqlstore: migrate: lock fails: SQL logic error: lock service down (1)",
	} {
		store, db := namedLockStore(t, lock, nil)

		err := store.Migrate(context.Background())
		require.EqualError(t, err, want)
		assert.Empty(t, tables(t, db), lock)
		assert.NotContains(t, lockCalls(lock), "RELEASE_LOCK("+lock+")", lock)
	}

	store, _ := namedLockStore(t, lockTimedOut, nil)
	require.ErrorIs(t, store.Migrate(context.Background()), context.DeadlineExceeded)
}

// TestMigrateDiscardsAConnectionWhoseLockIsUnknown: a GET_LOCK that fails
// leaves the lock's state unknown — the server may have granted it before
// the reply was lost — so the connection is discarded, never pooled with
// the server-wide migration lock possibly held.
func TestMigrateDiscardsAConnectionWhoseLockIsUnknown(t *testing.T) {
	store, db := namedLockStore(t, lockFails, nil)

	require.Error(t, store.Migrate(context.Background()))
	assert.Zero(t, db.Stats().OpenConnections, "the connection is closed, not pooled")

	timedOut, timedOutDB := namedLockStore(t, lockTimedOut, nil)

	require.Error(t, timedOut.Migrate(context.Background()))
	assert.Equal(t, 1, timedOutDB.Stats().Idle, "a lock refused for sure keeps its connection")
}

// TestMigrateNamedLockFailures: no connection, or a failing statement,
// fails Migrate; a failing statement releases the lock first.
func TestMigrateNamedLockFailures(t *testing.T) {
	store, db := namedLockStore(t, lockGranted+"-closed", nil)
	require.NoError(t, db.Close())
	require.ErrorContains(t, store.Migrate(context.Background()), "sqlstore: migrate: connection: ")

	store, db = namedLockStore(t, lockGranted+"-blocked", nil)
	last := schemaTables[len(schemaTables)-1]
	execAll(t, db, `CREATE TABLE blocker (x INTEGER)`, `CREATE INDEX `+last+` ON blocker (x)`)

	require.ErrorContains(t, store.Migrate(context.Background()), "already an index named "+last)
	assert.Contains(t, lockCalls(lockGranted+"-blocked"), "RELEASE_LOCK("+lockGranted+"-blocked)")
}

// TestMigrateDiscardsAConnectionKeepingTheLock: a release the server
// refuses discards the connection, whose session would keep the lock.
func TestMigrateDiscardsAConnectionKeepingTheLock(t *testing.T) {
	store, db := namedLockStore(t, lockReleaseFails, nil)

	require.NoError(t, store.Migrate(context.Background()))
	assert.Contains(t, lockCalls(lockReleaseFails), "RELEASE_LOCK("+lockReleaseFails+")")
	assert.Zero(t, db.Stats().OpenConnections, "the connection is closed, not pooled")
}

func TestLockWaitSeconds(t *testing.T) {
	t.Parallel()

	assert.Equal(t, int64(lockWaitForever), lockWaitSeconds(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	assert.Equal(t, int64(2), lockWaitSeconds(ctx), "rounded up")

	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()

	assert.Equal(t, int64(1), lockWaitSeconds(expired), "at least one second")
}

func TestNamedMigrationLock(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "hyperscale-stack/security/oidc/client/store/sql.Migrate", MySQL.namedMigrationLock())
	assert.Empty(t, Postgres.namedMigrationLock())
	assert.Empty(t, SQLite.namedMigrationLock())
}
