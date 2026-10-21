// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstores_test

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	oauth2sql "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/stretchr/testify/require"
)

// lockingServers are the servers with row locks: SQLite's single writer
// serializes the store's transactions instead.
var lockingServers = []backend{postgres, mysql80, mysql84, mariadb}

// placeholders rewrites the ? of query into PostgreSQL's $1, $2, … on e.
func placeholders(e engine, query string) string {
	if e != enginePostgres {
		return query
	}

	var b strings.Builder

	n := 0

	for _, r := range query {
		if r != '?' {
			b.WriteRune(r)

			continue
		}

		n++

		b.WriteString("$" + strconv.Itoa(n))
	}

	return b.String()
}

// lockHolder is a transaction of the test holding row locks, on a
// connection of its own whose server-side ID — the backend PID on
// PostgreSQL, CONNECTION_ID() on MySQL — identifies the sessions it blocks.
type lockHolder struct {
	t      *testing.T
	engine engine
	conn   *sql.Conn
	tx     *sql.Tx
	id     int64
}

// holdLocks opens a transaction on db and runs each statement in it — a
// SELECT … FOR UPDATE, an UPDATE — so that it holds their row locks.
func holdLocks(t *testing.T, db *sql.DB, e engine, stmts ...stmt) *lockHolder {
	t.Helper()

	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	h := &lockHolder{t: t, engine: e, conn: conn}

	idQuery := "SELECT CONNECTION_ID()"
	if e == enginePostgres {
		idQuery = "SELECT pg_backend_pid()"
	}

	require.NoError(t, conn.QueryRowContext(t.Context(), idQuery).Scan(&h.id))

	h.tx, err = conn.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.tx.Rollback() })

	h.exec(stmts...)

	return h
}

// stmt is a statement with its arguments, written with ? placeholders.
type stmt struct {
	query string
	args  []any
}

// exec runs stmts in the holder's transaction.
func (h *lockHolder) exec(stmts ...stmt) {
	h.t.Helper()

	for _, s := range stmts {
		_, err := h.tx.ExecContext(h.t.Context(), placeholders(h.engine, s.query), s.args...)
		require.NoError(h.t, err, s.query)
	}
}

// commit ends the holder's transaction, releasing its locks.
func (h *lockHolder) commit() {
	h.t.Helper()

	require.NoError(h.t, h.tx.Commit())
}

// lockWaitDeadline bounds the wait for a session to block on a holder,
// polled every lockWaitPoll: a MySQL sys.innodb_lock_waits query latches
// the lock system, so polling it in a tight loop keeps the waiting session
// from enqueuing its wait.
const (
	lockWaitDeadline = 10 * time.Second
	lockWaitPoll     = 100 * time.Millisecond
)

// waitForWaiter returns once the server reports a session waiting for one
// of the holder's locks — that session, not another test's: the query
// names the holder. It reads through admin, another pool on the server.
func (h *lockHolder) waitForWaiter(admin *sql.DB) {
	h.t.Helper()

	query := `SELECT COUNT(*) FROM sys.innodb_lock_waits WHERE blocking_pid = ?`
	if h.engine == enginePostgres {
		query = `SELECT COUNT(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))`
	}

	deadline := time.Now().Add(lockWaitDeadline)

	for {
		var waiters int
		require.NoError(h.t, admin.QueryRowContext(h.t.Context(), query, h.id).Scan(&waiters))

		if waiters > 0 {
			return
		}

		require.True(h.t, time.Now().Before(deadline), "no session waited for the holder's locks within %s", lockWaitDeadline)
		time.Sleep(lockWaitPoll)
	}
}

// lockingStore returns a migrated oauth2 store on a new namespace of b, its
// pool, and an admin pool for the lock-wait queries.
func lockingStore(t *testing.T, b backend) (store *oauth2sql.Store, db, admin *sql.DB) {
	t.Helper()

	driver, dsn := b.namespace(t)
	db = open(t, driver, dsn, 4)
	admin = open(t, driver, dsn, 1)

	store, err := oauth2sql.New(db, oauth2Dialect(b.engine))
	require.NoError(t, err)
	require.NoError(t, store.Migrate(t.Context()))

	return store, db, admin
}

// rotateInBackground starts the rotation of from into next and returns the
// channel its result arrives on.
func rotateInBackground(store *oauth2sql.Store, from, next *oauth2.TokenPair) <-chan error {
	done := make(chan error, 1)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		done <- store.RotateRefreshToken(ctx, from.Refresh.TokenHash, next)
	}()

	return done
}

// countRows returns the number of rows of table whose key column holds key.
func countRows(t *testing.T, db *sql.DB, e engine, table, column, key string) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(),
		placeholders(e, "SELECT COUNT(*) FROM "+table+" WHERE "+column+" = ?"), key).Scan(&n))

	return n
}

// requireNotPersisted asserts that no token of pair was written.
func requireNotPersisted(t *testing.T, db *sql.DB, e engine, pair *oauth2.TokenPair) {
	t.Helper()

	require.Zero(t, countRows(t, db, e, "oauth2_access_tokens", "token_hash", pair.Access.TokenHash), "access token persisted")
	require.Zero(t, countRows(t, db, e, "oauth2_refresh_tokens", "token_hash", pair.Refresh.TokenHash), "refresh token persisted")
}

// TestOAuth2RotationWaitsForTheFamilyLock pins the family row lock (I-25,
// the first locking layer): a revocation holds the family's row while a
// rotation of one of its tokens starts. The rotation waits for it, then
// finds the family revoked: it fails with ErrTokenFamilyRevoked and writes
// nothing. A rotation reading the family without the lock would not wait:
// it would read the family active and write its tokens into a family being
// revoked (on PostgreSQL; on MySQL the family upsert, INSERT … ON
// DUPLICATE KEY UPDATE, takes the row lock first).
func TestOAuth2RotationWaitsForTheFamilyLock(t *testing.T) {
	for _, b := range lockingServers {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			store, db, admin := lockingStore(t, b)

			first, next := tokenPair("lock-family-0", "fam-lock"), tokenPair("lock-family-1", "fam-lock")
			require.NoError(t, store.SaveTokenPair(t.Context(), first))

			holder := holdLocks(t, db, b.engine,
				stmt{`SELECT revoked_at FROM oauth2_token_families WHERE family_id = ? FOR UPDATE`, []any{"fam-lock"}})

			done := rotateInBackground(store, first, next)
			holder.waitForWaiter(admin)

			holder.exec(stmt{`UPDATE oauth2_token_families SET revoked_at = ? WHERE family_id = ?`,
				[]any{time.Now().Unix(), "fam-lock"}})
			holder.commit()

			require.ErrorIs(t, <-done, oauth2.ErrTokenFamilyRevoked)
			requireNotPersisted(t, db, b.engine, next)

			var consumed int
			require.NoError(t, db.QueryRowContext(t.Context(), placeholders(b.engine,
				`SELECT consumed FROM oauth2_refresh_tokens WHERE token_hash = ?`), first.Refresh.TokenHash).Scan(&consumed))
			require.Zero(t, consumed, "the presented token is not consumed")
		})
	}
}

// TestOAuth2RotationLocksThePresentedToken pins the refresh-token row lock
// (I-25, the second locking layer): another writer holds the presented
// token's row and consumes it while a rotation starts. The rotation waits
// for it, then finds the token consumed: a reuse, which revokes the
// family. A rotation reading the token without the lock would see it
// unconsumed and stop on the third layer — its UPDATE consuming no row — as
// a backend error, not as the reuse it is.
func TestOAuth2RotationLocksThePresentedToken(t *testing.T) {
	for _, b := range lockingServers {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			store, db, admin := lockingStore(t, b)

			first, next := tokenPair("lock-token-0", "fam-lock-token"), tokenPair("lock-token-1", "fam-lock-token")
			require.NoError(t, store.SaveTokenPair(t.Context(), first))

			holder := holdLocks(t, db, b.engine,
				stmt{`SELECT consumed FROM oauth2_refresh_tokens WHERE token_hash = ? FOR UPDATE`, []any{first.Refresh.TokenHash}})

			done := rotateInBackground(store, first, next)
			holder.waitForWaiter(admin)

			holder.exec(stmt{`UPDATE oauth2_refresh_tokens SET consumed = 1 WHERE token_hash = ?`, []any{first.Refresh.TokenHash}})
			holder.commit()

			err := <-done
			require.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
			require.NotErrorIs(t, err, oauth2.ErrTokenFamilyRevocationFailed)
			requireNotPersisted(t, db, b.engine, next)

			_, err = store.LookupAccessToken(t.Context(), first.Access.TokenHash)
			require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, "the reuse revoked the family")
		})
	}
}
