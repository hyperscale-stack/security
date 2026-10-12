// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	sqlstore "github.com/hyperscale-stack/security/oidc/client/store/sql"
	"github.com/hyperscale-stack/security/oidc/client/storetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // pure-Go SQLite driver — no cgo, no Docker
)

// open opens the SQLite database dsn with a pool of conns connections,
// migrates it, and returns the store with the raw handle, which tests use
// to inspect the table and inject failures.
func open(t *testing.T, dsn string, conns int) (*sqlstore.Store, *sql.DB) {
	t.Helper()

	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(conns)

	t.Cleanup(func() { _ = db.Close() })

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(t.Context()))

	return store, db
}

// openMemory opens a private in-memory database. A ":memory:" database
// lives in its connection, so the pool is capped at one connection.
func openMemory(t *testing.T) (*sqlstore.Store, *sql.DB) {
	t.Helper()

	return open(t, ":memory:", 1)
}

// openFile opens a database file shared by several connections.
func openFile(t *testing.T, pragmas ...string) (*sqlstore.Store, *sql.DB) {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "transactions.db") + "?_pragma=busy_timeout(30000)"
	for _, p := range pragmas {
		dsn += "&_pragma=" + p
	}

	return open(t, dsn, 8)
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

// sample returns a valid transaction unique per seed.
func sample(seed string, created, expires time.Time) *oidcclient.Transaction {
	return &oidcclient.Transaction{
		StateHash:    hash("state-" + seed),
		BindingHash:  hash("binding-" + seed),
		ConnectionID: "acme",
		Issuer:       "https://idp.example.com",
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/oidc/acme/callback",
		ResponseMode: oidcclient.ResponseModeQuery,
		MaxAge:       oidcclient.NoMaxAge,
		CreatedAt:    created,
		ExpiresAt:    expires,
	}
}

// now is the current time in whole seconds.
func now() time.Time { return time.Unix(time.Now().Unix(), 0).UTC() }

func rows(t *testing.T, db *sql.DB) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM oidc_client_transactions`).Scan(&n))

	return n
}

func TestConformance(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oidcclient.TransactionStore {
		store, _ := openMemory(t)

		return store
	})
}

// TestConformanceConcurrentConnections runs the suite on a database file
// shared by eight connections, in both journal modes: the concurrent
// consumers of the suite then contend for SQLite's write lock across
// connections, which the write opening Consume takes before any read —
// otherwise a consumer upgrading a read lock gets SQLITE_BUSY instead of a
// verdict.
func TestConformanceConcurrentConnections(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"delete", "wal"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			storetest.RunConformance(t, func() oidcclient.TransactionStore {
				store, _ := openFile(t, "journal_mode("+mode+")")

				return store
			})
		})
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()

	store, _ := openMemory(t)
	require.NoError(t, store.Migrate(t.Context()), "a second Migrate is a no-op")
}

func TestNewValidatesArguments(t *testing.T) {
	t.Parallel()

	_, err := sqlstore.New(nil, sqlstore.SQLite)
	require.Error(t, err)

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = sqlstore.New(db, nil)
	require.Error(t, err)
}

func TestDialectNames(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "postgres", sqlstore.Postgres.Name())
	assert.Equal(t, "mysql", sqlstore.MySQL.Name())
	assert.Equal(t, "sqlite", sqlstore.SQLite.Name())
}

// TestSchemaIsPortable pins a DDL every supported engine accepts:
// PostgreSQL has no implicit integer/boolean cast and MySQL has no CREATE
// INDEX IF NOT EXISTS, so the schema is the same for every dialect.
func TestSchemaIsPortable(t *testing.T) {
	t.Parallel()

	want := sqlstore.Schema(sqlstore.SQLite)
	require.Len(t, want, 1)

	for _, d := range []sqlstore.Dialect{sqlstore.Postgres, sqlstore.MySQL} {
		assert.Equal(t, want, sqlstore.Schema(d), d.Name())
	}

	assert.NotContains(t, strings.ToUpper(want[0]), "BOOLEAN")
	assert.NotContains(t, strings.ToUpper(want[0]), "CREATE INDEX")
	assert.Contains(t, want[0], "CREATE TABLE IF NOT EXISTS oidc_client_transactions")
}

// TestAppStateEncoding checks that the application state is stored
// base64-encoded and round-trips any UTF-8, NUL included.
func TestAppStateEncoding(t *testing.T) {
	t.Parallel()

	store, db := openMemory(t)
	at := now()
	tx := sample("app-state", at, at.Add(time.Minute))
	tx.AppState = "a\x00b \U0001F512 é"
	require.NoError(t, store.Save(t.Context(), tx))

	var raw string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT app_state FROM oidc_client_transactions`).Scan(&raw))
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(tx.AppState)), raw)

	got, err := store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.NoError(t, err)
	assert.Equal(t, tx.AppState, got.AppState)
}

// TestConsumeDeletesExpired checks that Consume purges the expired
// transaction it is asked for, whatever the binding.
func TestConsumeDeletesExpired(t *testing.T) {
	t.Parallel()

	store, db := openMemory(t)
	at := now()

	for _, binding := range []string{hash("binding-right"), hash("another browser")} {
		tx := sample("expired", at.Add(-time.Minute), at)
		tx.BindingHash = hash("binding-right")
		require.NoError(t, store.Save(t.Context(), tx))

		got, err := store.Consume(t.Context(), tx.StateHash, binding, at)
		require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
		assert.Nil(t, got)
		assert.Zero(t, rows(t, db), "the expired transaction is deleted")
	}
}

func TestPurgeExpired(t *testing.T) {
	t.Parallel()

	store, db := openMemory(t)
	at := now()

	atExpiry := sample("at-expiry", at.Add(-time.Hour), at)
	older := sample("older", at.Add(-2*time.Hour), at.Add(-time.Hour))
	live := sample("live", at.Add(-time.Minute), at.Add(time.Second))

	for _, tx := range []*oidcclient.Transaction{atExpiry, older, live} {
		require.NoError(t, store.Save(t.Context(), tx))
	}

	n, err := store.PurgeExpired(t.Context(), at)
	require.NoError(t, err)
	assert.EqualValues(t, 2, n, "now == ExpiresAt is expired")
	assert.Equal(t, 1, rows(t, db))

	got, err := store.Consume(t.Context(), live.StateHash, live.BindingHash, at)
	require.NoError(t, err)
	assert.Equal(t, live.StateHash, got.StateHash)

	n, err = store.PurgeExpired(t.Context(), at)
	require.NoError(t, err)
	assert.Zero(t, n)
}
