// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	sqlstore "github.com/hyperscale-stack/security/saml/sp/store/sql"
	"github.com/hyperscale-stack/security/saml/sp/storetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// openSQLite opens a private in-memory SQLite database (one connection: a
// ":memory:" database lives in its connection) and migrates it.
func openSQLite(t *testing.T) (*sqlstore.Store, *sql.DB) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(context.Background()))

	return store, db
}

// TestSQLiteStoreConformance runs the shared storage contract, races
// included, on SQLite.
func TestSQLiteStoreConformance(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() samlsp.Storage {
		store, _ := openSQLite(t)

		return store
	})
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()

	store, _ := openSQLite(t)
	require.NoError(t, store.Migrate(context.Background()))
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

func TestDialects(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "postgres", sqlstore.Postgres.Name())
	assert.Equal(t, "mysql", sqlstore.MySQL.Name())
	assert.Equal(t, "sqlite", sqlstore.SQLite.Name())
}

func TestSchemaIsPortable(t *testing.T) {
	t.Parallel()

	for _, d := range []sqlstore.Dialect{sqlstore.Postgres, sqlstore.MySQL, sqlstore.SQLite} {
		stmts := sqlstore.Schema(d)
		require.Equal(t, sqlstore.Schema(sqlstore.SQLite), stmts, "same DDL for %s", d.Name())

		for _, s := range stmts {
			upper := strings.ToUpper(s)
			assert.NotContains(t, upper, "BOOLEAN")
			assert.NotContains(t, upper, "CREATE INDEX")
			assert.NotContains(t, upper, "TIMESTAMP")
			assert.Contains(t, upper, "IF NOT EXISTS")
		}
	}
}

func key(label string) string {
	sum := sha256.Sum256([]byte(label))

	return hex.EncodeToString(sum[:])
}

func record(label string) *samlsp.TransactionRecord {
	return &samlsp.TransactionRecord{
		ID: key("tx/" + label), BindingHash: key("b/" + label), Payload: `{"v":1}`,
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second), Integrity: key("i/" + label),
	}
}

func TestStoredValues(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	ctx := context.Background()
	rec := record("stored")

	require.NoError(t, store.SaveTransaction(ctx, rec))
	require.NoError(t, store.MarkAssertionUsed(ctx, key("a"), rec.ExpiresAt))

	var (
		binding, payload, integrity string
		consumed                    int
		expires                     int64
	)

	require.NoError(t, db.QueryRow(`SELECT binding_hash, payload, consumed, expires_at, integrity FROM samlsp_transactions WHERE id = ?`, rec.ID).
		Scan(&binding, &payload, &consumed, &expires, &integrity))
	assert.Equal(t, rec.BindingHash, binding)
	assert.Equal(t, rec.Payload, payload)
	assert.Equal(t, rec.Integrity, integrity)
	assert.Equal(t, 0, consumed)
	assert.Equal(t, rec.ExpiresAt.Unix(), expires)

	require.NoError(t, store.ConsumeTransaction(ctx, rec.ID, rec.BindingHash))
	require.NoError(t, db.QueryRow(`SELECT consumed FROM samlsp_transactions WHERE id = ?`, rec.ID).Scan(&consumed))
	assert.Equal(t, 1, consumed, "a consumed row is kept (replays are reported as such)")

	require.NoError(t, db.QueryRow(`SELECT expires_at FROM samlsp_used_assertions WHERE assertion_key = ?`, key("a")).Scan(&expires))
	assert.Equal(t, rec.ExpiresAt.Unix(), expires)
}

// TestPreIntegrityTableIsAStoreFailure: on a table created before the
// integrity column (Migrate never alters a table), saving fails as an
// infrastructure error, never as a rejection or a silent success.
func TestPreIntegrityTableIsAStoreFailure(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`CREATE TABLE samlsp_transactions (
		id           VARCHAR(64) PRIMARY KEY,
		binding_hash VARCHAR(64) NOT NULL,
		payload      TEXT        NOT NULL,
		consumed     SMALLINT    NOT NULL DEFAULT 0,
		expires_at   BIGINT      NOT NULL
	)`)
	require.NoError(t, err)

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(context.Background()), "Migrate leaves the existing table as it is")

	err = store.SaveTransaction(context.Background(), record("old table"))
	require.Error(t, err)
	require.NotErrorIs(t, err, samlsp.ErrRejected)
	require.NotErrorIs(t, err, samlsp.ErrTransactionExists)
}

func TestInsertFailureIsNotAConflict(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	ctx := context.Background()

	_, err := db.Exec(`CREATE TRIGGER refuse_tx BEFORE INSERT ON samlsp_transactions BEGIN SELECT RAISE(ABORT, 'boom'); END`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TRIGGER refuse_as BEFORE INSERT ON samlsp_used_assertions BEGIN SELECT RAISE(ABORT, 'boom'); END`)
	require.NoError(t, err)

	err = store.SaveTransaction(ctx, record("x"))
	require.Error(t, err)
	require.NotErrorIs(t, err, samlsp.ErrTransactionExists, "classified by reading the key, not by the error")

	err = store.MarkAssertionUsed(ctx, key("a"), time.Now().Add(time.Hour).Truncate(time.Second))
	require.Error(t, err)
	require.NotErrorIs(t, err, samlsp.ErrAssertionReplayed)
}

func TestInfrastructureFailures(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	ctx := context.Background()

	_, err := db.Exec(`DROP TABLE samlsp_transactions`)
	require.NoError(t, err)
	_, err = db.Exec(`DROP TABLE samlsp_used_assertions`)
	require.NoError(t, err)

	errs := []error{
		store.SaveTransaction(ctx, record("x")),
		store.ConsumeTransaction(ctx, key("x"), key("b")),
		store.MarkAssertionUsed(ctx, key("a"), time.Now().Add(time.Hour).Truncate(time.Second)),
	}

	_, lookupErr := store.LookupTransaction(ctx, key("x"))
	errs = append(errs, lookupErr)

	for _, err := range errs {
		require.Error(t, err)
		require.NotErrorIs(t, err, samlsp.ErrRejected, "an infrastructure failure is not a rejection")
	}

	require.NoError(t, db.Close())

	_, err = store.LookupTransaction(ctx, key("x"))
	require.Error(t, err)
}

func TestInvalidInputsNeverReachTheDatabase(t *testing.T) {
	t.Parallel()

	store, _ := openSQLite(t)
	ctx := context.Background()

	require.ErrorIs(t, store.SaveTransaction(ctx, &samlsp.TransactionRecord{}), samlsp.ErrInvalidStoreRecord)

	_, err := store.LookupTransaction(ctx, "x")
	require.ErrorIs(t, err, samlsp.ErrInvalidStoreRecord)
	require.ErrorIs(t, store.ConsumeTransaction(ctx, "x", key("b")), samlsp.ErrInvalidStoreRecord)
	require.ErrorIs(t, store.ConsumeTransaction(ctx, key("x"), "b"), samlsp.ErrInvalidStoreRecord)
	require.ErrorIs(t, store.MarkAssertionUsed(ctx, "k", time.Now()), samlsp.ErrInvalidStoreRecord)
	require.ErrorIs(t, store.MarkAssertionUsed(ctx, key("k"), time.Time{}), samlsp.ErrInvalidStoreRecord)
}
