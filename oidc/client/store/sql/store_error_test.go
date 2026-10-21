// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	sqlstore "github.com/hyperscale-stack/security/oidc/client/store/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inject creates a trigger running action — RAISE(ABORT, …) or
// RAISE(IGNORE) — on every statement matching spec, a trigger event clause
// such as "BEFORE INSERT ON t", until the returned function drops it.
func inject(t *testing.T, db *sql.DB, spec, action string) func() {
	t.Helper()

	_, err := db.ExecContext(t.Context(), fmt.Sprintf(
		"CREATE TRIGGER injected %s BEGIN SELECT %s; END", spec, action))
	require.NoError(t, err)

	return func() {
		_, err := db.ExecContext(t.Context(), "DROP TRIGGER injected")
		require.NoError(t, err)
	}
}

const injectedAbort = "RAISE(ABORT, 'injected failure')"

// requireBackendError asserts err is a failure, not a verdict of the
// contract.
func requireBackendError(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	assert.NotErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	assert.NotErrorIs(t, err, oidcclient.ErrBindingMismatch)
	assert.NotErrorIs(t, err, oidcclient.ErrTransactionExists)
	assert.NotErrorIs(t, err, oidcclient.ErrInvalidTransaction)
}

func TestSaveFailureIsNotADuplicate(t *testing.T) {
	t.Parallel()

	store, db := openMemory(t)
	at := now()
	drop := inject(t, db, "BEFORE INSERT ON oidc_client_transactions", injectedAbort)

	tx := sample("insert-fails", at, at.Add(time.Minute))
	requireBackendError(t, store.Save(t.Context(), tx))

	drop()
	assert.Zero(t, rows(t, db))
	require.NoError(t, store.Save(t.Context(), tx))
}

// TestConsumeLostRace makes the final DELETE affect no row, as when a
// concurrent consumer won on a backend without row locks: Consume returns
// ErrTransactionNotFound and no transaction.
func TestConsumeLostRace(t *testing.T) {
	t.Parallel()

	store, db := openMemory(t)
	at := now()
	tx := sample("lost-race", at, at.Add(time.Minute))
	require.NoError(t, store.Save(t.Context(), tx))

	drop := inject(t, db, "BEFORE DELETE ON oidc_client_transactions", "RAISE(IGNORE)")

	got, err := store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	assert.Nil(t, got)

	drop()

	got, err = store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	require.NoError(t, err)
	assert.Equal(t, tx.StateHash, got.StateHash)
}

// TestConsumeDeleteFailure checks both DELETEs of Consume: a failure
// returns no transaction and rolls back, keeping the record.
func TestConsumeDeleteFailure(t *testing.T) {
	t.Parallel()

	for name, consumeAt := range map[string]func(*oidcclient.Transaction) time.Time{
		"opening delete of an expired transaction": func(tx *oidcclient.Transaction) time.Time { return tx.ExpiresAt },
		"final delete": func(tx *oidcclient.Transaction) time.Time { return tx.CreatedAt },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store, db := openMemory(t)
			at := now()
			tx := sample("delete-fails", at, at.Add(time.Minute))
			require.NoError(t, store.Save(t.Context(), tx))

			drop := inject(t, db, "BEFORE DELETE ON oidc_client_transactions", injectedAbort)

			got, err := store.Consume(t.Context(), tx.StateHash, tx.BindingHash, consumeAt(tx))
			requireBackendError(t, err)
			assert.Nil(t, got)

			drop()
			assert.Equal(t, 1, rows(t, db), "rolled back")
		})
	}
}

// TestConsumeCorruptRow checks that a row the store cannot read fails the
// login and stays.
func TestConsumeCorruptRow(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"non-numeric timestamp": `UPDATE oidc_client_transactions SET created_at = 'soon'`,
		"app state not base64":  `UPDATE oidc_client_transactions SET app_state = '!!!'`,
	}

	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store, db := openMemory(t)
			at := now()
			tx := sample("corrupt", at, at.Add(time.Minute))
			require.NoError(t, store.Save(t.Context(), tx))

			_, err := db.ExecContext(t.Context(), corrupt)
			require.NoError(t, err)

			got, err := store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
			requireBackendError(t, err)
			assert.Nil(t, got)
			assert.Equal(t, 1, rows(t, db))
		})
	}
}

// TestConsumeCommitFailure makes COMMIT fail — a deferred foreign key
// pins the row — and checks that no transaction is returned: a record is
// handed out only once its deletion is committed.
func TestConsumeCommitFailure(t *testing.T) {
	t.Parallel()

	store, db := openFile(t, "foreign_keys(1)")
	at := now()
	tx := sample("commit-fails", at, at.Add(time.Minute))
	require.NoError(t, store.Save(t.Context(), tx))

	_, err := db.ExecContext(t.Context(), `CREATE TABLE pins (
		state_hash VARCHAR(64) REFERENCES oidc_client_transactions (state_hash) DEFERRABLE INITIALLY DEFERRED)`)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `INSERT INTO pins VALUES (?)`, tx.StateHash)
	require.NoError(t, err)

	got, err := store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	requireBackendError(t, err)
	assert.Nil(t, got)
}

// TestBackendErrors runs every operation on a database without the table.
func TestBackendErrors(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	at := now()
	tx := sample("no-table", at, at.Add(time.Minute))

	requireBackendError(t, store.Save(t.Context(), tx))

	_, err = store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	requireBackendError(t, err)

	_, err = store.PurgeExpired(t.Context(), at)
	requireBackendError(t, err)

	require.NoError(t, db.Close())

	_, err = store.Consume(t.Context(), tx.StateHash, tx.BindingHash, at)
	requireBackendError(t, err)
	requireBackendError(t, store.Migrate(t.Context()))

	_, err = store.PurgeExpired(t.Context(), at)
	requireBackendError(t, err)
	require.ErrorContains(t, err, "sqlstore: purge expired transactions: begin: ")
}

// TestSaveRefusesInvalidBeforeIO checks Validate runs before any
// statement: the database has no table at all.
func TestSaveRefusesInvalidBeforeIO(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	require.ErrorIs(t, store.Save(t.Context(), &oidcclient.Transaction{}), oidcclient.ErrInvalidTransaction)
	require.ErrorIs(t, store.Save(t.Context(), nil), oidcclient.ErrInvalidTransaction)
}
