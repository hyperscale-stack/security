// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	sqlstore "github.com/hyperscale-stack/security/saml/sp/store/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedSAMLPurge stores, as of now, a transaction and a replay mark expired
// before it, and of each one expiring at now and one live: PurgeExpired
// deletes the first two only.
func seedSAMLPurge(t *testing.T, s *sqlstore.Store, now time.Time) {
	t.Helper()

	ctx := t.Context()

	for label, expires := range map[string]time.Time{
		"expired": now.Add(-time.Hour), "boundary": now, "live": now.Add(time.Hour),
	} {
		require.NoError(t, s.SaveTransaction(ctx, &samlsp.TransactionRecord{
			ID: key("tx/" + label), BindingHash: key("b/" + label), Payload: `{"v":1}`,
			ExpiresAt: expires, Integrity: key("i/" + label),
		}))
		require.NoError(t, s.MarkAssertionUsed(ctx, key("as/"+label), expires))
	}
}

func samlRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&n))

	return n
}

// TestSQLPurgeExpired deletes the transactions and replay marks expired
// before now — never one expiring at now: a mark is kept at least until
// its expiry — and a second purge deletes nothing.
func TestSQLPurgeExpired(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	now := time.Unix(time.Now().Unix(), 0)
	seedSAMLPurge(t, store, now)

	n, err := store.PurgeExpired(t.Context(), now)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	assert.Equal(t, 2, samlRows(t, db, "samlsp_transactions"))
	assert.Equal(t, 2, samlRows(t, db, "samlsp_used_assertions"))

	require.ErrorIs(t, store.MarkAssertionUsed(t.Context(), key("as/boundary"), now), samlsp.ErrAssertionReplayed,
		"the mark expiring at now is kept")

	n, err = store.PurgeExpired(t.Context(), now)
	require.NoError(t, err)
	assert.Zero(t, n)
}

// TestSQLPurgeExpiredFailures: a failing statement or transaction fails
// the purge.
func TestSQLPurgeExpiredFailures(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	unmigrated, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	n, err := unmigrated.PurgeExpired(t.Context(), time.Now())
	require.ErrorContains(t, err, "sqlstore: purge expired rows: ")
	assert.Zero(t, n)

	store, _ := openSQLite(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = store.PurgeExpired(ctx, time.Now())
	require.ErrorIs(t, err, context.Canceled)
}

// TestSQLPurgeExpiredDriverFailures: a row count the driver cannot give,
// and a transaction it cannot begin at READ COMMITTED, fail the purge.
func TestSQLPurgeExpiredDriverFailures(t *testing.T) {
	t.Parallel()

	store := openFaultyDialect(t, &faultyConn{rowsAffectedErr: errors.New("no row count")}, sqlstore.SQLite)
	_, err := store.PurgeExpired(t.Context(), time.Now())
	require.ErrorContains(t, err, "sqlstore: purge expired rows: rows affected: no row count")

	store = openFaultyDialect(t, &faultyConn{}, sqlstore.Postgres)
	_, err = store.PurgeExpired(t.Context(), time.Now())
	require.ErrorContains(t, err, "sqlstore: purge expired rows: begin: ")
}
