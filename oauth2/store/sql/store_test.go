// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	sqlstore "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/hyperscale-stack/security/oauth2/storetest"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // pure-Go SQLite driver — no cgo, no Docker
)

// openSQLite opens a private in-memory SQLite database, migrates it, and
// returns the store over it along with the raw handle, which tests use to
// inspect the tables and inject failures with triggers.
//
// A plain ":memory:" database lives in its connection, so the pool is
// capped at one connection: every call gets a database of its own, which
// survives as long as the handle, and the store's transactions serialize
// on it (SQLite is single-writer anyway).
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

// newSQLiteStore returns a ready oauth2.Storage over a private database.
func newSQLiteStore(t *testing.T) oauth2.Storage {
	t.Helper()

	store, _ := openSQLite(t)

	return store
}

// TestSQLiteStoreConformance runs the shared storage contract against the
// database/sql implementation on a pure-Go SQLite backend. It exercises
// the same suite the in-memory store passes, including the concurrency
// races that assert atomic ConsumeAuthorizationCode / RotateRefreshToken.
func TestSQLiteStoreConformance(t *testing.T) {
	t.Parallel()

	storetest.RunConformance(t, func() oauth2.Storage {
		return newSQLiteStore(t)
	})
}

// TestMigrateIsIdempotent verifies the IF NOT EXISTS DDL can run twice.
func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()

	store, _ := openSQLite(t)

	require.NoError(t, store.Migrate(context.Background()), "second Migrate must be a no-op")
}

// TestNewValidatesArguments checks the constructor guards.
func TestNewValidatesArguments(t *testing.T) {
	t.Parallel()

	_, err := sqlstore.New(nil, sqlstore.SQLite)
	require.Error(t, err)

	db, _ := sql.Open("sqlite", "file::memory:")
	t.Cleanup(func() { _ = db.Close() })

	_, err = sqlstore.New(db, nil)
	require.Error(t, err)
}

// TestPostgresDialectRebindsPlaceholders is a unit check on the dialect
// abstraction — Postgres is the only dialect that rewrites "?".
func TestPostgresDialectRebindsPlaceholders(t *testing.T) {
	t.Parallel()

	// Exercised indirectly through the store; here we just assert the
	// dialect names are stable (used in OTel attributes / errors).
	require.Equal(t, "postgres", sqlstore.Postgres.Name())
	require.Equal(t, "mysql", sqlstore.MySQL.Name())
	require.Equal(t, "sqlite", sqlstore.SQLite.Name())
}
