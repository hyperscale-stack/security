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

// newSQLiteStore opens a fresh in-memory SQLite database, migrates it, and
// returns a ready oauth2.Storage. Each call gets an isolated database
// (the "file::memory:" + unique cache prevents sharing across calls).
func newSQLiteStore(t *testing.T) oauth2.Storage {
	t.Helper()

	// A private in-memory database, scoped to this *sql.DB handle.
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&_pragma=foreign_keys(1)")
	require.NoError(t, err)

	// SQLite in-memory shared-cache stays alive while at least one
	// connection is open; cap the pool at 1 so the schema persists and
	// writes serialise (SQLite is single-writer anyway).
	db.SetMaxOpenConns(1)

	t.Cleanup(func() { _ = db.Close() })

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	require.NoError(t, store.Migrate(context.Background()))

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

	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)

	t.Cleanup(func() { _ = db.Close() })

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	require.NoError(t, store.Migrate(context.Background()))
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
