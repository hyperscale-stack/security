// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	sqlstore "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// unmigratedStore opens a private SQLite database WITHOUT running Migrate,
// so every statement fails with "no such table" — the cheap way to
// exercise the store's error-return branches. A plain ":memory:" DSN
// (no cache=shared) keeps the database isolated from the conformance
// suite's migrated databases.
func unmigratedStore(t *testing.T) *sqlstore.Store {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	return store
}

func TestSQLStoreReportsBackendErrors(t *testing.T) {
	t.Parallel()

	store := unmigratedStore(t)
	ctx := context.Background()
	now := time.Now()

	code := &oauth2.AuthorizationCode{
		CodeHash: "h", ClientID: "c", Subject: "s", RedirectURI: "u", Scope: "r",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	require.Error(t, store.SaveAuthorizationCode(ctx, code))

	_, err := store.ConsumeAuthorizationCode(ctx, "h")
	require.Error(t, err)

	pair := testPair("h", "f", time.Minute)
	require.Error(t, store.SaveTokenPair(ctx, pair))

	// Outside any family the pair skips the family record: the access
	// token insert is the failing statement.
	require.Error(t, store.SaveTokenPair(ctx, &oauth2.TokenPair{Access: oauth2.AccessToken{
		TokenHash: "h", ClientID: "c", Subject: "s", Scope: "r", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}}))

	_, err = store.LookupAccessToken(ctx, "h")
	require.Error(t, err)

	require.Error(t, store.RevokeAccessToken(ctx, "h"))

	_, err = store.LookupRefreshToken(ctx, "h")
	require.Error(t, err)

	require.Error(t, store.RotateRefreshToken(ctx, "h", testPair("next", "f", time.Minute)))
	require.ErrorIs(t, store.RevokeRefreshFamily(ctx, "f"), oauth2.ErrTokenFamilyRevocationFailed)
}

func TestSQLStoreRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	store := unmigratedStore(t)
	ctx := context.Background()
	tooLong := strings.Repeat("f", oauth2.MaxFamilyIDLength+1)
	bare := &oauth2.TokenPair{Access: oauth2.AccessToken{TokenHash: "h", FamilyID: "f"}}

	// Refused before any statement runs: the database has no table at all.
	for _, err := range []error{
		store.SaveAuthorizationCode(ctx, &oauth2.AuthorizationCode{}),
		store.SaveTokenPair(ctx, &oauth2.TokenPair{}),
		store.SaveTokenPair(ctx, nil),
		store.RotateRefreshToken(ctx, "h", nil),
		store.RotateRefreshToken(ctx, "h", bare),
		store.RevokeRefreshFamily(ctx, ""),
		store.RevokeRefreshFamily(ctx, tooLong),
	} {
		assert.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err), "%v", err)
	}
}

func TestSQLStoreReportsErrorsOnClosedDB(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	require.NoError(t, db.Close())

	ctx := context.Background()

	// BeginTx fails on a closed pool — exercises the "begin" error branch.
	_, err = store.ConsumeAuthorizationCode(ctx, "h")
	require.Error(t, err)

	require.Error(t, store.SaveTokenPair(ctx, testPair("h", "f", time.Minute)))
	require.Error(t, store.RotateRefreshToken(ctx, "h", testPair("next", "f", time.Minute)))
	require.ErrorIs(t, store.RevokeRefreshFamily(ctx, "f"), oauth2.ErrTokenFamilyRevocationFailed)
}
