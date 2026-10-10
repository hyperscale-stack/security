// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// injected is the message of the failures the SQLite triggers inject.
const injected = "injected failure"

// testPair returns a pair in family whose tokens both expire after ttl.
func testPair(name, family string, ttl time.Duration) *oauth2.TokenPair {
	now := time.Now()

	return &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			TokenHash: "at-" + name, ClientID: "c", Subject: "s", Scope: "r", Audience: "api",
			FamilyID: family, IssuedAt: now, ExpiresAt: now.Add(ttl),
		},
		Refresh: &oauth2.RefreshToken{
			TokenHash: "rt-" + name, ClientID: "c", Subject: "s", Scope: "r",
			FamilyID: family, IssuedAt: now, ExpiresAt: now.Add(ttl),
		},
	}
}

// inject makes every statement matching spec — a SQLite trigger event
// clause such as "BEFORE INSERT ON t" — fail, until the test drops the
// trigger with the returned function.
func inject(t *testing.T, db *sql.DB, spec string) func() {
	t.Helper()

	_, err := db.ExecContext(t.Context(), fmt.Sprintf(
		"CREATE TRIGGER injected %s BEGIN SELECT RAISE(ABORT, '%s'); END", spec, injected))
	require.NoError(t, err)

	return func() {
		_, err := db.ExecContext(t.Context(), "DROP TRIGGER injected")
		require.NoError(t, err)
	}
}

// count runs a SELECT COUNT(*) query.
func count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), query, args...).Scan(&n))

	return n
}

// requirePersisted asserts how many rows of pair's tokens the tables hold.
func requirePersisted(t *testing.T, db *sql.DB, pair *oauth2.TokenPair, want int) {
	t.Helper()

	assert.Equal(t, want, count(t, db,
		"SELECT COUNT(*) FROM oauth2_access_tokens WHERE token_hash = ?", pair.Access.TokenHash),
		"access token %s", pair.Access.TokenHash)
	assert.Equal(t, want, count(t, db,
		"SELECT COUNT(*) FROM oauth2_refresh_tokens WHERE token_hash = ?", pair.Refresh.TokenHash),
		"refresh token %s", pair.Refresh.TokenHash)
}

// family reads the record of family straight from the table.
func family(t *testing.T, db *sql.DB, id string) (revokedAt, expiresAt int64) {
	t.Helper()

	require.NoError(t, db.QueryRowContext(t.Context(),
		"SELECT revoked_at, expires_at FROM oauth2_token_families WHERE family_id = ?", id,
	).Scan(&revokedAt, &expiresAt))

	return revokedAt, expiresAt
}

// requireUsable asserts that both tokens of pair can still be used.
func requireUsable(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.NoError(t, err)

	rt, err := s.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err)
	assert.False(t, rt.Consumed, "refresh token %s", pair.Refresh.TokenHash)
}

// requireUnusable asserts that no token of pair can be used any more.
func requireUnusable(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	assert.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)

	rt, err := s.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err)
	assert.True(t, rt.Consumed, "refresh token %s", pair.Refresh.TokenHash)
}

func TestSQLRevokeFamilyFailureIsReported(t *testing.T) {
	t.Parallel()

	// One failing statement per subtest — SQLite fires a BEFORE INSERT
	// trigger even when ON CONFLICT DO NOTHING then skips the row.
	cases := []struct{ name, trigger string }{
		{"recording the family", "BEFORE INSERT ON oauth2_token_families WHEN NEW.revoked_at <> 0"},
		{"marking it revoked", "BEFORE UPDATE OF revoked_at ON oauth2_token_families"},
		{"extending its retention", "BEFORE UPDATE OF expires_at ON oauth2_token_families"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, db := openSQLite(t)
			pair := testPair("revoke", "fam-revoke", time.Hour)
			require.NoError(t, store.SaveTokenPair(t.Context(), pair))

			drop := inject(t, db, tc.trigger)

			err := store.RevokeRefreshFamily(t.Context(), "fam-revoke")
			require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevocationFailed)
			assert.Empty(t, oauth2.IsCode(err), "not an OAuth2 error: a caller answers server_error")
			assert.ErrorContains(t, err, `"fam-revoke"`)
			assert.ErrorContains(t, err, injected)

			// The failed revocation applied nothing...
			requireUsable(t, store, pair)

			// ...and a retry, once the backend recovered, revokes.
			drop()
			require.NoError(t, store.RevokeRefreshFamily(t.Context(), "fam-revoke"))
			requireUnusable(t, store, pair)
		})
	}
}

func TestSQLReuseRevocationFailureIsReported(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	first := testPair("reuse-0", "fam-reuse", time.Hour)
	second := testPair("reuse-1", "fam-reuse", time.Hour)
	replay := testPair("reuse-2", "fam-reuse", time.Hour)

	require.NoError(t, store.SaveTokenPair(t.Context(), first))
	require.NoError(t, store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, second))

	drop := inject(t, db, "BEFORE UPDATE OF revoked_at ON oauth2_token_families")

	err := store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, replay)
	require.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevocationFailed)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
	assert.ErrorContains(t, err, `"fam-reuse"`)
	assert.ErrorContains(t, err, injected)

	// The store says the family is NOT revoked, and it is not.
	requireUsable(t, store, second)
	requirePersisted(t, db, replay, 0)

	drop()
	require.NoError(t, store.RevokeRefreshFamily(t.Context(), "fam-reuse"))
	requireUnusable(t, store, second)
}

func TestSQLRotationIsAtomic(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, trigger string }{
		{"access token insert", "BEFORE INSERT ON oauth2_access_tokens"},
		{"refresh token insert", "BEFORE INSERT ON oauth2_refresh_tokens"},
		{"family retention", "BEFORE UPDATE OF expires_at ON oauth2_token_families"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, db := openSQLite(t)
			first := testPair("atomic-0", "fam-atomic", time.Hour)
			require.NoError(t, store.SaveTokenPair(t.Context(), first))

			_, before := family(t, db, "fam-atomic")
			drop := inject(t, db, tc.trigger)

			// The replacement outlives the family's retention, so the
			// rotation has to extend it too.
			next := testPair("atomic-1", "fam-atomic", 48*time.Hour)
			err := store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, next)
			require.ErrorContains(t, err, injected)
			assert.Empty(t, oauth2.IsCode(err), "a backend failure is no OAuth2 error")

			drop()
			requirePersisted(t, db, next, 0)
			requireUsable(t, store, first)

			_, after := family(t, db, "fam-atomic")
			assert.Equal(t, before, after, "the failed rotation did not extend the family")
		})
	}
}

func TestSQLSaveTokenPairIsAtomic(t *testing.T) {
	t.Parallel()

	for _, trigger := range []string{
		"BEFORE INSERT ON oauth2_access_tokens",
		"BEFORE INSERT ON oauth2_refresh_tokens",
	} {
		t.Run(trigger, func(t *testing.T) {
			t.Parallel()

			store, db := openSQLite(t)
			inject(t, db, trigger)

			pair := testPair("save", "fam-save", time.Hour)
			require.ErrorContains(t, store.SaveTokenPair(t.Context(), pair), injected)

			requirePersisted(t, db, pair, 0)
			assert.Zero(t, count(t, db,
				"SELECT COUNT(*) FROM oauth2_token_families WHERE family_id = ?", "fam-save"),
				"the failed issuance did not create the family")
		})
	}
}

func TestSQLFamilyRetention(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	ctx := t.Context()
	before := time.Now()
	floor := before.Add(oauth2.FamilyRevocationRetention).Unix()

	// Issuance records the family active, retained as long as its tokens.
	first := testPair("ret-0", "fam-ret", time.Hour)
	require.NoError(t, store.SaveTokenPair(ctx, first))

	revokedAt, expiresAt := family(t, db, "fam-ret")
	assert.Zero(t, revokedAt)
	assert.Equal(t, first.Refresh.ExpiresAt.Unix(), expiresAt)

	// A rotation extends the retention to its tokens.
	next := testPair("ret-1", "fam-ret", 48*time.Hour)
	require.NoError(t, store.RotateRefreshToken(ctx, first.Refresh.TokenHash, next))

	_, expiresAt = family(t, db, "fam-ret")
	assert.Equal(t, next.Refresh.ExpiresAt.Unix(), expiresAt)

	// The revocation keeps the longer of the tokens and the retention floor.
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-ret"))

	revokedAt, expiresAt = family(t, db, "fam-ret")
	assert.GreaterOrEqual(t, revokedAt, before.Unix())
	assert.Equal(t, next.Refresh.ExpiresAt.Unix(), expiresAt)

	short := testPair("ret-short", "fam-short", time.Minute)
	require.NoError(t, store.SaveTokenPair(ctx, short))
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-short"))

	_, expiresAt = family(t, db, "fam-short")
	assert.GreaterOrEqual(t, expiresAt, floor)

	// A revocation before issuance is retained for the floor too.
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-unknown"))

	revokedAt, expiresAt = family(t, db, "fam-unknown")
	assert.GreaterOrEqual(t, revokedAt, before.Unix())
	assert.GreaterOrEqual(t, expiresAt, floor)

	// Revoking again keeps the first revocation time and never shortens
	// the retention.
	far := time.Now().Add(100 * time.Hour).Unix()
	_, err := db.ExecContext(ctx,
		"UPDATE oauth2_token_families SET revoked_at = 1, expires_at = ? WHERE family_id = ?", far, "fam-short")
	require.NoError(t, err)
	require.NoError(t, store.RevokeRefreshFamily(ctx, "fam-short"))

	revokedAt, expiresAt = family(t, db, "fam-short")
	assert.Equal(t, int64(1), revokedAt)
	assert.Equal(t, far, expiresAt)
}

// TestSQLMissingFamilyRecordFailsClosed covers a family record that is gone
// — deleted by a premature cleanup, or never written by a build predating
// the family table: its tokens are unusable, and a rotation neither
// succeeds nor records the family.
func TestSQLMissingFamilyRecordFailsClosed(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	ctx := t.Context()
	pair := testPair("lost", "fam-lost", time.Hour)
	require.NoError(t, store.SaveTokenPair(ctx, pair))

	_, err := db.ExecContext(ctx, "DELETE FROM oauth2_token_families WHERE family_id = ?", "fam-lost")
	require.NoError(t, err)

	requireUnusable(t, store, pair)

	next := testPair("lost-next", "fam-lost", time.Hour)
	require.ErrorIs(t, store.RotateRefreshToken(ctx, pair.Refresh.TokenHash, next), oauth2.ErrTokenFamilyRevoked)
	requirePersisted(t, db, next, 0)
	assert.Zero(t, count(t, db,
		"SELECT COUNT(*) FROM oauth2_token_families WHERE family_id = ?", "fam-lost"),
		"a rotation never records a family")

	rt, err := store.LookupRefreshToken(ctx, pair.Refresh.TokenHash)
	require.NoError(t, err)
	assert.True(t, rt.Consumed, "the presented token was not consumed, it reads consumed for its lost family")
}

// TestSQLRefreshTokenWithoutFamilyIsConsumed covers a refresh token stored
// without a family — only a build predating #82 could write one: it can no
// longer be exchanged, while a token outside any family by design (a
// client_credentials access token) stays usable.
func TestSQLRefreshTokenWithoutFamilyIsConsumed(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	ctx := t.Context()
	exp := time.Now().Add(time.Hour).Unix()

	_, err := db.ExecContext(ctx, `INSERT INTO oauth2_refresh_tokens
		(token_hash, client_id, subject, scope, family_id, consumed, issued_at, expires_at)
		VALUES ('rt-legacy', 'c', 's', 'r', '', 0, 0, ?)`, exp)
	require.NoError(t, err)

	rt, err := store.LookupRefreshToken(ctx, "rt-legacy")
	require.NoError(t, err)
	assert.True(t, rt.Consumed)

	cc := &oauth2.TokenPair{Access: oauth2.AccessToken{
		TokenHash: "at-cc", ClientID: "c", Subject: "c", ExpiresAt: time.Now().Add(time.Hour),
	}}
	require.NoError(t, store.SaveTokenPair(ctx, cc))

	got, err := store.LookupAccessToken(ctx, "at-cc")
	require.NoError(t, err)
	assert.Equal(t, "c", got.ClientID)
}

// TestSQLStoreHonorsContext checks that a canceled context reaches the
// driver: the store does not swallow it into a success.
func TestSQLStoreHonorsContext(t *testing.T) {
	t.Parallel()

	store, _ := openSQLite(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	require.ErrorIs(t, store.RevokeRefreshFamily(ctx, "fam-ctx"), context.Canceled)
	require.ErrorIs(t, store.SaveTokenPair(ctx, testPair("ctx", "fam-ctx", time.Hour)), context.Canceled)
}

// TestSQLRotationReportsTokenReadFailure fails the locking read of the old
// token: a backend failure, reported as such and not as an OAuth2 refusal.
func TestSQLRotationReportsTokenReadFailure(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	first := testPair("read-0", "fam-read", time.Hour)
	require.NoError(t, store.SaveTokenPair(t.Context(), first))

	_, err := db.ExecContext(t.Context(), "DROP TABLE oauth2_refresh_tokens")
	require.NoError(t, err)

	err = store.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, testPair("read-1", "fam-read", time.Hour))
	require.ErrorContains(t, err, "lock refresh token")
	assert.Empty(t, oauth2.IsCode(err))
}
