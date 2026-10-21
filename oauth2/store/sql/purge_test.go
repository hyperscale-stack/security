// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	sqlstore "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// purgeSeed is what seedPurge stored: the records PurgeExpired must keep.
type purgeSeed struct {
	live, revoked *oauth2.TokenPair
}

// pairExpiring returns a pair of family whose tokens expire at expiresAt.
func pairExpiring(name, family string, expiresAt time.Time) *oauth2.TokenPair {
	pair := testPair(name, family, time.Hour)
	pair.Access.ExpiresAt, pair.Refresh.ExpiresAt = expiresAt, expiresAt

	return pair
}

// seedPurge stores, as of now, eight rows expired before it — two codes,
// three access tokens, two refresh tokens, one family — and rows that must
// stay: codes and a family expiring at now exactly, a live code and pair,
// and the record of a family revoked, whose expired tokens go.
func seedPurge(t *testing.T, s *sqlstore.Store, db *sql.DB, now time.Time) purgeSeed {
	t.Helper()

	ctx := t.Context()
	past := now.Add(-time.Hour)

	for hash, expires := range map[string]time.Time{
		"code-expired": past, "code-consumed": past, "code-boundary": now, "code-live": now.Add(time.Hour),
	} {
		require.NoError(t, s.SaveAuthorizationCode(ctx, &oauth2.AuthorizationCode{
			CodeHash: hash, ClientID: "c", Subject: "s", RedirectURI: "https://app.example/cb", Scope: "r",
			IssuedAt: past.Add(-time.Minute), ExpiresAt: expires,
		}))
	}

	_, err := s.ConsumeAuthorizationCode(ctx, "code-consumed")
	require.NoError(t, err)

	require.NoError(t, s.SaveTokenPair(ctx, pairExpiring("purge-expired", "fam-purge-expired", past)))

	cc := pairExpiring("purge-cc", "", past)
	cc.Refresh = nil
	require.NoError(t, s.SaveTokenPair(ctx, cc))

	seed := purgeSeed{
		live:    pairExpiring("purge-live", "fam-purge-live", now.Add(time.Hour)),
		revoked: pairExpiring("purge-revoked", "fam-purge-revoked", past),
	}
	require.NoError(t, s.SaveTokenPair(ctx, seed.live))
	require.NoError(t, s.SaveTokenPair(ctx, seed.revoked))
	require.NoError(t, s.RevokeRefreshFamily(ctx, "fam-purge-revoked"))

	require.NoError(t, s.SaveTokenPair(ctx, pairExpiring("purge-boundary", "fam-purge-boundary", now)))

	return seed
}

// purgedSeed is the number of rows seedPurge stores expired.
const purgedSeed = 8

// rowCount returns the number of rows of table.
func rowCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&n))

	return n
}

// TestSQLPurgeExpired deletes every row expired before now, table by
// table, and keeps the rows expiring at now, the live ones and the record
// of a revoked family within its retention: once purged, the live pair is
// still usable and the revoked family still refuses issuance. A second
// purge deletes nothing.
func TestSQLPurgeExpired(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	now := time.Unix(time.Now().Unix(), 0)
	seed := seedPurge(t, store, db, now)

	n, err := store.PurgeExpired(t.Context(), now)
	require.NoError(t, err)
	assert.Equal(t, int64(purgedSeed), n)

	for table, rows := range map[string]int{
		"oauth2_auth_codes": 2, "oauth2_access_tokens": 2, "oauth2_refresh_tokens": 2, "oauth2_token_families": 3,
	} {
		assert.Equal(t, rows, rowCount(t, db, table), table)
	}

	_, err = store.LookupAccessToken(t.Context(), seed.live.Access.TokenHash)
	require.NoError(t, err, "the live pair stays")

	again := pairExpiring("purge-revoked-again", "fam-purge-revoked", now.Add(time.Hour))
	require.ErrorIs(t, store.SaveTokenPair(t.Context(), again), oauth2.ErrTokenFamilyRevoked,
		"the revoked family's record stays")

	n, err = store.PurgeExpired(t.Context(), now)
	require.NoError(t, err)
	assert.Zero(t, n)
}

// TestSQLPurgeExpiredFailures: a statement or a transaction that fails
// fails the purge, with the rows deleted until then.
func TestSQLPurgeExpiredFailures(t *testing.T) {
	t.Parallel()

	n, err := unmigratedStore(t).PurgeExpired(t.Context(), time.Now())
	require.ErrorContains(t, err, "sqlstore: purge expired rows: ")
	assert.Zero(t, n)

	store, _ := openSQLite(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = store.PurgeExpired(ctx, time.Now())
	require.ErrorIs(t, err, context.Canceled)
}
