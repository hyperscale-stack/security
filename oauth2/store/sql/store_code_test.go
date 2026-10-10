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
	_ "modernc.org/sqlite"
)

// testCode returns an authorization code stored under hash that expires
// at expiresAt.
func testCode(hash string, expiresAt time.Time) *oauth2.AuthorizationCode {
	return &oauth2.AuthorizationCode{
		Code: "raw-" + hash, CodeHash: hash, ClientID: "c", Subject: "s",
		RedirectURI: "https://app.example/cb", Scope: "r",
		CodeChallenge: "challenge", CodeChallengeMethod: "S256", Nonce: "n",
		IssuedAt: expiresAt.Add(-10 * time.Minute), ExpiresAt: expiresAt,
	}
}

// requireCodeReplay asserts that err reports a replay of the code stored
// under hash, carrying its retained record.
func requireCodeReplay(t *testing.T, err error, hash string) {
	t.Helper()

	var replay *oauth2.CodeReplayError

	require.ErrorAs(t, err, &replay)
	require.NotNil(t, replay.Record)
	assert.Equal(t, hash, replay.Record.CodeHash)
	assert.Equal(t, "c", replay.Record.ClientID)
}

// TestSQLConsumedCodeRowIsKept: consuming a code flags its row instead of
// deleting it, so a replay can be recognized; the record stays intact.
func TestSQLConsumedCodeRowIsKept(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	code := testCode("kept", time.Now().Add(10*time.Minute))
	require.NoError(t, store.SaveAuthorizationCode(t.Context(), code))

	_, err := store.ConsumeAuthorizationCode(t.Context(), "kept")
	require.NoError(t, err)

	require.Equal(t, 1, count(t, db, "SELECT COUNT(*) FROM oauth2_auth_codes WHERE code_hash = ?", "kept"),
		"the consumed code is retained")

	var (
		consumed  int
		clientID  string
		challenge string
		expiresAt int64
	)

	require.NoError(t, db.QueryRowContext(t.Context(),
		"SELECT consumed, client_id, code_challenge, expires_at FROM oauth2_auth_codes WHERE code_hash = ?", "kept",
	).Scan(&consumed, &clientID, &challenge, &expiresAt))
	assert.Equal(t, 1, consumed)
	assert.Equal(t, "c", clientID)
	assert.Equal(t, "challenge", challenge)
	assert.Equal(t, code.ExpiresAt.Unix(), expiresAt)
}

// TestSQLCodeCleanupRule runs the cleanup the package documentation
// describes: it drops the codes past expires_at, whose replays then read as
// unknown codes, and keeps the others recognizable.
func TestSQLCodeCleanupRule(t *testing.T) {
	t.Parallel()

	store, db := openSQLite(t)
	now := time.Now()

	require.NoError(t, store.SaveAuthorizationCode(t.Context(), testCode("short", now.Add(10*time.Minute))))
	require.NoError(t, store.SaveAuthorizationCode(t.Context(), testCode("long", now.Add(2*time.Hour))))

	for _, hash := range []string{"short", "long"} {
		_, err := store.ConsumeAuthorizationCode(t.Context(), hash)
		require.NoError(t, err)
	}

	// The cleanup, run an hour later.
	_, err := db.ExecContext(t.Context(), "DELETE FROM oauth2_auth_codes WHERE expires_at < ?", now.Add(time.Hour).Unix())
	require.NoError(t, err)

	got, err := store.ConsumeAuthorizationCode(t.Context(), "short")
	assert.Nil(t, got)
	require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)

	var replay *oauth2.CodeReplayError

	assert.NotErrorAs(t, err, &replay, "a deleted code reads as unknown")

	got, err = store.ConsumeAuthorizationCode(t.Context(), "long")
	assert.Nil(t, got)
	requireCodeReplay(t, err, "long")
}

// TestSQLConsumeReportsSelectError covers a consume whose read fails after
// its write: the error is reported, no code is returned, and the
// transaction leaves the code unconsumed.
func TestSQLConsumeReportsSelectError(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()

	// A table with only the columns the write needs: the read that follows
	// it fails.
	_, err = db.ExecContext(ctx, "CREATE TABLE oauth2_auth_codes (code_hash VARCHAR(128) PRIMARY KEY, consumed SMALLINT NOT NULL DEFAULT 0)")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO oauth2_auth_codes (code_hash) VALUES ('h')")
	require.NoError(t, err)

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	got, err := store.ConsumeAuthorizationCode(ctx, "h")
	assert.Nil(t, got)
	require.ErrorContains(t, err, "sqlstore: select authorization code")

	var consumed int

	require.NoError(t, db.QueryRowContext(ctx, "SELECT consumed FROM oauth2_auth_codes WHERE code_hash = 'h'").Scan(&consumed))
	assert.Equal(t, 0, consumed, "the failed consume rolled back")
}
