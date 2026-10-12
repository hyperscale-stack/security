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

// pre83Schema is the DDL Schema returned before codes and tokens recorded
// their issuer and extension data (#83): the tables an upgraded deployment
// still has when it applies the statements of MIGRATION.md.
var pre83Schema = []string{
	`CREATE TABLE oauth2_auth_codes (
		code_hash             VARCHAR(128) PRIMARY KEY,
		client_id             VARCHAR(255) NOT NULL,
		subject               VARCHAR(255) NOT NULL,
		redirect_uri          TEXT         NOT NULL,
		scope                 TEXT         NOT NULL,
		code_challenge        TEXT         NOT NULL,
		code_challenge_method VARCHAR(16)  NOT NULL,
		nonce                 TEXT         NOT NULL,
		consumed              SMALLINT     NOT NULL DEFAULT 0,
		issued_at             BIGINT       NOT NULL,
		expires_at            BIGINT       NOT NULL
	)`,
	`CREATE TABLE oauth2_access_tokens (
		token_hash VARCHAR(128) PRIMARY KEY,
		client_id  VARCHAR(255) NOT NULL,
		subject    VARCHAR(255) NOT NULL,
		scope      TEXT         NOT NULL,
		family_id  VARCHAR(64)  NOT NULL,
		audience   VARCHAR(255) NOT NULL,
		issued_at  BIGINT       NOT NULL,
		expires_at BIGINT       NOT NULL
	)`,
	`CREATE TABLE oauth2_refresh_tokens (
		token_hash VARCHAR(128) PRIMARY KEY,
		client_id  VARCHAR(255) NOT NULL,
		subject    VARCHAR(255) NOT NULL,
		scope      TEXT         NOT NULL,
		family_id  VARCHAR(64)  NOT NULL,
		consumed   SMALLINT     NOT NULL DEFAULT 0,
		issued_at  BIGINT       NOT NULL,
		expires_at BIGINT       NOT NULL
	)`,
	`CREATE TABLE oauth2_token_families (
		family_id  VARCHAR(64)  PRIMARY KEY,
		revoked_at BIGINT       NOT NULL DEFAULT 0,
		expires_at BIGINT       NOT NULL
	)`,
}

// upgrade83 are the statements MIGRATION.md tells an existing deployment to
// apply for #83 — keep them identical.
var upgrade83 = []string{
	`ALTER TABLE oauth2_auth_codes ADD COLUMN issuer TEXT`,
	`ALTER TABLE oauth2_auth_codes ADD COLUMN extension_data TEXT`,
	`ALTER TABLE oauth2_access_tokens ADD COLUMN issuer TEXT`,
	`ALTER TABLE oauth2_access_tokens ADD COLUMN extension_data TEXT`,
	`ALTER TABLE oauth2_refresh_tokens ADD COLUMN issuer TEXT`,
	`ALTER TABLE oauth2_refresh_tokens ADD COLUMN extension_data TEXT`,
}

// backfill83 is the optional single-issuer backfill MIGRATION.md documents.
var backfill83 = []string{
	`UPDATE oauth2_auth_codes SET issuer = 'https://auth.example' WHERE issuer IS NULL`,
	`UPDATE oauth2_access_tokens SET issuer = 'https://auth.example' WHERE issuer IS NULL`,
	`UPDATE oauth2_refresh_tokens SET issuer = 'https://auth.example' WHERE issuer IS NULL`,
}

// openRawSQLite opens a private in-memory SQLite database without any table.
func openRawSQLite(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// execAll runs every statement on db.
func execAll(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()

	for _, stmt := range stmts {
		_, err := db.ExecContext(t.Context(), stmt)
		require.NoError(t, err, stmt)
	}
}

// seedLegacyRows writes, with the columns of the pre-#83 schema only, an
// unconsumed code "legacy-code", and an active family "fam-legacy" holding
// access token "at-legacy" and refresh token "rt-legacy".
func seedLegacyRows(t *testing.T, db *sql.DB) {
	t.Helper()

	until := time.Now().Add(time.Hour).Unix()

	for _, stmt := range []string{
		`INSERT INTO oauth2_auth_codes (code_hash, client_id, subject, redirect_uri, scope,
			code_challenge, code_challenge_method, nonce, issued_at, expires_at)
			VALUES ('legacy-code', 'c', 's', 'https://app.example/cb', 'r', '', '', '', 0, ?)`,
		`INSERT INTO oauth2_token_families (family_id, revoked_at, expires_at) VALUES ('fam-legacy', 0, ?)`,
		`INSERT INTO oauth2_access_tokens (token_hash, client_id, subject, scope, family_id, audience, issued_at, expires_at)
			VALUES ('at-legacy', 'c', 's', 'r', 'fam-legacy', 'api', 0, ?)`,
		`INSERT INTO oauth2_refresh_tokens (token_hash, client_id, subject, scope, family_id, consumed, issued_at, expires_at)
			VALUES ('rt-legacy', 'c', 's', 'r', 'fam-legacy', 0, 0, ?)`,
	} {
		_, err := db.ExecContext(t.Context(), stmt, until)
		require.NoError(t, err, stmt)
	}
}

// requireLegacyContext asserts the legacy rows read an empty grant context
// — or issuer once backfilled — and that the rotation of the legacy refresh
// token keeps that context.
func requireLegacyContext(t *testing.T, store *sqlstore.Store, issuer string) {
	t.Helper()

	ctx := t.Context()

	code, err := store.ConsumeAuthorizationCode(ctx, "legacy-code")
	require.NoError(t, err)
	assert.Equal(t, issuer, code.Issuer)
	assert.Empty(t, code.ExtensionData)

	_, err = store.ConsumeAuthorizationCode(ctx, "legacy-code")

	var replay *oauth2.CodeReplayError

	require.ErrorAs(t, err, &replay)
	assert.Equal(t, issuer, replay.Record.Issuer)
	assert.Empty(t, replay.Record.ExtensionData)

	at, err := store.LookupAccessToken(ctx, "at-legacy")
	require.NoError(t, err)
	assert.Equal(t, issuer, at.Issuer)
	assert.Empty(t, at.ExtensionData)

	rt, err := store.LookupRefreshToken(ctx, "rt-legacy")
	require.NoError(t, err)
	assert.Equal(t, issuer, rt.Issuer)
	assert.Empty(t, rt.ExtensionData)

	// The rotation compares the stored context with the replacement's: a
	// NULL column reads as "".
	rewritten := legacyNext("rt-rewritten", issuer, "rewritten")
	require.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(store.RotateRefreshToken(ctx, "rt-legacy", rewritten)))

	require.NoError(t, store.RotateRefreshToken(ctx, "rt-legacy", legacyNext("rt-next", issuer, "")))

	next, err := store.LookupRefreshToken(ctx, "rt-next")
	require.NoError(t, err)
	assert.Equal(t, issuer, next.Issuer)
}

// legacyNext is the pair a rotation of the legacy refresh token issues.
func legacyNext(hash, issuer, data string) *oauth2.TokenPair {
	now := time.Now()

	return &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			TokenHash: "at-" + hash, ClientID: "c", Subject: "s", Scope: "r", FamilyID: "fam-legacy",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: issuer, ExtensionData: data,
		},
		Refresh: &oauth2.RefreshToken{
			TokenHash: hash, ClientID: "c", Subject: "s", Scope: "r", FamilyID: "fam-legacy",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: issuer, ExtensionData: data,
		},
	}
}

// TestSQLDocumentedUpgradeKeepsLegacyRows applies the MIGRATION.md
// statements to a pre-#83 database holding rows: they keep working, read an
// empty grant context, and new rows record theirs.
func TestSQLDocumentedUpgradeKeepsLegacyRows(t *testing.T) {
	t.Parallel()

	db := openRawSQLite(t)
	execAll(t, db, pre83Schema...)
	seedLegacyRows(t, db)
	execAll(t, db, upgrade83...)

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	requireLegacyContext(t, store, "")

	now := time.Now()
	fresh := &oauth2.AuthorizationCode{
		CodeHash: "fresh", ClientID: "c", Subject: "s", RedirectURI: "https://app.example/cb", Scope: "r",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), Issuer: "https://auth.example", ExtensionData: "ctx",
	}
	require.NoError(t, store.SaveAuthorizationCode(t.Context(), fresh))

	got, err := store.ConsumeAuthorizationCode(t.Context(), "fresh")
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example", got.Issuer)
	assert.Equal(t, "ctx", got.ExtensionData)
}

// TestSQLDocumentedBackfillBindsLegacyRows runs the optional single-issuer
// backfill after the upgrade: the legacy rows then carry the issuer.
func TestSQLDocumentedBackfillBindsLegacyRows(t *testing.T) {
	t.Parallel()

	db := openRawSQLite(t)
	execAll(t, db, pre83Schema...)
	seedLegacyRows(t, db)
	execAll(t, db, upgrade83...)
	execAll(t, db, backfill83...)

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)

	requireLegacyContext(t, store, "https://auth.example")
}

// TestSQLContextColumnsAreNullableText pins the new columns of Schema: TEXT
// and nullable, the only form every engine accepts in an ALTER TABLE … ADD
// COLUMN on a populated table (MySQL refuses a literal default on TEXT,
// SQLite and PostgreSQL a NOT NULL without default) — so a fresh install and
// an upgraded one have the same columns.
func TestSQLContextColumnsAreNullableText(t *testing.T) {
	t.Parallel()

	_, db := openSQLite(t)

	for _, table := range []string{"oauth2_auth_codes", "oauth2_access_tokens", "oauth2_refresh_tokens"} {
		for _, column := range []string{"issuer", "extension_data"} {
			var (
				typ     string
				notNull int
			)

			require.NoError(t, db.QueryRowContext(context.Background(),
				`SELECT type, "notnull" FROM pragma_table_info(?) WHERE name = ?`, table, column,
			).Scan(&typ, &notNull), table+"."+column)
			assert.Equal(t, "TEXT", typ, table+"."+column)
			assert.Equal(t, 0, notNull, table+"."+column+" is nullable")
		}
	}
}
