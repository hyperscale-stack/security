// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstores_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	oauth2sql "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/hyperscale-stack/security/oauth2/storetest"
	"github.com/stretchr/testify/require"
)

// mysql84FoundRows is MySQL 8.4 with the CLIENT_FOUND_ROWS flag, under
// which an UPDATE reports the rows it matched rather than those it changed.
var mysql84FoundRows = backend{
	name: "mysql84-client-found-rows", engine: engineMySQL, env: envMySQL84DSN, clientFoundRows: true,
}

// conformancePoolSize is the number of connections a conformance case
// races on: every one is open before the case starts.
const conformancePoolSize = 8

// conformancePools returns the pool opener of a RunConformance run: each
// call returns a pool on dsn whose conformancePoolSize connections are open
// and idle before the case starts, so the racers of the concurrency cases
// overlap for real instead of queuing on connection setup (with one warm
// connection, a check-then-act consumption passes them). RunConformance
// builds every case's store on the parent test, which keeps the pools
// until it ends: each call closes the pool of the previous case, so a run
// holds conformancePoolSize connections, not one set per case. That relies
// on RunConformance running its cases one after the other, as it does.
func conformancePools(t *testing.T) func(driver, dsn string) *sql.DB {
	t.Helper()

	var previous *sql.DB

	return func(driver, dsn string) *sql.DB {
		if previous != nil {
			_ = previous.Close()
		}

		previous = warmPool(t, driver, dsn, conformancePoolSize)

		return previous
	}
}

// warmPool returns a pool of size connections on dsn, every one of them
// opened — each held until all are, so that they are distinct — and
// returned to the pool idle.
func warmPool(t *testing.T, driver, dsn string, size int) *sql.DB {
	t.Helper()

	db := open(t, driver, dsn, size)
	conns := make([]*sql.Conn, 0, size)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	for i := range size {
		c, err := db.Conn(ctx)
		require.NoError(t, err, "opening connection %d of the pool", i)

		conns = append(conns, c)
	}

	for _, c := range conns {
		require.NoError(t, c.Close())
	}

	require.Equal(t, size, db.Stats().Idle, "idle connections of the warmed pool")

	return db
}

// TestOAuth2Conformance runs the oauth2 storage conformance suite — code
// consumption and rotation under races, the token-family invariants, keys
// compared byte for byte — on every backend, each case in a new namespace
// that Migrate prepares.
func TestOAuth2Conformance(t *testing.T) {
	for _, b := range []backend{sqliteFile, postgres, mysql80, mysql84, mysql84FoundRows, mariadb} {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			pool := conformancePools(t)

			storetest.RunConformance(t, func() oauth2.Storage {
				driver, dsn := b.namespace(t)

				s, err := oauth2sql.New(pool(driver, dsn), oauth2Dialect(b.engine))
				require.NoError(t, err)
				require.NoError(t, s.Migrate(t.Context()))

				return s
			})
		})
	}
}

// legacyMySQLSchema is the DDL Schema returned for MySQL before its key
// columns became binary strings: the tables a deployment upgrading from it
// still has.
var legacyMySQLSchema = []string{
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
		expires_at            BIGINT       NOT NULL,
		issuer                TEXT,
		extension_data        TEXT,
		redirect_uri_omitted  SMALLINT     NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE oauth2_access_tokens (
		token_hash VARCHAR(128) PRIMARY KEY,
		client_id  VARCHAR(255) NOT NULL,
		subject    VARCHAR(255) NOT NULL,
		scope      TEXT         NOT NULL,
		family_id  VARCHAR(64)  NOT NULL,
		audience   VARCHAR(255) NOT NULL,
		issued_at  BIGINT       NOT NULL,
		expires_at BIGINT       NOT NULL,
		issuer         TEXT,
		extension_data TEXT
	)`,
	`CREATE TABLE oauth2_refresh_tokens (
		token_hash VARCHAR(128) PRIMARY KEY,
		client_id  VARCHAR(255) NOT NULL,
		subject    VARCHAR(255) NOT NULL,
		scope      TEXT         NOT NULL,
		family_id  VARCHAR(64)  NOT NULL,
		consumed   SMALLINT     NOT NULL DEFAULT 0,
		issued_at  BIGINT       NOT NULL,
		expires_at BIGINT       NOT NULL,
		issuer         TEXT,
		extension_data TEXT,
		family_issued_at BIGINT NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE oauth2_token_families (
		family_id  VARCHAR(64)  PRIMARY KEY,
		revoked_at BIGINT       NOT NULL DEFAULT 0,
		expires_at BIGINT       NOT NULL
	)`,
}

// upgradeSection is the heading of the MIGRATION.md section whose SQL
// blocks — the preflight queries, the upgrade, the optional conversion of
// the codes' table — TestOAuth2MySQLUpgrade runs: the documented
// statements are the tested ones.
const upgradeSection = "### `oauth2/store/sql`: MySQL compares keys byte for byte"

var sqlBlock = regexp.MustCompile("(?s)```sql\n(.*?)```")

// upgradeBlocks returns the SQL blocks of the upgrade section of
// MIGRATION.md, each as its statements: comment lines dropped, split at
// the semicolons ending a line.
func upgradeBlocks(t *testing.T) [][]string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "MIGRATION.md"))
	require.NoError(t, err)

	doc := string(raw)
	start := strings.Index(doc, "\n"+upgradeSection+"\n")
	require.GreaterOrEqual(t, start, 0, "MIGRATION.md has no section %q", upgradeSection)

	section := doc[start+1:]
	if end := strings.Index(section[len(upgradeSection):], "\n### "); end >= 0 {
		section = section[:len(upgradeSection)+end]
	}

	var blocks [][]string

	for _, m := range sqlBlock.FindAllStringSubmatch(section, -1) {
		var (
			stmts []string
			stmt  strings.Builder
		)

		for _, line := range strings.Split(m[1], "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "--") {
				continue
			}

			stmt.WriteString(line + "\n")

			if strings.HasSuffix(trimmed, ";") {
				stmts = append(stmts, strings.TrimSuffix(strings.TrimSpace(stmt.String()), ";"))
				stmt.Reset()
			}
		}

		require.Empty(t, strings.TrimSpace(stmt.String()), "a statement without its semicolon")

		blocks = append(blocks, stmts)
	}

	return blocks
}

// execAll runs stmts on one connection of db, so that a SET SESSION
// applies to the statements after it.
func execAll(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()

	conn, err := db.Conn(t.Context())
	require.NoError(t, err)

	defer func() { _ = conn.Close() }()

	for _, stmt := range stmts {
		_, err := conn.ExecContext(t.Context(), stmt)
		require.NoError(t, err, stmt)
	}
}

// queryRow returns the integers of the single row query returns.
func queryRow(t *testing.T, db *sql.DB, query string) []int64 {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), query)
	require.NoError(t, err, query)

	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	require.NoError(t, err)
	require.True(t, rows.Next(), "a row")

	values := make([]int64, len(columns))
	targets := make([]any, len(columns))

	for i := range values {
		targets[i] = &values[i]
	}

	require.NoError(t, rows.Scan(targets...))
	require.False(t, rows.Next(), "a single row")

	return values
}

// requireBinaryKeys asserts that the six key columns of an upgraded
// database are binary strings of their length, NOT NULL, and that the
// primary keys survived the conversion.
func requireBinaryKeys(t *testing.T, db *sql.DB) {
	t.Helper()

	for _, c := range []struct {
		table, column string
		length        int64
		primary       bool
	}{
		{"oauth2_auth_codes", "code_hash", 128, true},
		{"oauth2_access_tokens", "token_hash", 128, true},
		{"oauth2_access_tokens", "family_id", 64, false},
		{"oauth2_refresh_tokens", "token_hash", 128, true},
		{"oauth2_refresh_tokens", "family_id", 64, false},
		{"oauth2_token_families", "family_id", 64, true},
	} {
		var (
			dataType, nullable, key string
			length                  int64
		)

		require.NoError(t, db.QueryRowContext(t.Context(), `SELECT DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE, COLUMN_KEY
			FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
			c.table, c.column).Scan(&dataType, &length, &nullable, &key))

		name := c.table + "." + c.column
		require.Equal(t, "varbinary", dataType, name)
		require.Equal(t, c.length, length, name)
		require.Equal(t, "NO", nullable, name)
		require.Equal(t, c.primary, key == "PRI", name+" primary key")
	}
}

// TestOAuth2MySQLUpgrade runs the upgrade statements of MIGRATION.md on
// tables created by the former MySQL DDL. Seeded with families the former
// collation merged with look-alikes — revoked, and active; whole pairs,
// a refresh token whose access token is gone, an access token alone — it
// checks what the upgrade keeps: the preflight counts the merged tokens,
// the key columns become binary, a revoked family and its look-alikes stay
// revoked even through a new issuance into each look-alike (the orphaned
// families are recorded revoked, for FamilyRevocationRetention at least),
// the look-alike of an active family reads revoked, other families and
// codes are untouched. In strict mode, an over-long key stops the upgrade
// instead of being truncated. The conformance suite then passes on
// upgraded tables.
func TestOAuth2MySQLUpgrade(t *testing.T) {
	blocks := upgradeBlocks(t)
	require.Len(t, blocks, 3, "the preflight, the upgrade and the conversion of the codes' table")

	preflight, upgrade := blocks[0], append(blocks[1], blocks[2]...)
	require.Len(t, preflight, 2)

	for _, b := range []backend{mysql80, mysql84, mariadb} {
		t.Run(b.name, func(t *testing.T) {
			b.server(t)

			t.Run("revocations survive", func(t *testing.T) {
				upgradeSeededDatabase(t, b, preflight, upgrade)
			})

			t.Run("over-long keys stop it", func(t *testing.T) {
				upgradeRefusesOverLongKeys(t, b, preflight, upgrade)
			})

			t.Run("conformance", func(t *testing.T) {
				pool := conformancePools(t)

				storetest.RunConformance(t, func() oauth2.Storage {
					driver, dsn := b.namespace(t)
					db := pool(driver, dsn)
					execAll(t, db, legacyMySQLSchema...)
					execAll(t, db, upgrade...)

					s, err := oauth2sql.New(db, oauth2sql.MySQL)
					require.NoError(t, err)

					return s
				})
			})
		})
	}
}

// upgradeSeededDatabase is the seeded half of TestOAuth2MySQLUpgrade.
func upgradeSeededDatabase(t *testing.T, b backend, preflight, upgrade []string) {
	t.Helper()

	start := time.Now().Unix()

	driver, dsn := b.namespace(t)
	db := open(t, driver, dsn, 4)
	execAll(t, db, legacyMySQLSchema...)

	s, err := oauth2sql.New(db, oauth2sql.MySQL)
	require.NoError(t, err)

	// Under the former collation a pair saved into a look-alike of a
	// family joins that family's record: revoking one revokes all of them.
	var (
		alice            = tokenPair("alice", "User-Alice")
		aliceAlike       = tokenPair("alice-alike", "user-alice")
		aliceRefreshOnly = tokenPair("alice-refresh-only", "USER-ALICE")
		aliceAccessOnly  = tokenPair("alice-access-only", "uSeR-aLiCe")
		bob              = tokenPair("bob", "Team-Bob")
		bobAlike         = tokenPair("bob-alike", "team-bob")
		plain            = tokenPair("plain", "plain-family")
	)

	// An access token alone: a non-rotating refresh under Profile20.
	aliceAccessOnly.Refresh = nil

	for _, p := range []*oauth2.TokenPair{alice, aliceAlike, aliceRefreshOnly, aliceAccessOnly, bob, bobAlike, plain} {
		require.NoError(t, s.SaveTokenPair(t.Context(), p))
	}

	// A refresh token whose access token is gone: revoked, or cleaned up.
	require.NoError(t, s.RevokeAccessToken(t.Context(), aliceRefreshOnly.Access.TokenHash))
	require.NoError(t, s.RevokeRefreshFamily(t.Context(), "User-Alice"))

	lookAlikes := map[string]func(){
		"user-alice": func() { requireUnusable(t, s, aliceAlike) },
		"USER-ALICE": func() { requireRefreshConsumed(t, s, aliceRefreshOnly) },
		"uSeR-aLiCe": func() { requireAccessRevoked(t, s, aliceAccessOnly) },
	}
	for _, unusable := range lookAlikes {
		unusable()
	}

	code := &oauth2.AuthorizationCode{CodeHash: sha256Hex("legacy-code"), ClientID: "client-1", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, s.SaveAuthorizationCode(t.Context(), code))

	require.Equal(t, []int64{3, 3}, queryRow(t, db, preflight[0]), "access and refresh tokens merged with a look-alike")

	for i, length := range queryRow(t, db, preflight[1]) {
		require.LessOrEqual(t, length, []int64{64, 64, 64, 128, 128, 128}[i], "longest key %d", i)
	}

	execAll(t, db, upgrade...)
	requireBinaryKeys(t, db)

	requireUnusable(t, s, alice)

	for family, unusable := range lookAlikes {
		unusable()
		require.ErrorIs(t, s.SaveTokenPair(t.Context(), tokenPair("new-"+family, family)), oauth2.ErrTokenFamilyRevoked,
			"an issuance into %q, a look-alike of a revoked family", family)
		unusable()
		requireRevokedRecord(t, db, family, start)
	}

	requireUsable(t, s, bob)
	requireUnusable(t, s, bobAlike)
	requireRevokedRecord(t, db, "team-bob", start)
	requireUsable(t, s, plain)

	_, err = s.ConsumeAuthorizationCode(t.Context(), code.CodeHash)
	require.NoError(t, err)
}

// requireRevokedRecord asserts that the upgrade recorded family revoked —
// no earlier than start — and kept for oauth2.FamilyRevocationRetention
// at least: past every one of its tokens, and past start + 24 hours even
// for a family whose tokens expire sooner (an access token alone lives an
// hour here).
func requireRevokedRecord(t *testing.T, db *sql.DB, family string, start int64) {
	t.Helper()

	var revokedAt, expiresAt int64
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT revoked_at, expires_at FROM oauth2_token_families WHERE family_id = ?`, family).Scan(&revokedAt, &expiresAt), family)

	require.GreaterOrEqual(t, revokedAt, start, "%s revoked at the upgrade", family)
	require.GreaterOrEqual(t, expiresAt, start+int64(oauth2.FamilyRevocationRetention/time.Second), "%s retained", family)
}

// upgradeRefusesOverLongKeys seeds, behind the store's back, a token row
// whose family ID fits VARCHAR(64) — 33 characters — but not VARBINARY(64):
// 66 bytes. The preflight reports it, and the upgrade, which sets a strict
// sql_mode for its session, stops at the ALTER of that table instead of
// truncating the key, on a connection whose own sql_mode is not strict.
func upgradeRefusesOverLongKeys(t *testing.T, b backend, preflight, upgrade []string) {
	t.Helper()

	lax := b
	lax.params = map[string]string{"sql_mode": "''"}

	driver, dsn := lax.namespace(t)
	db := open(t, driver, dsn, 1)
	execAll(t, db, legacyMySQLSchema...)

	long := strings.Repeat("\u00e9", 33)
	execAll(t, db, `INSERT INTO oauth2_access_tokens (token_hash, client_id, subject, scope, family_id, audience, issued_at, expires_at)
		VALUES ('at-long', 'client-1', 'alice', 'read', '`+long+`', 'api', 0, 4102444800)`)

	require.Equal(t, int64(66), queryRow(t, db, preflight[1])[1], "the preflight reports the 66-byte family ID")

	// One session: the SET applies to the statements after it.
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)

	var failed error

	for _, stmt := range upgrade {
		if _, failed = conn.ExecContext(t.Context(), stmt); failed != nil {
			require.Contains(t, stmt, "ALTER TABLE oauth2_access_tokens", "the statement that fails")

			break
		}
	}

	require.NoError(t, conn.Close())
	require.Error(t, failed, "the upgrade truncated a 66-byte family ID into VARBINARY(64)")

	var familyID, dataType string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT family_id FROM oauth2_access_tokens WHERE token_hash = 'at-long'`).Scan(&familyID))
	require.Equal(t, long, familyID, "the key is intact")
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT DATA_TYPE FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oauth2_access_tokens' AND COLUMN_NAME = 'family_id'`).Scan(&dataType))
	require.Equal(t, "varchar", dataType, "the table is left as it was")
}

// requireRefreshConsumed asserts that pair's refresh token reads consumed.
func requireRefreshConsumed(t *testing.T, s *oauth2sql.Store, pair *oauth2.TokenPair) {
	t.Helper()

	rt, err := s.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err, pair.Refresh.TokenHash)
	require.True(t, rt.Consumed, pair.Refresh.TokenHash)
}

// requireAccessRevoked asserts that pair's access token reads revoked.
func requireAccessRevoked(t *testing.T, s *oauth2sql.Store, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, pair.Access.TokenHash)
}

// requireUsable asserts that pair's access token is found and its refresh
// token is not consumed.
func requireUsable(t *testing.T, s *oauth2sql.Store, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.NoError(t, err, pair.Access.TokenHash)

	rt, err := s.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err, pair.Refresh.TokenHash)
	require.False(t, rt.Consumed, pair.Refresh.TokenHash)
}

// requireUnusable asserts that pair's access token reads revoked and its
// refresh token consumed.
func requireUnusable(t *testing.T, s *oauth2sql.Store, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, pair.Access.TokenHash)

	rt, err := s.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err, pair.Refresh.TokenHash)
	require.True(t, rt.Consumed, pair.Refresh.TokenHash)
}
