// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// Dialect abstracts the few SQL differences the store cares about: the
// parameter-placeholder style, the insert-if-absent syntax, row locking,
// the transaction isolation level and the serialization of concurrent
// migrations. The store writes every query with "?" placeholders and
// rebinds them through the dialect, so query strings stay readable.
type Dialect interface {
	// Name returns a stable identifier ("postgres", "mysql", "sqlite")
	// used in error messages and OTel attributes.
	Name() string
	// rebind rewrites a "?"-placeholder query into the dialect's native
	// placeholder style. Postgres needs $1,$2,…; MySQL and SQLite keep ?.
	rebind(query string) string
	// insertFamily inserts a token-family record (family_id, revoked_at,
	// expires_at) unless one already exists, keeping the existing one.
	insertFamily() string
	// lockFamily reads a family's revoked_at under a row lock.
	lockFamily() string
	// lockRefresh reads a refresh token's family_id, consumed flag,
	// issuer and extension_data (NULL read as '') under a row lock.
	lockRefresh() string
	// txOptions are the options of every store transaction.
	txOptions() *sql.TxOptions
	// migrationLock is the statement [Store.Migrate] runs first, in the
	// transaction creating the tables, to serialize concurrent migrations;
	// "" when the engine serializes the creation of a table itself and
	// Migrate runs its statements one by one.
	migrationLock() string
	// keyType is the column type [Schema] gives a key of at most length
	// bytes — a code or token hash, a token-family ID: the only columns
	// the statements compare. It must compare them byte for byte.
	keyType(length int) string
	// tableOptions follows the column list of every CREATE TABLE of
	// [Schema]: the storage engine and character set the dialect needs,
	// "" when it needs none.
	tableOptions() string
	// checkDeployment verifies the requirements of the package
	// documentation the database reports (see [Store.CheckDeployment]).
	checkDeployment(ctx context.Context, db *sql.DB) error
	// purgeStatements are the statements [Store.PurgeExpired] runs, one
	// per table — codes, access tokens, refresh tokens, then families —
	// each deleting at most a batch of the rows expired before a second.
	purgeStatements() []string
	// purgeArgs are the arguments of a purge statement: the second rows
	// must have expired before, and the batch size.
	purgeArgs(before int64, limit int) []any
	// purgeTxOptions are the options of a purge batch's transaction.
	purgeTxOptions() *sql.TxOptions
}

// migrationLockKey is the PostgreSQL advisory lock [Store.Migrate] takes:
// the first eight bytes of SHA-256 of
// "github.com/hyperscale-stack/security/oauth2/store/sql.Migrate",
// big-endian, as a bigint. Advisory locks are local to a database, which
// the stores of other modules may share: each store module has a key of
// its own, so that their migrations never wait for one another.
const migrationLockKey = "-2450120788798466590"

// The token-family statements several dialects share, each a full literal.
const (
	insertFamilyOnConflict = `INSERT INTO oauth2_token_families (family_id, revoked_at, expires_at) VALUES (?, ?, ?)
		ON CONFLICT (family_id) DO NOTHING`
	lockFamilyForUpdate  = `SELECT revoked_at FROM oauth2_token_families WHERE family_id = ? FOR UPDATE`
	lockRefreshForUpdate = `SELECT family_id, consumed, COALESCE(issuer, ''), COALESCE(extension_data, '')
		FROM oauth2_refresh_tokens WHERE token_hash = ? FOR UPDATE`
)

// Postgres is the PostgreSQL dialect ($1,$2,… placeholders). Its store
// transactions run at READ COMMITTED whatever the server default: the
// family lock and the consumption of a code rely on re-reading the latest
// committed row, where REPEATABLE READ or SERIALIZABLE would abort the
// transaction with a serialization failure instead. [Store.Migrate] takes
// the transaction-level advisory lock -2450120788798466590
// (pg_advisory_xact_lock) before creating the tables.
var Postgres Dialect = postgres{}

// MySQL is the MySQL / MariaDB dialect (? placeholders). The tables must be
// InnoDB — the store relies on its transactions and row locks — and
// [Schema] creates them so (ENGINE=InnoDB DEFAULT CHARSET=utf8mb4); their
// key columns are VARBINARY. [Store.CheckDeployment] verifies both, and
// a strict sql_mode.
var MySQL Dialect = mysql{}

// SQLite is the SQLite dialect (? placeholders). SQLite has no row locks:
// its single writer serializes the store's write transactions, each of
// which starts with a write.
var SQLite Dialect = sqlite{}

type postgres struct{}

func (postgres) Name() string { return "postgres" }

// rebind replaces each ? with the positional $N form Postgres expects.
func (postgres) rebind(query string) string {
	var b strings.Builder

	b.Grow(len(query) + 8)

	n := 0

	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++

			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))

			continue
		}

		b.WriteByte(query[i])
	}

	return b.String()
}

func (postgres) insertFamily() string { return insertFamilyOnConflict }
func (postgres) lockFamily() string   { return lockFamilyForUpdate }
func (postgres) lockRefresh() string  { return lockRefreshForUpdate }

func (postgres) txOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

// migrationLock takes a transaction-level advisory lock: concurrent
// CREATE TABLE IF NOT EXISTS of one table can both find it missing, and
// the loser then fails on the unique index of the catalog's row types. A
// transaction-level lock is released by the COMMIT or ROLLBACK ending the
// migration, whatever becomes of the connection afterwards.
func (postgres) migrationLock() string {
	return "SELECT pg_advisory_xact_lock(" + migrationLockKey + ")"
}

// keyType is VARCHAR: PostgreSQL compares text byte for byte under a
// deterministic collation, which a database's default collation is. A
// VARCHAR(n) silently drops the spaces past n characters, which no key
// reaches: the store refuses a family ID over 64 bytes, and oauth2.HashToken
// hashes are 64 characters.
func (postgres) keyType(length int) string { return varchar(length) }

func (postgres) tableOptions() string { return "" }

func (postgres) purgeStatements() []string               { return purgeSubqueries }
func (postgres) purgeArgs(before int64, limit int) []any { return subqueryArgs(before, limit) }

// purgeTxOptions pins READ COMMITTED: the outer DELETE then re-checks the
// expiry of a row a concurrent transaction changed, where REPEATABLE READ
// or SERIALIZABLE would abort the batch with a serialization failure.
func (postgres) purgeTxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

// checkDeployment checks nothing: the store pins READ COMMITTED itself,
// and synchronous_commit — off, it can lose an acknowledged revocation in a
// crash — can be set per role, session or transaction, so the value one
// pooled connection reports proves nothing about the others.
func (postgres) checkDeployment(context.Context, *sql.DB) error { return nil }

type mysql struct{}

func (mysql) Name() string           { return "mysql" }
func (mysql) rebind(q string) string { return q }

// insertFamily uses ON DUPLICATE KEY UPDATE rather than INSERT IGNORE,
// which would also silence errors such as a truncated value.
func (mysql) insertFamily() string {
	return `INSERT INTO oauth2_token_families (family_id, revoked_at, expires_at) VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE family_id = family_id`
}

// keyType is VARBINARY: MySQL and MariaDB compare text under the column's
// collation — case- and accent-insensitive by default, trailing spaces
// ignored by every PAD SPACE one, utf8mb4_bin included — and binary
// strings byte for byte.
func (mysql) keyType(length int) string { return "VARBINARY(" + strconv.Itoa(length) + ")" }

func (mysql) lockFamily() string  { return lockFamilyForUpdate }
func (mysql) lockRefresh() string { return lockRefreshForUpdate }

// tableOptions names the engine and the character set: a table created
// with the server's default engine would be MyISAM on a server configured
// so, without transactions or row locks.
func (mysql) tableOptions() string { return " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" }

func (mysql) checkDeployment(ctx context.Context, db *sql.DB) error { return checkMySQL(ctx, db) }

// purgeStatements are single-table DELETEs with LIMIT, which MySQL accepts
// (unlike LIMIT in an IN subquery): the statement locks and re-checks each
// row it deletes on its latest version.
func (mysql) purgeStatements() []string {
	return []string{
		`DELETE FROM oauth2_auth_codes WHERE expires_at < ? LIMIT ?`,
		`DELETE FROM oauth2_access_tokens WHERE expires_at < ? LIMIT ?`,
		`DELETE FROM oauth2_refresh_tokens WHERE expires_at < ? LIMIT ?`,
		`DELETE FROM oauth2_token_families WHERE expires_at < ? LIMIT ?`,
	}
}

func (mysql) purgeArgs(before int64, limit int) []any { return []any{before, limit} }

// purgeTxOptions pins READ COMMITTED: at the server's default, REPEATABLE
// READ, a batch locks every record it scans and the gaps between them,
// blocking the inserts of /authorize and /token until it commits.
func (mysql) purgeTxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

func (mysql) txOptions() *sql.TxOptions { return nil }

// migrationLock is empty: MySQL commits every DDL statement on its own,
// and serializes the creation of a table on the metadata lock of its name.
func (mysql) migrationLock() string { return "" }

// dialectSQLite is the dialect identifier for SQLite.
const dialectSQLite = "sqlite"

type sqlite struct{}

func (sqlite) Name() string           { return dialectSQLite }
func (sqlite) rebind(q string) string { return q }

func (sqlite) insertFamily() string { return insertFamilyOnConflict }

// keyType is VARCHAR: SQLite compares text byte for byte under its default
// BINARY collation.
func (sqlite) keyType(length int) string { return varchar(length) }

func (sqlite) tableOptions() string { return "" }

func (sqlite) purgeStatements() []string               { return purgeSubqueries }
func (sqlite) purgeArgs(before int64, limit int) []any { return subqueryArgs(before, limit) }

// purgeTxOptions are the defaults: SQLite's single writer serializes the
// batches with every other write.
func (sqlite) purgeTxOptions() *sql.TxOptions { return nil }

// checkDeployment checks nothing: SQLite has one engine, and a missing busy
// timeout fails operations closed (SQLITE_BUSY).
func (sqlite) checkDeployment(context.Context, *sql.DB) error { return nil }

// varchar is the VARCHAR(length) column type.
func varchar(length int) string { return "VARCHAR(" + strconv.Itoa(length) + ")" }

// lockFamily and lockRefresh are plain reads: SQLite has no FOR UPDATE,
// and the write that opens every store transaction already holds the
// database's single write lock.
func (sqlite) lockFamily() string {
	return `SELECT revoked_at FROM oauth2_token_families WHERE family_id = ?`
}

func (sqlite) lockRefresh() string {
	return `SELECT family_id, consumed, COALESCE(issuer, ''), COALESCE(extension_data, '')
		FROM oauth2_refresh_tokens WHERE token_hash = ?`
}

func (sqlite) txOptions() *sql.TxOptions { return nil }

// migrationLock is empty: SQLite's single writer serializes the creation
// of the tables, and a statement prepared before a concurrent change of the
// schema is prepared again.
func (sqlite) migrationLock() string { return "" }
