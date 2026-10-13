// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
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
// InnoDB: the store relies on its row locks. Its key columns are
// VARBINARY (see [Schema]).
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
