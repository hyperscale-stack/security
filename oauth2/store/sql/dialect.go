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
// parameter-placeholder style, the insert-if-absent syntax, row locking and
// the transaction isolation level. The store writes every query with "?"
// placeholders and rebinds them through the dialect, so query strings stay
// readable.
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
	// lockRefresh reads a refresh token's family_id and consumed flag
	// under a row lock.
	lockRefresh() string
	// txOptions are the options of every store transaction.
	txOptions() *sql.TxOptions
}

// The token-family statements several dialects share, each a full literal.
const (
	insertFamilyOnConflict = `INSERT INTO oauth2_token_families (family_id, revoked_at, expires_at) VALUES (?, ?, ?)
		ON CONFLICT (family_id) DO NOTHING`
	lockFamilyForUpdate  = `SELECT revoked_at FROM oauth2_token_families WHERE family_id = ? FOR UPDATE`
	lockRefreshForUpdate = `SELECT family_id, consumed FROM oauth2_refresh_tokens WHERE token_hash = ? FOR UPDATE`
)

// Postgres is the PostgreSQL dialect ($1,$2,… placeholders). Its store
// transactions run at READ COMMITTED whatever the server default: the
// family lock and the consumption of a code rely on re-reading the latest
// committed row, where REPEATABLE READ or SERIALIZABLE would abort the
// transaction with a serialization failure instead.
var Postgres Dialect = postgres{}

// MySQL is the MySQL / MariaDB dialect (? placeholders). The tables must be
// InnoDB: the store relies on its row locks.
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

type mysql struct{}

func (mysql) Name() string           { return "mysql" }
func (mysql) rebind(q string) string { return q }

// insertFamily uses ON DUPLICATE KEY UPDATE rather than INSERT IGNORE,
// which would also silence errors such as a truncated value.
func (mysql) insertFamily() string {
	return `INSERT INTO oauth2_token_families (family_id, revoked_at, expires_at) VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE family_id = family_id`
}

func (mysql) lockFamily() string  { return lockFamilyForUpdate }
func (mysql) lockRefresh() string { return lockRefreshForUpdate }

func (mysql) txOptions() *sql.TxOptions { return nil }

// dialectSQLite is the dialect identifier for SQLite.
const dialectSQLite = "sqlite"

type sqlite struct{}

func (sqlite) Name() string           { return dialectSQLite }
func (sqlite) rebind(q string) string { return q }

func (sqlite) insertFamily() string { return insertFamilyOnConflict }

// lockFamily and lockRefresh are plain reads: SQLite has no FOR UPDATE,
// and the write that opens every store transaction already holds the
// database's single write lock.
func (sqlite) lockFamily() string {
	return `SELECT revoked_at FROM oauth2_token_families WHERE family_id = ?`
}

func (sqlite) lockRefresh() string {
	return `SELECT family_id, consumed FROM oauth2_refresh_tokens WHERE token_hash = ?`
}

func (sqlite) txOptions() *sql.TxOptions { return nil }
