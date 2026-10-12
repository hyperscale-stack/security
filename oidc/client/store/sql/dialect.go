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
// parameter-placeholder style, the locking read of Consume and the
// transaction isolation level. The store writes every query with "?"
// placeholders and rebinds them through the dialect.
type Dialect interface {
	// Name returns a stable identifier ("postgres", "mysql", "sqlite").
	Name() string
	// rebind rewrites a "?"-placeholder query into the dialect's native
	// placeholder style. Postgres needs $1,$2,…; MySQL and SQLite keep ?.
	rebind(query string) string
	// lockRow reads a transaction under a row lock.
	lockRow() string
	// txOptions are the options of the Consume transaction.
	txOptions() *sql.TxOptions
}

// selectTransaction reads a transaction by its state hash.
const selectTransaction = `SELECT state_hash, binding_hash, connection_id, issuer, client_id, redirect_uri,
		response_mode, max_age, acr_values, app_state, created_at, expires_at, integrity
		FROM oidc_client_transactions WHERE state_hash = ?`

// Postgres is the PostgreSQL dialect ($1,$2,… placeholders). Consume runs
// at READ COMMITTED whatever the server default, so that its locking read
// waits for a concurrent consumer and then sees its deletion, where
// REPEATABLE READ or SERIALIZABLE would abort with a serialization failure.
var Postgres Dialect = postgres{}

// MySQL is the MySQL / MariaDB dialect (? placeholders). The table must be
// InnoDB: Consume relies on its row locks.
var MySQL Dialect = mysql{}

// SQLite is the SQLite dialect (? placeholders). SQLite has no row locks:
// its single writer serializes the Consume transactions, each of which
// starts with a write.
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

func (postgres) lockRow() string { return selectTransaction + " FOR UPDATE" }

func (postgres) txOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

type mysql struct{}

func (mysql) Name() string              { return "mysql" }
func (mysql) rebind(q string) string    { return q }
func (mysql) lockRow() string           { return selectTransaction + " FOR UPDATE" }
func (mysql) txOptions() *sql.TxOptions { return nil }

type sqlite struct{}

func (sqlite) Name() string           { return "sqlite" }
func (sqlite) rebind(q string) string { return q }

// lockRow is a plain read: SQLite has no FOR UPDATE, and the write opening
// the Consume transaction already holds the database's write lock.
func (sqlite) lockRow() string { return selectTransaction }

func (sqlite) txOptions() *sql.TxOptions { return nil }
