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
// parameter-placeholder style, the locking read of Consume, the
// transaction isolation level and the serialization of concurrent
// migrations. The store writes every query with "?" placeholders and
// rebinds them through the dialect.
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
	// migrationLock is the statement [Store.Migrate] runs first, in the
	// transaction creating the table, to serialize concurrent migrations;
	// "" when the engine serializes the creation of a table itself and
	// Migrate runs its statement on its own.
	migrationLock() string
	// tableOptions follows the column list of the CREATE TABLE of
	// [Schema]: the storage engine and character set the dialect needs,
	// "" when it needs none.
	tableOptions() string
	// checkDeployment verifies the requirements of the package
	// documentation the database reports (see [Store.CheckDeployment]).
	checkDeployment(ctx context.Context, db *sql.DB) error
	// purgeTxOptions are the options of the [Store.PurgeExpired]
	// transaction.
	purgeTxOptions() *sql.TxOptions
}

// migrationLockKey is the PostgreSQL advisory lock [Store.Migrate] takes:
// the first eight bytes of SHA-256 of
// "github.com/hyperscale-stack/security/oidc/client/store/sql.Migrate",
// big-endian, as a bigint. Advisory locks are local to a database, which
// the stores of other modules may share: each store module has a key of
// its own, so that their migrations never wait for one another.
const migrationLockKey = "-3346565968272468758"

// selectTransaction reads a transaction by its state hash.
const selectTransaction = `SELECT state_hash, binding_hash, connection_id, issuer, client_id, redirect_uri,
		response_mode, max_age, acr_values, app_state, created_at, expires_at, integrity
		FROM oidc_client_transactions WHERE state_hash = ?`

// Postgres is the PostgreSQL dialect ($1,$2,… placeholders). Consume runs
// at READ COMMITTED whatever the server default, so that its locking read
// waits for a concurrent consumer and then sees its deletion, where
// REPEATABLE READ or SERIALIZABLE would abort with a serialization failure.
// [Store.Migrate] takes the transaction-level advisory lock
// -3346565968272468758 (pg_advisory_xact_lock) before creating the table.
var Postgres Dialect = postgres{}

// MySQL is the MySQL / MariaDB dialect (? placeholders). The table must be
// InnoDB — Consume relies on its row locks — and [Schema] creates it so
// (ENGINE=InnoDB DEFAULT CHARSET=utf8mb4); [Store.CheckDeployment]
// verifies it.
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

// migrationLock takes a transaction-level advisory lock: concurrent
// CREATE TABLE IF NOT EXISTS of one table can both find it missing, and
// the loser then fails on the unique index of the catalog's row types. A
// transaction-level lock is released by the COMMIT or ROLLBACK ending the
// migration, whatever becomes of the connection afterwards.
func (postgres) migrationLock() string {
	return "SELECT pg_advisory_xact_lock(" + migrationLockKey + ")"
}

func (postgres) tableOptions() string { return "" }

func (postgres) purgeTxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

// checkDeployment checks nothing: the store pins READ COMMITTED itself.
func (postgres) checkDeployment(context.Context, *sql.DB) error { return nil }

type mysql struct{}

func (mysql) Name() string              { return "mysql" }
func (mysql) rebind(q string) string    { return q }
func (mysql) lockRow() string           { return selectTransaction + " FOR UPDATE" }
func (mysql) txOptions() *sql.TxOptions { return nil }

// migrationLock is empty: MySQL commits every DDL statement on its own,
// and serializes the creation of a table on the metadata lock of its name.
func (mysql) migrationLock() string { return "" }

// tableOptions names the engine and the character set: a table created
// with the server's default engine would be MyISAM on a server configured
// so, without transactions, row locks or crash safety.
func (mysql) tableOptions() string { return " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" }

func (mysql) checkDeployment(ctx context.Context, db *sql.DB) error { return checkMySQL(ctx, db) }

// purgeTxOptions pins READ COMMITTED: at REPEATABLE READ the purge locks
// the gaps it scans, blocking the inserts of Save until it commits.
func (mysql) purgeTxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadCommitted}
}

type sqlite struct{}

func (sqlite) Name() string           { return "sqlite" }
func (sqlite) rebind(q string) string { return q }

// lockRow is a plain read: SQLite has no FOR UPDATE, and the write opening
// the Consume transaction already holds the database's write lock.
func (sqlite) lockRow() string { return selectTransaction }

func (sqlite) txOptions() *sql.TxOptions { return nil }

// migrationLock is empty: SQLite's single writer serializes the creation
// of the table, and a statement prepared before a concurrent change of the
// schema is prepared again.
func (sqlite) migrationLock() string { return "" }

func (sqlite) tableOptions() string { return "" }

func (sqlite) purgeTxOptions() *sql.TxOptions { return nil }

// checkDeployment checks nothing: SQLite has one engine.
func (sqlite) checkDeployment(context.Context, *sql.DB) error { return nil }
