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

// Dialect abstracts the SQL differences the store cares about: the
// parameter placeholders, the serialization of concurrent migrations, the
// table options and the deployment check. Every statement is written with
// "?" and rebound.
type Dialect interface {
	// Name returns a stable identifier: "postgres", "mysql" or "sqlite".
	Name() string
	// rebind rewrites "?" placeholders into the dialect's style.
	rebind(query string) string
	// migrationLock is the statement [Store.Migrate] runs first, in the
	// transaction creating the tables, to serialize concurrent migrations;
	// "" when the engine serializes the creation of a table itself and
	// Migrate runs its statements one by one.
	migrationLock() string
	// tableOptions follows the column list of every CREATE TABLE of
	// [Schema]: the storage engine and character set the dialect needs,
	// "" when it needs none.
	tableOptions() string
	// namedMigrationLock is the session-level named lock [Store.Migrate]
	// takes around the creation of the tables and its deployment check, on
	// an engine whose DDL cannot run in a transaction; "" for none.
	namedMigrationLock() string
	// checkDeployment verifies the requirements of the package
	// documentation the database reports (see [Store.CheckDeployment]).
	checkDeployment(ctx context.Context, q querier) error
	// purgeStatements are the statements [Store.PurgeExpired] runs, one
	// per table, each deleting at most a batch of the rows expired before
	// a second.
	purgeStatements() []string
	// purgeArgs are the arguments of a purge statement: the second rows
	// must have expired before, and the batch size.
	purgeArgs(before int64, limit int) []any
	// purgeTxOptions are the options of a purge batch's transaction.
	purgeTxOptions() *sql.TxOptions
}

// migrationLockKey is the PostgreSQL advisory lock [Store.Migrate] takes:
// the first eight bytes of SHA-256 of
// "github.com/hyperscale-stack/security/saml/sp/store/sql.Migrate",
// big-endian, as a bigint. Advisory locks are local to a database, which
// the stores of other modules may share: each store module has a key of
// its own, so that their migrations never wait for one another.
const migrationLockKey = "1266919442082856213"

// Postgres is the PostgreSQL dialect ($1, $2, … placeholders).
// [Store.Migrate] takes the transaction-level advisory lock
// 1266919442082856213 (pg_advisory_xact_lock) before creating the tables.
var Postgres Dialect = postgres{}

// MySQL is the MySQL / MariaDB dialect (? placeholders). [Schema] creates
// its tables InnoDB (ENGINE=InnoDB DEFAULT CHARSET=utf8mb4), and
// [Store.CheckDeployment] verifies they are.
var MySQL Dialect = mysql{}

// SQLite is the SQLite dialect (? placeholders).
var SQLite Dialect = sqlite{}

type postgres struct{}

func (postgres) Name() string { return "postgres" }

// rebind replaces each ? with $N.
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

// migrationLock takes a transaction-level advisory lock: concurrent
// CREATE TABLE IF NOT EXISTS of one table can both find it missing, and
// the loser then fails on the unique index of the catalog's row types. A
// transaction-level lock is released by the COMMIT or ROLLBACK ending the
// migration, whatever becomes of the connection afterwards.
func (postgres) migrationLock() string {
	return "SELECT pg_advisory_xact_lock(" + migrationLockKey + ")"
}

func (postgres) tableOptions() string { return "" }

func (postgres) purgeStatements() []string { return purgeSubqueries }

func (postgres) purgeArgs(before int64, limit int) []any { return []any{before, limit, before} }

// purgeTxOptions pins READ COMMITTED: a serialization failure would abort
// a batch under REPEATABLE READ or SERIALIZABLE.
func (postgres) purgeTxOptions() *sql.TxOptions { return readCommitted }

// checkDeployment checks nothing PostgreSQL reports.
func (postgres) checkDeployment(context.Context, querier) error { return nil }

func (postgres) namedMigrationLock() string { return "" }

type mysql struct{}

func (mysql) Name() string           { return "mysql" }
func (mysql) rebind(q string) string { return q }

// migrationLock is empty: MySQL commits every DDL statement on its own, so
// Migrate takes a named lock instead (see namedMigrationLock).
func (mysql) migrationLock() string { return "" }

// tableOptions names the engine and the character set: a table created
// with the server's default engine would be MyISAM on a server configured
// so, without crash safety.
func (mysql) tableOptions() string { return " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" }

func (mysql) checkDeployment(ctx context.Context, q querier) error { return checkMySQL(ctx, q) }

// namedMigrationLock serializes the Migrate calls of a deployment: MySQL
// commits every DDL statement on its own, so no transaction can hold a
// lock across them, and concurrent CREATE TABLE IF NOT EXISTS of one
// table can fail with a metadata-lock deadlock (1213).
func (mysql) namedMigrationLock() string { return migrationLockName }

// purgeStatements are single-table DELETEs with LIMIT, which MySQL accepts
// (unlike LIMIT in an IN subquery).
func (mysql) purgeStatements() []string {
	return []string{
		`DELETE FROM samlsp_transactions WHERE expires_at < ? LIMIT ?`,
		`DELETE FROM samlsp_used_assertions WHERE expires_at < ? LIMIT ?`,
	}
}

func (mysql) purgeArgs(before int64, limit int) []any { return []any{before, limit} }

// purgeTxOptions pins READ COMMITTED: at REPEATABLE READ a batch locks
// the gaps it scans, blocking the inserts of SaveTransaction and
// MarkAssertionUsed until it commits.
func (mysql) purgeTxOptions() *sql.TxOptions { return readCommitted }

type sqlite struct{}

func (sqlite) Name() string           { return "sqlite" }
func (sqlite) rebind(q string) string { return q }

// migrationLock is empty: SQLite's single writer serializes the creation
// of the tables, and a statement prepared before a concurrent change of the
// schema is prepared again.
func (sqlite) migrationLock() string { return "" }

func (sqlite) tableOptions() string { return "" }

func (sqlite) purgeStatements() []string { return purgeSubqueries }

func (sqlite) purgeArgs(before int64, limit int) []any { return []any{before, limit, before} }

// purgeTxOptions are the defaults: SQLite's single writer serializes the
// batches with every other write.
func (sqlite) purgeTxOptions() *sql.TxOptions { return nil }

// checkDeployment checks nothing: SQLite has one engine.
func (sqlite) checkDeployment(context.Context, querier) error { return nil }

func (sqlite) namedMigrationLock() string { return "" }
