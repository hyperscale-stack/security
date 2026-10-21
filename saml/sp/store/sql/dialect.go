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
	// checkDeployment verifies the requirements of the package
	// documentation the database reports (see [Store.CheckDeployment]).
	checkDeployment(ctx context.Context, db *sql.DB) error
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

// checkDeployment checks nothing PostgreSQL reports.
func (postgres) checkDeployment(context.Context, *sql.DB) error { return nil }

type mysql struct{}

func (mysql) Name() string           { return "mysql" }
func (mysql) rebind(q string) string { return q }

// migrationLock is empty: MySQL commits every DDL statement on its own,
// and serializes the creation of a table on the metadata lock of its name.
func (mysql) migrationLock() string { return "" }

// tableOptions names the engine and the character set: a table created
// with the server's default engine would be MyISAM on a server configured
// so, without crash safety.
func (mysql) tableOptions() string { return " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" }

func (mysql) checkDeployment(ctx context.Context, db *sql.DB) error { return checkMySQL(ctx, db) }

type sqlite struct{}

func (sqlite) Name() string           { return "sqlite" }
func (sqlite) rebind(q string) string { return q }

// migrationLock is empty: SQLite's single writer serializes the creation
// of the tables, and a statement prepared before a concurrent change of the
// schema is prepared again.
func (sqlite) migrationLock() string { return "" }

func (sqlite) tableOptions() string { return "" }

// checkDeployment checks nothing: SQLite has one engine.
func (sqlite) checkDeployment(context.Context, *sql.DB) error { return nil }
