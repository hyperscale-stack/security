// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"strconv"
	"strings"
)

// Dialect abstracts the few SQL syntax differences the store cares about:
// the parameter-placeholder style and the boolean literals. The store
// writes every query with "?" placeholders and rebinds them through the
// dialect, so query strings stay readable.
type Dialect interface {
	// Name returns a stable identifier ("postgres", "mysql", "sqlite")
	// used in error messages and OTel attributes.
	Name() string
	// rebind rewrites a "?"-placeholder query into the dialect's native
	// placeholder style. Postgres needs $1,$2,…; MySQL and SQLite keep ?.
	rebind(query string) string
}

// Postgres is the PostgreSQL dialect ($1,$2,… placeholders).
var Postgres Dialect = postgres{}

// MySQL is the MySQL / MariaDB dialect (? placeholders).
var MySQL Dialect = mysql{}

// SQLite is the SQLite dialect (? placeholders).
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

type mysql struct{}

func (mysql) Name() string           { return "mysql" }
func (mysql) rebind(q string) string { return q }

// dialectSQLite is the dialect identifier for SQLite, kept as a constant so
// it can be referenced from Name() and from schema generation.
const dialectSQLite = "sqlite"

type sqlite struct{}

func (sqlite) Name() string           { return dialectSQLite }
func (sqlite) rebind(q string) string { return q }
