// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"strconv"
	"strings"
)

// Dialect abstracts the SQL differences the store cares about: only the
// parameter placeholders. Every statement is written with "?" and rebound.
type Dialect interface {
	// Name returns a stable identifier: "postgres", "mysql" or "sqlite".
	Name() string
	// rebind rewrites "?" placeholders into the dialect's style.
	rebind(query string) string
}

// Postgres is the PostgreSQL dialect ($1, $2, … placeholders).
var Postgres Dialect = postgres{}

// MySQL is the MySQL / MariaDB dialect (? placeholders, InnoDB tables).
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

type mysql struct{}

func (mysql) Name() string           { return "mysql" }
func (mysql) rebind(q string) string { return q }

type sqlite struct{}

func (sqlite) Name() string           { return "sqlite" }
func (sqlite) rebind(q string) string { return q }
