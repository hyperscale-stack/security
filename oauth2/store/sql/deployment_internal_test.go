// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// innoDB is the engine of every table in a compliant MySQL database.
func innoDB() map[string]string {
	engines := map[string]string{}
	for _, table := range storeTables {
		engines[table] = "InnoDB"
	}

	return engines
}

// varbinary is the type of every key column in a compliant database.
func varbinary() map[string]string {
	types := map[string]string{"oauth2_auth_codes.client_id": "varchar"}
	for _, column := range keyColumns {
		types[column] = "varbinary"
	}

	return types
}

// requireUnmet asserts that err reports requirements not met, each of want
// matching ErrDeploymentRequirement on a line of its own.
func requireUnmet(t *testing.T, err error, want ...string) {
	t.Helper()

	require.ErrorIs(t, err, ErrDeploymentRequirement)

	lines := strings.Split(err.Error(), "\n")
	require.Len(t, lines, len(want), err.Error())

	for i, w := range want {
		assert.Equal(t, "sqlstore: deployment requirement not met: "+w, lines[i])
	}
}

func TestCheckEngines(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkEngines(storeTables, innoDB()))

	engines := innoDB()
	engines["oauth2_auth_codes"] = "innodb" // as a server may spell it
	require.NoError(t, checkEngines(storeTables, engines))

	engines["oauth2_access_tokens"] = "MyISAM"
	engines["oauth2_token_families"] = "MEMORY"
	delete(engines, "oauth2_refresh_tokens")

	requireUnmet(t, checkEngines(storeTables, engines),
		"table oauth2_access_tokens uses the MyISAM engine, not InnoDB",
		"table oauth2_refresh_tokens not found in the connection's database",
		"table oauth2_token_families uses the MEMORY engine, not InnoDB")

	requireUnmet(t, checkEngines(storeTables, map[string]string{}),
		"table oauth2_auth_codes not found in the connection's database",
		"table oauth2_access_tokens not found in the connection's database",
		"table oauth2_refresh_tokens not found in the connection's database",
		"table oauth2_token_families not found in the connection's database")
}

func TestCheckKeyColumns(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkKeyColumns(innoDB(), varbinary()))

	types := varbinary()
	types["oauth2_auth_codes.code_hash"] = "VARCHAR"
	types["oauth2_token_families.family_id"] = "char"
	delete(types, "oauth2_refresh_tokens.family_id")

	requireUnmet(t, checkKeyColumns(innoDB(), types),
		"column oauth2_auth_codes.code_hash is varchar, not varbinary: keys would be compared under a collation",
		"column oauth2_refresh_tokens.family_id not found",
		"column oauth2_token_families.family_id is char, not varbinary: keys would be compared under a collation")

	// The columns of a missing table are reported with the table, once.
	engines := innoDB()
	delete(engines, "oauth2_access_tokens")
	require.NoError(t, checkKeyColumns(engines, map[string]string{
		"oauth2_auth_codes.code_hash":       "varbinary",
		"oauth2_refresh_tokens.token_hash":  "varbinary",
		"oauth2_refresh_tokens.family_id":   "varbinary",
		"oauth2_token_families.family_id":   "varbinary",
		"oauth2_access_tokens.token_hash":   "varchar",
		"unrelated_table.unrelated_column":  "varchar",
		"oauth2_access_tokens.family_id":    "varchar",
		"oauth2_auth_codes.redirect_uri":    "text",
		"oauth2_refresh_tokens.extra_field": "int",
	}))
}

func TestCheckSQLMode(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{
		"STRICT_TRANS_TABLES",
		"STRICT_ALL_TABLES",
		"ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
		"STRICT_TRANS_TABLES,STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,TRADITIONAL,NO_ENGINE_SUBSTITUTION",
		"strict_all_tables",
		"ANSI_QUOTES, STRICT_TRANS_TABLES",
	} {
		require.NoError(t, checkSQLMode(mode), mode)
	}

	for _, mode := range []string{"", "NO_ENGINE_SUBSTITUTION", "ANSI_QUOTES,NO_ZERO_DATE", "STRICT", "NOT_STRICT_TRANS_TABLES"} {
		err := checkSQLMode(mode)
		requireUnmet(t, err, "sql_mode \""+mode+
			"\" is not strict (STRICT_TRANS_TABLES or STRICT_ALL_TABLES): an over-long value would be truncated")
	}
}

// TestCheckDeploymentPerDialect: PostgreSQL and SQLite report nothing the
// store checks; MySQL's check reaches the database, whose failure is
// returned as such, not as a requirement found unmet.
func TestCheckDeploymentPerDialect(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	for _, d := range []Dialect{Postgres, SQLite} {
		store, err := New(db, d)
		require.NoError(t, err)
		require.NoError(t, store.CheckDeployment(t.Context()), d.Name())
		assert.Empty(t, d.tableOptions(), d.Name())
	}

	store, err := New(db, MySQL)
	require.NoError(t, err)

	err = store.CheckDeployment(t.Context())
	require.ErrorContains(t, err, "sqlstore: check deployment: storage engines: ")
	require.False(t, errors.Is(err, ErrDeploymentRequirement), "a database failure is not a requirement found unmet")
	assert.Equal(t, " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4", MySQL.tableOptions())
}
