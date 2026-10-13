// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"strings"
	"testing"

	sqlstore "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSchemaPerDialect pins the DDL of each engine. PostgreSQL and SQLite —
// and a nil Dialect — get one portable DDL: no BOOLEAN (PostgreSQL has no
// implicit integer/boolean cast, so BOOLEAN DEFAULT 0 and consumed = 1 are
// rejected) and no CREATE INDEX (MySQL has no CREATE INDEX IF NOT EXISTS).
// MySQL gets the same DDL but for its six key columns — the code and token
// hashes and the token-family IDs, the only columns the statements
// compare — which are VARBINARY: MySQL and MariaDB compare binary strings
// byte for byte, text under a collation that may ignore case, accents or
// trailing spaces.
func TestSchemaPerDialect(t *testing.T) {
	t.Parallel()

	portable := sqlstore.Schema(sqlstore.SQLite)
	assert.Equal(t, portable, sqlstore.Schema(sqlstore.Postgres))
	assert.Equal(t, portable, sqlstore.Schema(nil))

	for _, stmt := range portable {
		assert.NotContains(t, strings.ToUpper(stmt), "BOOLEAN", stmt)
		assert.NotContains(t, strings.ToUpper(stmt), "CREATE INDEX", stmt)
		assert.NotContains(t, stmt, "VARBINARY", stmt)
	}

	assert.Contains(t, strings.Join(portable, "\n"), "consumed   SMALLINT")

	mysql := sqlstore.Schema(sqlstore.MySQL)
	require.Len(t, mysql, len(portable))

	for i, stmt := range mysql {
		assert.Equal(t, portable[i], strings.ReplaceAll(stmt, "VARBINARY(", "VARCHAR("), "only the key columns differ")
	}

	ddl := strings.Join(mysql, "\n")

	assert.Equal(t, 6, strings.Count(ddl, "VARBINARY("))

	for column, n := range map[string]int{
		"code_hash             VARBINARY(128) PRIMARY KEY": 1,
		"token_hash VARBINARY(128) PRIMARY KEY":            2,
		"family_id  VARBINARY(64)  NOT NULL":               2,
		"family_id  VARBINARY(64)  PRIMARY KEY":            1,
	} {
		assert.Equal(t, n, strings.Count(ddl, column), column)
	}
}
