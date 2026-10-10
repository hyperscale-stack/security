// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"strings"
	"testing"

	sqlstore "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/stretchr/testify/assert"
)

// TestSchemaIsPortable pins a DDL every supported engine accepts:
// PostgreSQL has no implicit integer/boolean cast (BOOLEAN DEFAULT 0 and
// consumed = 1 are rejected) and MySQL has no CREATE INDEX IF NOT EXISTS,
// so the schema sticks to the portable subset and is the same everywhere.
func TestSchemaIsPortable(t *testing.T) {
	t.Parallel()

	want := sqlstore.Schema(sqlstore.SQLite)

	for _, d := range []sqlstore.Dialect{sqlstore.Postgres, sqlstore.MySQL} {
		assert.Equal(t, want, sqlstore.Schema(d), d.Name())
	}

	for _, stmt := range want {
		assert.NotContains(t, strings.ToUpper(stmt), "BOOLEAN", stmt)
		assert.NotContains(t, strings.ToUpper(stmt), "CREATE INDEX", stmt)
	}

	assert.Contains(t, strings.Join(want, "\n"), "consumed   SMALLINT")
}
