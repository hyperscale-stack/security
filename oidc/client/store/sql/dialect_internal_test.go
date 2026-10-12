// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDialectRebind(t *testing.T) {
	t.Parallel()

	const query = `SELECT * FROM t WHERE a = ? AND b = ? AND c = ?`

	assert.Equal(t, `SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3`, postgres{}.rebind(query))
	assert.Equal(t, query, mysql{}.rebind(query))
	assert.Equal(t, query, sqlite{}.rebind(query))
	assert.Equal(t, `SELECT 1`, postgres{}.rebind(`SELECT 1`))
}

// TestDialectLocking pins the locking read and the isolation level of
// Consume per engine.
func TestDialectLocking(t *testing.T) {
	t.Parallel()

	for _, d := range []Dialect{Postgres, MySQL} {
		assert.True(t, strings.HasSuffix(d.lockRow(), " FOR UPDATE"), d.Name())
		assert.True(t, strings.HasPrefix(d.lockRow(), selectTransaction), d.Name())
	}

	assert.Equal(t, selectTransaction, SQLite.lockRow(), "SQLite has no FOR UPDATE")

	assert.Equal(t, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, Postgres.txOptions())
	assert.Nil(t, MySQL.txOptions())
	assert.Nil(t, SQLite.txOptions())
}
