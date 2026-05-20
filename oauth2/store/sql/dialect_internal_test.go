// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDialectRebind(t *testing.T) {
	t.Parallel()

	const query = `SELECT * FROM t WHERE a = ? AND b = ? AND c = ?`

	// Postgres rewrites "?" into positional $N placeholders.
	assert.Equal(t,
		`SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3`,
		postgres{}.rebind(query))

	// MySQL and SQLite keep the "?" placeholders verbatim.
	assert.Equal(t, query, mysql{}.rebind(query))
	assert.Equal(t, query, sqlite{}.rebind(query))

	// A query with no placeholders is returned unchanged by every dialect.
	const noParams = `SELECT 1`
	assert.Equal(t, noParams, postgres{}.rebind(noParams))
}
