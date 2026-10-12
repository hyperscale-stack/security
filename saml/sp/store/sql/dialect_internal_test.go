// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRebind(t *testing.T) {
	t.Parallel()

	q := `UPDATE t SET a = 1 WHERE b = ? AND c = ?`
	assert.Equal(t, `UPDATE t SET a = 1 WHERE b = $1 AND c = $2`, Postgres.rebind(q))
	assert.Equal(t, q, MySQL.rebind(q))
	assert.Equal(t, q, SQLite.rebind(q))
}
