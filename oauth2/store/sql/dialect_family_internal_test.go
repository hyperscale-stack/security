// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDialectFamilyStatements(t *testing.T) {
	t.Parallel()

	const (
		onConflict = `INSERT INTO oauth2_token_families (family_id, revoked_at, expires_at) VALUES (?, ?, ?)
		ON CONFLICT (family_id) DO NOTHING`
		onDuplicate = `INSERT INTO oauth2_token_families (family_id, revoked_at, expires_at) VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE family_id = family_id`
		familyForUpdate  = `SELECT revoked_at FROM oauth2_token_families WHERE family_id = ? FOR UPDATE`
		refreshForUpdate = `SELECT family_id, consumed FROM oauth2_refresh_tokens WHERE token_hash = ? FOR UPDATE`
	)

	cases := []struct {
		dialect                               Dialect
		insertFamily, lockFamily, lockRefresh string
		txOptions                             *sql.TxOptions
	}{
		// PostgreSQL pins READ COMMITTED: a locking read then re-reads the
		// latest committed row instead of failing on a concurrent update.
		{
			postgres{}, onConflict, familyForUpdate, refreshForUpdate,
			&sql.TxOptions{Isolation: sql.LevelReadCommitted},
		},
		{mysql{}, onDuplicate, familyForUpdate, refreshForUpdate, nil},
		// SQLite has no FOR UPDATE: its single writer serializes instead.
		{
			sqlite{}, onConflict,
			`SELECT revoked_at FROM oauth2_token_families WHERE family_id = ?`,
			`SELECT family_id, consumed FROM oauth2_refresh_tokens WHERE token_hash = ?`,
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.dialect.Name(), func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.insertFamily, tc.dialect.insertFamily())
			assert.Equal(t, tc.lockFamily, tc.dialect.lockFamily())
			assert.Equal(t, tc.lockRefresh, tc.dialect.lockRefresh())
			assert.Equal(t, tc.txOptions, tc.dialect.txOptions())
		})
	}

	// PostgreSQL numbers the placeholders of the family statements too.
	assert.Equal(t,
		`INSERT INTO oauth2_token_families (family_id, revoked_at, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (family_id) DO NOTHING`,
		postgres{}.rebind(postgres{}.insertFamily()))
	assert.Equal(t,
		`SELECT family_id, consumed FROM oauth2_refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		postgres{}.rebind(postgres{}.lockRefresh()))
}
