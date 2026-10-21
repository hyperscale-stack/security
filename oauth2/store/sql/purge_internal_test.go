// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"database/sql"
	"strconv"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPurgeExpiredInBatches deletes a backlog larger than a batch, batch
// after batch, until one comes back short. It changes purgeBatch, so it
// does not run in parallel.
func TestPurgeExpiredInBatches(t *testing.T) {
	defer func(batch int) { purgeBatch = batch }(purgeBatch)

	purgeBatch = 2

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	store, err := New(db, SQLite)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(t.Context()))

	now := time.Unix(time.Now().Unix(), 0)

	for i := range 5 {
		require.NoError(t, store.SaveAuthorizationCode(t.Context(), &oauth2.AuthorizationCode{
			CodeHash: "expired-" + strconv.Itoa(i), ClientID: "c", Subject: "s", RedirectURI: "https://app.example/cb",
			Scope: "r", IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
		}))
	}

	n, err := store.PurgeExpired(t.Context(), now)
	require.NoError(t, err)
	assert.Equal(t, int64(5), n)

	var left int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM oauth2_auth_codes`).Scan(&left))
	assert.Zero(t, left)
}
