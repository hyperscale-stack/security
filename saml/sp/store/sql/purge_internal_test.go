// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPurgeExpiredInBatches deletes a backlog larger than a batch, batch
// after batch. It changes purgeBatch, so it does not run in parallel.
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
		sum := sha256.Sum256([]byte("expired-" + strconv.Itoa(i)))
		require.NoError(t, store.MarkAssertionUsed(t.Context(), hex.EncodeToString(sum[:]), now.Add(-time.Hour)))
	}

	n, err := store.PurgeExpired(t.Context(), now)
	require.NoError(t, err)
	assert.Equal(t, int64(5), n)
}
