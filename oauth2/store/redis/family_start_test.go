// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore_test

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisstore "github.com/hyperscale-stack/security/oauth2/store/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedisRefreshPayloadOmitsAnUnsetFamilyStart pins the payload of a
// refresh token without a recorded family start: the field is absent, like
// in a payload written before it existed — never the negative Unix second
// of year 1 — while a recorded start is kept in Unix seconds.
func TestRedisRefreshPayloadOmitsAnUnsetFamilyStart(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := redisstore.New(client)
	require.NoError(t, err)

	unset := testPair("start-unset", "fam-start-unset", time.Hour)
	require.NoError(t, store.SaveTokenPair(t.Context(), unset))

	raw, err := mr.Get(rtKey(unset.Refresh.TokenHash))
	require.NoError(t, err)
	assert.NotContains(t, raw, "family_issued_at")

	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	set := testPair("start-set", "fam-start-set", time.Hour)
	set.Refresh.FamilyIssuedAt = start
	require.NoError(t, store.SaveTokenPair(t.Context(), set))

	raw, err = mr.Get(rtKey(set.Refresh.TokenHash))
	require.NoError(t, err)
	assert.Contains(t, raw, `"family_issued_at":`)
}
