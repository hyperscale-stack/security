// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package memory_test

import (
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryKeepsNoRawToken: like every store, the in-memory one keeps
// tokens hashed only — SaveTokenPair and RotateRefreshToken store copies
// without the raw value, and the lookups never return it — while the pairs
// the caller handed over keep theirs.
func TestMemoryKeepsNoRawToken(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pair := func(raw string) *oauth2.TokenPair {
		return &oauth2.TokenPair{
			Access: oauth2.AccessToken{
				Token: raw + "-access", TokenHash: oauth2.HashToken(nil, raw+"-access"),
				FamilyID: "fam", ExpiresAt: now.Add(time.Hour),
			},
			Refresh: &oauth2.RefreshToken{
				Token: raw, TokenHash: oauth2.HashToken(nil, raw),
				FamilyID: "fam", ExpiresAt: now.Add(time.Hour),
			},
		}
	}

	s := memory.New()
	first, next := pair("RAW-REFRESH-SECRET"), pair("RAW-REFRESH-2")

	require.NoError(t, s.SaveTokenPair(t.Context(), first))
	require.NoError(t, s.RotateRefreshToken(t.Context(), first.Refresh.TokenHash, next))

	for _, p := range []*oauth2.TokenPair{first, next} {
		at, err := s.LookupAccessToken(t.Context(), p.Access.TokenHash)
		require.NoError(t, err)
		assert.Empty(t, at.Token, "the raw access token is never kept")

		rt, err := s.LookupRefreshToken(t.Context(), p.Refresh.TokenHash)
		require.NoError(t, err)
		assert.Empty(t, rt.Token, "the raw refresh token is never kept")
	}

	assert.Equal(t, "RAW-REFRESH-SECRET-access", first.Access.Token, "the caller's pair is untouched")
	assert.Equal(t, "RAW-REFRESH-2", next.Refresh.Token, "the caller's pair is untouched")
}
