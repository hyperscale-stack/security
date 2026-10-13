// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// familyStart is the issuance time of the families the lifetime tests seed.
var familyStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// familyConfig is a grant configuration with RefreshTTL 24h and
// RefreshFamilyTTL familyTTL.
func familyConfig(store oauth2.Storage, familyTTL time.Duration) grant.Config {
	return grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, RefreshFamilyTTL: familyTTL,
	}
}

// seedFamily stores a pair of family "fam-life" whose refresh token raw was
// issued at issuedAt, expires at expiresAt and records familyIssuedAt.
func seedFamily(t *testing.T, store oauth2.Storage, raw string, issuedAt, expiresAt, familyIssuedAt time.Time) {
	t.Helper()

	pair := clientPair(raw, "fam-life", "read:mail", expiresAt)
	pair.Access.IssuedAt, pair.Refresh.IssuedAt = issuedAt, issuedAt
	pair.Refresh.FamilyIssuedAt = familyIssuedAt
	require.NoError(t, store.SaveTokenPair(t.Context(), pair))
}

// refreshAt is the BCP refresh request of raw at instant now.
func refreshAt(raw string, now time.Time) grant.Request {
	req := refreshReq(raw, oauth2.Profile20BCP)
	req.Now = now

	return req
}

// TestCodeExchangeRecordsTheFamilyStart: the first issuance of a family
// records its start on the refresh token — whatever RefreshFamilyTTL, so a
// bound set later applies to it — and caps the refresh token's expiry at the
// family's deadline when one is set.
func TestCodeExchangeRecordsTheFamilyStart(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		familyTTL, expiresIn time.Duration
	}{
		"no bound":                {0, 24 * time.Hour},
		"bound beyond RefreshTTL": {72 * time.Hour, 24 * time.Hour},
		"bound within RefreshTTL": {time.Hour, time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := memory.New()
			req := codeRequest(t, store, "family-code")

			resp, err := grant.NewAuthorizationCode(familyConfig(store, tc.familyTTL)).Handle(t.Context(), req)
			require.NoError(t, err)
			require.NotNil(t, resp.Pair.Refresh)
			assert.True(t, req.Now.Equal(resp.Pair.Refresh.FamilyIssuedAt), "the family starts at the exchange")
			assert.True(t, req.Now.Add(tc.expiresIn).Equal(resp.Pair.Refresh.ExpiresAt), "expiry %v", resp.Pair.Refresh.ExpiresAt)
		})
	}
}

// TestRefreshFamilyLifetime replays the audit's sliding-lifetime probe with
// a bound: RefreshTTL 24h slides at every rotation, but no replacement
// outlives the family's deadline (start + RefreshFamilyTTL, 72h), and the
// family dies there.
func TestRefreshFamilyLifetime(t *testing.T) {
	t.Parallel()

	store := memory.New()
	seedFamily(t, store, "life-0", familyStart, familyStart.Add(24*time.Hour), familyStart)

	g := grant.NewRefreshToken(familyConfig(store, 72*time.Hour))
	deadline := familyStart.Add(72 * time.Hour)
	raw := "life-0"

	for _, at := range []time.Duration{23 * time.Hour, 46 * time.Hour, 69 * time.Hour} {
		now := familyStart.Add(at)

		resp, err := g.Handle(t.Context(), refreshAt(raw, now))
		require.NoError(t, err, "refresh at +%v", at)
		assert.True(t, familyStart.Equal(resp.Pair.Refresh.FamilyIssuedAt), "the start is carried unchanged")

		want := now.Add(24 * time.Hour)
		if want.After(deadline) {
			want = deadline
		}

		assert.True(t, want.Equal(resp.Pair.Refresh.ExpiresAt), "+%v: expiry %v, want %v", at, resp.Pair.Refresh.ExpiresAt, want)

		raw = resp.Pair.Refresh.Token
	}

	_, err := g.Handle(t.Context(), refreshAt(raw, deadline.Add(time.Second)))
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

// TestRefreshFamilyLifetimeAppliesToExistingFamilies: the bound is checked
// against the recorded start at every refresh, so setting or shortening
// RefreshFamilyTTL ends existing families — rotating or not — with
// invalid_grant, nothing consumed.
func TestRefreshFamilyLifetimeAppliesToExistingFamilies(t *testing.T) {
	t.Parallel()

	for name, profile := range map[string]oauth2.Profile{"rotating": oauth2.Profile20BCP, "non-rotating": oauth2.Profile20} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := memory.New()
			seedFamily(t, store, "old-family", familyStart, familyStart.Add(24*time.Hour), familyStart)

			req := refreshAt("old-family", familyStart.Add(2*time.Hour))
			req.Profile = profile

			resp, err := grant.NewRefreshToken(familyConfig(store, time.Hour)).Handle(t.Context(), req)
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
			assert.ErrorContains(t, err, "refresh token family expired")

			presented, err := store.LookupRefreshToken(t.Context(), oauth2.HashToken(nil, "old-family"))
			require.NoError(t, err)
			assert.False(t, presented.Consumed, "nothing consumed")
		})
	}
}

// TestRefreshFamilyLifetimeOfALegacyToken: a refresh token written before
// families recorded their start counts from its own issuance — the latest
// the family can have started — and hands that start to its replacement.
func TestRefreshFamilyLifetimeOfALegacyToken(t *testing.T) {
	t.Parallel()

	store := memory.New()
	seedFamily(t, store, "legacy-a", familyStart, familyStart.Add(100*time.Hour), time.Time{})
	seedFamily(t, store, "legacy-b", familyStart, familyStart.Add(100*time.Hour), time.Time{})

	g := grant.NewRefreshToken(familyConfig(store, 72*time.Hour))

	resp, err := g.Handle(t.Context(), refreshAt("legacy-a", familyStart.Add(71*time.Hour)))
	require.NoError(t, err)
	assert.True(t, familyStart.Equal(resp.Pair.Refresh.FamilyIssuedAt), "the start is adopted")
	assert.True(t, familyStart.Add(72*time.Hour).Equal(resp.Pair.Refresh.ExpiresAt))

	_, err = g.Handle(t.Context(), refreshAt("legacy-b", familyStart.Add(73*time.Hour)))
	assert.ErrorContains(t, err, "refresh token family expired")
}

// TestRefreshFamilyLifetimeZeroSlides is the audit's probe without a bound:
// 30 refreshes 23 hours apart keep the family alive — RefreshTTL is an
// inactivity expiry (RFC 9700 §4.14.2) — and the start stays recorded.
func TestRefreshFamilyLifetimeZeroSlides(t *testing.T) {
	t.Parallel()

	store := memory.New()
	seedFamily(t, store, "slide-0", familyStart, familyStart.Add(24*time.Hour), familyStart)

	g := grant.NewRefreshToken(familyConfig(store, 0))
	raw := "slide-0"

	for i := 1; i <= 30; i++ {
		resp, err := g.Handle(t.Context(), refreshAt(raw, familyStart.Add(time.Duration(i)*23*time.Hour)))
		require.NoError(t, err, "refresh %d", i)
		assert.True(t, familyStart.Equal(resp.Pair.Refresh.FamilyIssuedAt))

		raw = resp.Pair.Refresh.Token
	}
}

// TestPasswordGrantFamilyIsBounded: the legacy password grant starts a
// family too.
func TestPasswordGrantFamilyIsBounded(t *testing.T) {
	t.Parallel()

	g := grant.NewLegacyPassword(familyConfig(memory.New(), time.Hour), fakeROVerifier{subject: subject})

	now := time.Now()

	resp, err := g.Handle(t.Context(), grant.Request{Client: newClient(), Form: passwordForm("alice", "pw", ""), Now: now})
	require.NoError(t, err)
	require.NotNil(t, resp.Pair.Refresh)
	assert.True(t, now.Equal(resp.Pair.Refresh.FamilyIssuedAt))
	assert.True(t, now.Add(time.Hour).Equal(resp.Pair.Refresh.ExpiresAt))
}
