// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spyAccessGen is a [token.AccessTokenGenerator] counting its calls, so a
// test can prove that no access token was minted.
type spyAccessGen struct{ calls int }

func (s *spyAccessGen) Generate(context.Context, token.AccessTokenClaims) (string, string, error) {
	s.calls++

	const raw = "spy-access-token"

	return raw, oauth2.HashToken(nil, raw), nil
}

// refreshReq builds the /token request exchanging the raw refresh token
// under profile p.
func refreshReq(raw string, p oauth2.Profile) grant.Request {
	return grant.Request{
		Client:   newClient(),
		Form:     url.Values{"refresh_token": {raw}},
		Issuer:   "https://auth.example",
		Audience: "api",
		Now:      time.Now(),
		Profile:  p,
	}
}

func TestRefreshTokenRotationMandatedByProfile(t *testing.T) {
	t.Parallel()

	for _, p := range []oauth2.Profile{oauth2.Profile20BCP, oauth2.Profile21Draft} {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			store := newStore()
			seedRefresh(t, store, "mandated-rt", "read:mail", time.Now().Add(time.Hour))

			// RotateRefreshTokens is left false: the profile alone mandates
			// the rotation.
			g := grant.NewRefreshToken(grant.Config{
				Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
				AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
			})

			first, err := g.Handle(ctx, refreshReq("mandated-rt", p))
			require.NoError(t, err)
			require.NotNil(t, first.Pair.Refresh, "the profile mandates a replacement refresh token")
			assert.NotEqual(t, "mandated-rt", first.Pair.Refresh.Token)
			assert.Equal(t, "fam-x", first.Pair.Refresh.FamilyID, "the replacement stays in the family")

			presented, err := store.LookupRefreshToken(ctx, oauth2.HashToken(nil, "mandated-rt"))
			require.NoError(t, err)
			assert.True(t, presented.Consumed, "the rotation consumes the presented token")

			// Replaying the presented token is reuse: refused, family revoked.
			_, err = g.Handle(ctx, refreshReq("mandated-rt", p))
			require.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

			rotated, err := store.LookupRefreshToken(ctx, first.Pair.Refresh.TokenHash)
			require.NoError(t, err)
			assert.True(t, rotated.Consumed, "the family revocation consumes the replacement too")

			_, err = store.LookupAccessToken(ctx, first.Pair.Access.TokenHash)
			assert.Error(t, err, "the family revocation removes the access token of the rotation")
		})
	}
}

func TestRefreshTokenRotationWithoutGeneratorFailsBeforeIssuance(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		profile oauth2.Profile
		rotate  bool
	}{
		{"bcp mandates rotation", oauth2.Profile20BCP, false},
		{"2.1 mandates rotation", oauth2.Profile21Draft, false},
		{"profile20 opts in", oauth2.Profile20, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			store := newStore()
			seedRefresh(t, store, "stranded-rt", "read:mail", time.Now().Add(time.Hour))

			spy := &spyAccessGen{}
			g := grant.NewRefreshToken(grant.Config{
				Storage: store, AccessTokens: spy, // no RefreshTokens generator
				AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, RotateRefreshTokens: tc.rotate,
			})

			resp, err := g.Handle(ctx, refreshReq("stranded-rt", tc.profile))
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, grant.ErrRotationRequiresGenerator)
			assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))
			assert.Zero(t, spy.calls, "no access token is minted when the rotation cannot be honored")

			presented, err := store.LookupRefreshToken(ctx, oauth2.HashToken(nil, "stranded-rt"))
			require.NoError(t, err)
			assert.False(t, presented.Consumed, "the presented token is left untouched")
		})
	}
}

func TestRefreshTokenValidateProfile(t *testing.T) {
	t.Parallel()

	// The grant cannot honor a profile iff it has to rotate — opted in, or
	// mandated by any profile but Profile20 — without a refresh generator.
	cases := []struct {
		profile oauth2.Profile
		rotate  bool
		withGen bool
		wantErr bool
	}{
		{oauth2.Profile20, false, false, false},
		{oauth2.Profile20, false, true, false},
		{oauth2.Profile20, true, false, true},
		{oauth2.Profile20, true, true, false},
		{oauth2.Profile20BCP, false, false, true},
		{oauth2.Profile20BCP, false, true, false},
		{oauth2.Profile20BCP, true, false, true},
		{oauth2.Profile20BCP, true, true, false},
		{oauth2.Profile21Draft, false, false, true},
		{oauth2.Profile21Draft, false, true, false},
		{oauth2.Profile21Draft, true, false, true},
		{oauth2.Profile21Draft, true, true, false},
		{oauth2.Profile(99), false, false, true}, // an unknown profile fails closed
	}

	for _, tc := range cases {
		name := fmt.Sprintf("%s/rotate=%t/generator=%t", tc.profile, tc.rotate, tc.withGen)

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), RotateRefreshTokens: tc.rotate}
			if tc.withGen {
				cfg.RefreshTokens = newRefreshGen()
			}

			err := grant.NewRefreshToken(cfg).ValidateProfile(tc.profile)
			if tc.wantErr {
				assert.ErrorIs(t, err, grant.ErrRotationRequiresGenerator)

				return
			}

			assert.NoError(t, err)
		})
	}
}

// TestRefreshTokenReuseDetectedWithoutGenerator pins where the rotation
// guard sits: after reuse detection. A grant that cannot rotate still
// answers a replayed token with invalid_grant — not server_error — and
// still revokes its family.
func TestRefreshTokenReuseDetectedWithoutGenerator(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := newStore()
	req := consumedRefreshRequest(ctx, store) // family-1, Profile20BCP

	const sibling = "active-sibling"

	require.NoError(t, store.SaveRefreshToken(ctx, &oauth2.RefreshToken{
		Token: sibling, TokenHash: oauth2.HashToken(nil, sibling),
		ClientID: clientID, Subject: subject, Scope: "read:mail", FamilyID: "family-1",
		IssuedAt: req.Now, ExpiresAt: req.Now.Add(time.Hour),
	}))

	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour, // no RefreshTokens generator
	})

	resp, err := g.Handle(ctx, req)
	assert.Nil(t, resp)
	require.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	got, err := store.LookupRefreshToken(ctx, oauth2.HashToken(nil, sibling))
	require.NoError(t, err)
	assert.True(t, got.Consumed, "reuse revokes the whole family")
}
