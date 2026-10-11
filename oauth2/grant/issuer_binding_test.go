// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The realms of the issuer-binding tests, and the opaque grant context an
// extension recorded for the authorization.
const (
	issuerA      = "https://a.example"
	issuerB      = "https://b.example"
	grantContext = `{"auth_time":1779278400,"amr":["pwd"]}`
)

// countingStore counts the token writes that reach the memory store.
type countingStore struct {
	*memory.Store

	writes atomic.Int32
}

func (s *countingStore) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	s.writes.Add(1)

	return s.Store.SaveTokenPair(ctx, pair) //nolint:wrapcheck // test double
}

func (s *countingStore) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.TokenPair) error {
	s.writes.Add(1)

	return s.Store.RotateRefreshToken(ctx, oldHash, next) //nolint:wrapcheck // test double
}

// grantConfig is the configuration of the issuer-binding grants over store.
func grantConfig(store oauth2.Storage) grant.Config {
	return grant.Config{
		Storage:       store,
		AccessTokens:  newAccessGen(),
		RefreshTokens: newRefreshGen(),
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
	}
}

// boundCode saves the S256-bound code raw, issued to the test client under
// issuer with grantContext, and returns the /token request redeeming it at
// reqIssuer.
func boundCode(t *testing.T, store oauth2.Storage, raw, issuer, reqIssuer string) grant.Request {
	t.Helper()

	now := time.Now()

	require.NoError(t, store.SaveAuthorizationCode(t.Context(), &oauth2.AuthorizationCode{
		Code: raw, CodeHash: oauth2.HashToken(nil, raw),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, Scope: "read:mail",
		CodeChallenge: codeChallenge, CodeChallengeMethod: string(pkce.MethodS256),
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		Issuer: issuer, ExtensionData: grantContext,
	}))

	return grant.Request{
		Client:   newClient(),
		Form:     url.Values{"code": {raw}, "redirect_uri": {redirectURI}, "code_verifier": {codeVerifier}},
		Issuer:   reqIssuer,
		Audience: "api",
		Now:      now,
		Profile:  oauth2.Profile20BCP,
	}
}

// requireTokenContext asserts that the store holds both tokens of pair
// with the given issuer and extension data.
func requireTokenContext(t *testing.T, store oauth2.Storage, pair oauth2.TokenPair, issuer, data string) {
	t.Helper()

	at, err := store.LookupAccessToken(t.Context(), pair.Access.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, issuer, at.Issuer, "access token issuer")
	assert.Equal(t, data, at.ExtensionData, "access token extension data")

	if pair.Refresh == nil {
		return
	}

	rt, err := store.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, issuer, rt.Issuer, "refresh token issuer")
	assert.Equal(t, data, rt.ExtensionData, "refresh token extension data")
}

// TestAuthorizationCodeIsBoundToItsIssuer redeems codes at the issuer they
// were issued under, at another one, and without an issuer on one side or
// both. Only matching issuers issue — the tokens then carry the code's
// issuer and grant context — and a refused exchange writes nothing.
func TestAuthorizationCodeIsBoundToItsIssuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		issuer, reqIssuer string
		ok                bool
	}{
		{"same issuer", issuerA, issuerA, true},
		{"another issuer", issuerA, issuerB, false},
		// A code saved before codes recorded their issuer: fail closed.
		{"code without issuer", "", issuerA, false},
		{"code with an issuer, request without", issuerA, "", false},
		{"no issuer on either side", "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &countingStore{Store: memory.New()}
			g := grant.NewAuthorizationCode(grantConfig(store))
			req := boundCode(t, store, "bound-code", tc.issuer, tc.reqIssuer)

			resp, err := g.Handle(t.Context(), req)
			if !tc.ok {
				require.Nil(t, resp)
				assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

				var oe *oauth2.Error

				require.ErrorAs(t, err, &oe)
				assert.Equal(t, "authorization code issued by another issuer", oe.Description)
				assert.Zero(t, store.writes.Load(), "nothing is persisted")

				return
			}

			require.NoError(t, err)
			requireTokenContext(t, store, resp.Pair, tc.issuer, grantContext)
		})
	}
}

// TestCodeReplayAtAnotherIssuerRevokesNothing replays a redeemed code with
// its full proof at another issuer: refused, and since the replay could not
// have redeemed the code there, the tokens it issued stay usable — while
// the same replay at the code's issuer revokes them (RFC 6749 §4.1.2).
func TestCodeReplayAtAnotherIssuerRevokesNothing(t *testing.T) {
	t.Parallel()

	store := memory.New()
	g := grant.NewAuthorizationCode(grantConfig(store))
	req := boundCode(t, store, "replayed-code", issuerA, issuerA)

	resp, err := g.Handle(t.Context(), req)
	require.NoError(t, err)

	elsewhere := req
	elsewhere.Issuer = issuerB

	_, err = g.Handle(t.Context(), elsewhere)
	require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)
	requireTokenContext(t, store, resp.Pair, issuerA, grantContext)

	_, err = g.Handle(t.Context(), req)
	require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)

	_, err = store.LookupAccessToken(t.Context(), resp.Pair.Access.TokenHash)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err), "the proven replay revoked the code's tokens")
}

// issueRefresh redeems a code issued under issuer and returns the pair.
func issueRefresh(t *testing.T, store oauth2.Storage, issuer string) oauth2.TokenPair {
	t.Helper()

	g := grant.NewAuthorizationCode(grantConfig(store))

	resp, err := g.Handle(t.Context(), boundCode(t, store, "refresh-code", issuer, issuer))
	require.NoError(t, err)
	require.NotNil(t, resp.Pair.Refresh)

	return resp.Pair
}

// refreshRequest is the /token request refreshing rt at issuer.
func refreshRequest(rt, issuer string) grant.Request {
	return grant.Request{
		Client:   newClient(),
		Form:     url.Values{"refresh_token": {rt}},
		Issuer:   issuer,
		Audience: "api",
		Now:      time.Now(),
		Profile:  oauth2.Profile20BCP,
	}
}

// TestRefreshTokenIsBoundToItsIssuer refreshes at another issuer — refused
// before anything is minted, the presented token left usable — then at its
// own: the rotated pair keeps the issuer and the grant context.
func TestRefreshTokenIsBoundToItsIssuer(t *testing.T) {
	t.Parallel()

	store := &countingStore{Store: memory.New()}
	pair := issueRefresh(t, store, issuerA)
	g := grant.NewRefreshToken(grantConfig(store))
	writes := store.writes.Load()

	_, err := g.Handle(t.Context(), refreshRequest(pair.Refresh.Token, issuerB))
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	var oe *oauth2.Error

	require.ErrorAs(t, err, &oe)
	assert.Equal(t, "refresh_token issued by another issuer", oe.Description)
	assert.Equal(t, writes, store.writes.Load(), "nothing is persisted")

	rt, err := store.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
	require.NoError(t, err)
	assert.False(t, rt.Consumed, "the refused refresh consumed nothing")

	resp, err := g.Handle(t.Context(), refreshRequest(pair.Refresh.Token, issuerA))
	require.NoError(t, err)
	requireTokenContext(t, store, resp.Pair, issuerA, grantContext)
}

// TestRefreshTokenWithoutIssuerIsRefused presents a refresh token saved
// before tokens recorded their issuer: refused at an issuer, accepted only
// where the resolver yields no issuer either.
func TestRefreshTokenWithoutIssuerIsRefused(t *testing.T) {
	t.Parallel()

	store := memory.New()
	now := time.Now()
	legacy := &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			TokenHash: "at-legacy", ClientID: clientID, Subject: subject, Scope: "read:mail",
			FamilyID: "fam-legacy", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		},
		Refresh: &oauth2.RefreshToken{
			TokenHash: oauth2.HashToken(nil, "rt-legacy"), ClientID: clientID, Subject: subject,
			Scope: "read:mail", FamilyID: "fam-legacy", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		},
	}
	require.NoError(t, store.SaveTokenPair(t.Context(), legacy))

	g := grant.NewRefreshToken(grantConfig(store))

	_, err := g.Handle(t.Context(), refreshRequest("rt-legacy", issuerA))
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	resp, err := g.Handle(t.Context(), refreshRequest("rt-legacy", ""))
	require.NoError(t, err)
	requireTokenContext(t, store, resp.Pair, "", "")
}

// TestRefreshWithoutRotationKeepsGrantContext covers the legacy Profile20
// refresh without rotation: the access token alone carries the context.
func TestRefreshWithoutRotationKeepsGrantContext(t *testing.T) {
	t.Parallel()

	store := memory.New()
	pair := issueRefresh(t, store, issuerA)
	g := grant.NewRefreshToken(grantConfig(store))

	req := refreshRequest(pair.Refresh.Token, issuerA)
	req.Profile = oauth2.Profile20

	resp, err := g.Handle(t.Context(), req)
	require.NoError(t, err)
	require.Nil(t, resp.Pair.Refresh)
	requireTokenContext(t, store, resp.Pair, issuerA, grantContext)
}

// staticVerifier authenticates every resource owner as subject.
type staticVerifier struct{}

func (staticVerifier) VerifyResourceOwner(context.Context, string, string) (string, error) {
	return subject, nil
}

// TestGrantsWithoutAuthorizationRecordTheIssuer: client_credentials and
// the legacy password grant bind their tokens to the issuer too, and carry
// no grant context.
func TestGrantsWithoutAuthorizationRecordTheIssuer(t *testing.T) {
	t.Parallel()

	store := memory.New()
	req := grant.Request{
		Client: newClient(), Issuer: issuerA, Audience: "api", Now: time.Now(), Profile: oauth2.Profile20,
		Form: url.Values{"scope": {"read:mail"}, "username": {"alice"}, "password": {"pw"}},
	}

	cc, err := grant.NewClientCredentials(grantConfig(store)).Handle(t.Context(), req)
	require.NoError(t, err)
	requireTokenContext(t, store, cc.Pair, issuerA, "")

	pw, err := grant.NewLegacyPassword(grantConfig(store), staticVerifier{}).Handle(t.Context(), req)
	require.NoError(t, err)
	requireTokenContext(t, store, pw.Pair, issuerA, "")
}
