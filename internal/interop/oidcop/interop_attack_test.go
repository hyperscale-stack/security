// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcop_test

import (
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"
)

// requireRetrieveError requires err to be x/oauth2's view of a token
// endpoint error response with code (RFC 6749 §5.2).
func requireRetrieveError(t *testing.T, err error, code string) {
	t.Helper()

	var re *xoauth2.RetrieveError
	require.ErrorAs(t, err, &re)
	assert.Equal(t, code, re.ErrorCode)
}

// TestInteropJWTAccessTokenIsNotAnIDToken: the provider issues RFC 9068
// access tokens signed by a key its JWK Set publishes, so their signature
// verifies like an ID Token's. go-oidc's ID Token verifier still refuses
// one: its audience is the resource ("api"), not the client. go-oidc does
// not look at typ (at+jwt, RFC 9068 §2.1, RFC 8725 §3.11): a verifier
// skipping the client-ID check accepts the access token — the audience
// separation is what protects relying parties that ignore typ.
func TestInteropJWTAccessTokenIsNotAnIDToken(t *testing.T) {
	t.Parallel()

	o := newOP(t, withJWTAccessTokens())
	r := newRP(t, o, o.issuer, basicClient)

	tok, _, _ := r.flow(t)
	assert.Equal(t, "at+jwt", jwsHeader(t, tok.AccessToken)["typ"])

	_, err := r.verifier.Verify(r.ctx, tok.AccessToken)
	require.ErrorContains(t, err, "expected audience")

	lax := r.provider.Verifier(&oidc.Config{SkipClientIDCheck: true})

	accepted, err := lax.Verify(r.ctx, tok.AccessToken)
	require.NoError(t, err, "a verifier ignoring typ and aud accepts it")
	assert.Equal(t, []string{"api"}, accepted.Audience)
}

// TestInteropCodeReplay pins RFC 6749 §4.1.2 through x/oauth2: a code
// exchanged twice is refused the second time (invalid_grant), and the
// tokens the first exchange issued are revoked — go-oidc's UserInfo call
// with them fails from then on.
func TestInteropCodeReplay(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient)

	verifier := xoauth2.GenerateVerifier()
	params := r.authorize(t, xoauth2.S256ChallengeOption(verifier), oidc.Nonce(randomNonce()))

	tok, err := r.config.Exchange(r.ctx, params.Get("code"), xoauth2.VerifierOption(verifier))
	require.NoError(t, err)

	_, err = r.provider.UserInfo(r.ctx, xoauth2.StaticTokenSource(tok))
	require.NoError(t, err)

	_, err = r.config.Exchange(r.ctx, params.Get("code"), xoauth2.VerifierOption(verifier))
	requireRetrieveError(t, err, "invalid_grant")

	_, err = r.provider.UserInfo(r.ctx, xoauth2.StaticTokenSource(tok))
	require.ErrorContains(t, err, "401", "the access token of the first exchange is revoked")
}

// TestInteropRefreshReuse pins RFC 9700 §4.14.2 through x/oauth2's token
// source: a refresh token rotates at each use; presenting a rotated one
// again is refused (invalid_grant) and revokes its whole family — the
// newest refresh token and access token stop working too.
func TestInteropRefreshReuse(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	r := newRP(t, o, o.issuer, basicClient, oidc.ScopeOpenID, oidc.ScopeOfflineAccess)

	tok, _, _ := r.flow(t, xoauth2.SetAuthURLParam("prompt", "consent"))
	require.NotEmpty(t, tok.RefreshToken)

	// expired makes x/oauth2 refresh at the next Token call.
	expired := func(tok *xoauth2.Token) *xoauth2.Token {
		c := *tok
		c.Expiry = time.Now().Add(-time.Minute)

		return &c
	}

	o.advance(time.Minute)

	rotated, err := r.config.TokenSource(r.ctx, expired(tok)).Token()
	require.NoError(t, err)
	require.NotEqual(t, tok.RefreshToken, rotated.RefreshToken, "rotated")

	_, err = r.provider.UserInfo(r.ctx, xoauth2.StaticTokenSource(rotated))
	require.NoError(t, err)

	_, err = r.config.TokenSource(r.ctx, expired(tok)).Token()
	requireRetrieveError(t, err, "invalid_grant")

	_, err = r.config.TokenSource(r.ctx, expired(rotated)).Token()
	requireRetrieveError(t, err, "invalid_grant")

	_, err = r.provider.UserInfo(r.ctx, xoauth2.StaticTokenSource(rotated))
	require.ErrorContains(t, err, "401", "the family is revoked")
}
