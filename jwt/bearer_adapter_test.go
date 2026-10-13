// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rsIssuer   = "https://auth.example"
	rsAudience = "https://api.example"
)

// rsVerifier returns an RFC 9068 §4 resource-server verifier: issuer,
// audience and the at+jwt type pinned.
func rsVerifier(pub jwtsec.PublicKey, opts ...jwtsec.Option) jwtsec.Verifier {
	return jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}), append([]jwtsec.Option{
		jwtsec.WithIssuer(rsIssuer), jwtsec.WithAudience(rsAudience), jwtsec.WithType(jwtsec.TypeAccessToken),
	}, opts...)...)
}

// accessToken returns an RFC 9068 access token for the resource server.
func accessToken(t *testing.T, priv jwtsec.PrivateKey, mutate ...func(*token.AccessTokenClaims)) string {
	t.Helper()

	now := time.Now()
	c := token.AccessTokenClaims{
		Issuer: rsIssuer, Subject: "alice", Audience: rsAudience, ClientID: "web",
		Scope: "read:mail write:mail admin", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}

	for _, m := range mutate {
		m(&c)
	}

	tok, err := mustAccessTokenSigner(t, priv).SignAccessToken(context.Background(), c)
	require.NoError(t, err)

	return tok
}

func TestBearerVerifierDefaultResolverExposesScopesAsAuthorities(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)

	got, err := jwtsec.BearerVerifier(rsVerifier(pub), nil).Verify(context.Background(), accessToken(t, priv))
	require.NoError(t, err)
	assert.True(t, got.IsAuthenticated())
	assert.Equal(t, "alice", got.Principal().Subject())
	assert.ElementsMatch(t, []string{"scope:read:mail", "scope:write:mail", "scope:admin"}, got.Authorities())
}

func TestBearerVerifierCustomResolver(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)

	tv := jwtsec.BearerVerifier(rsVerifier(pub), func(c *jwtsec.StandardClaims) []string {
		return []string{"ROLE_" + c.Subject}
	})

	got, err := tv.Verify(context.Background(), accessToken(t, priv))
	require.NoError(t, err)
	assert.Equal(t, []string{"ROLE_alice"}, got.Authorities())
}

func TestBearerVerifierPropagatesVerifierError(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)
	verifier := jwtsec.NewVerifier(jwtsec.NewStaticJWKS(nil), // no keys
		jwtsec.WithIssuer(rsIssuer), jwtsec.WithAudience(rsAudience), jwtsec.WithType(jwtsec.TypeAccessToken))

	_, err := jwtsec.BearerVerifier(verifier, nil).Verify(context.Background(), accessToken(t, priv))
	assert.ErrorIs(t, err, jwtsec.ErrInvalidSignature)
}

// foreignVerifier is a Verifier the package did not build.
type foreignVerifier struct{}

func (foreignVerifier) Verify(context.Context, string, any) (*jwtsec.StandardClaims, error) {
	return &jwtsec.StandardClaims{Subject: "anyone"}, nil
}

// TestBearerVerifierRefusesAnUnsafeVerifier pins decision 9 and RFC 9068
// §4 — the resource server MUST check typ (at+jwt), iss and aud, and that
// the current time is before exp (audit JWT-05: the defaults and the
// bundled examples checked none of typ, iss, aud): BearerVerifier refuses
// at construction a verifier that would not.
func TestBearerVerifierRefusesAnUnsafeVerifier(t *testing.T) {
	t.Parallel()

	_, pub := genECDSA(t)
	keys := jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub})
	iss, aud, typ := jwtsec.WithIssuer(rsIssuer), jwtsec.WithAudience(rsAudience), jwtsec.WithType(jwtsec.TypeAccessToken)

	cases := map[string]struct {
		v    jwtsec.Verifier
		opts []jwtsec.BearerOption
		why  string // in the panic message
	}{
		"not built by NewVerifier": {v: foreignVerifier{}, why: "built by NewVerifier"},
		"nil verifier":             {v: nil, why: "built by NewVerifier"},
		"typed nil verifier":       {v: jwtsec.TypedNilVerifier, why: "built by NewVerifier"},
		"no issuer":                {v: jwtsec.NewVerifier(keys, aud, typ), why: "WithIssuer"},
		"no audience":              {v: jwtsec.NewVerifier(keys, iss, typ), why: "WithAudience"},
		"empty audience list":      {v: jwtsec.NewVerifier(keys, iss, jwtsec.WithAudience(), typ), why: "WithAudience"},
		"no type":                  {v: jwtsec.NewVerifier(keys, iss, aud), why: "WithType"},
		"type JWT without option":  {v: jwtsec.NewVerifier(keys, iss, aud, jwtsec.WithType(jwtsec.TypeJWT)), why: "WithType"},
		"option for another type":  {v: jwtsec.NewVerifier(keys, iss, aud, typ), opts: []jwtsec.BearerOption{jwtsec.WithAccessTokenType(jwtsec.TypeJWT)}, why: "WithType"},
		"optional expiry":          {v: jwtsec.NewVerifier(keys, iss, aud, typ, jwtsec.WithOptionalExpiry()), why: "WithOptionalExpiry"},
		"no check at all":          {v: jwtsec.NewVerifier(keys), why: "WithIssuer"},
	}

	for name, tc := range cases {
		msg := panicMessage(func() { jwtsec.BearerVerifier(tc.v, nil, tc.opts...) })
		assert.Contains(t, msg, "jwtsec.BearerVerifier: ", name)
		assert.Contains(t, msg, tc.why, name)
	}

	assert.Panics(t, func() { jwtsec.WithAccessTokenType("") }, "an empty type")
}

// panicMessage returns the string fn panics with, "" when it does not
// panic or panics with another value (a nil dereference, for instance).
func panicMessage(fn func()) (msg string) {
	defer func() { msg, _ = recover().(string) }()

	fn()

	return ""
}

// TestBearerVerifierAcceptsAnRFC9068Verifier pins the accepted forms: the
// at+jwt type in either spelling of RFC 9068 §4 ("at+jwt" or
// "application/at+jwt").
func TestBearerVerifierAcceptsAnRFC9068Verifier(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)

	for _, typ := range []string{jwtsec.TypeAccessToken, "application/at+jwt", "AT+JWT"} {
		v := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}),
			jwtsec.WithIssuer(rsIssuer), jwtsec.WithAudience(rsAudience, "https://other.example"), jwtsec.WithType(typ))

		var tv any

		require.NotPanics(t, func() { tv = jwtsec.BearerVerifier(v, nil) }, typ)

		got, err := jwtsec.BearerVerifier(v, nil).Verify(context.Background(), accessToken(t, priv))
		require.NoError(t, err, typ)
		assert.Equal(t, "alice", got.Name())
		assert.NotNil(t, tv)
	}
}

// TestBearerVerifierWithAccessTokenType pins decision 9's explicit option:
// an authorization server typing its access tokens "JWT" can be served,
// with a verifier requiring that type and the option naming it.
func TestBearerVerifierWithAccessTokenType(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	v := rsVerifier(pub, jwtsec.WithType(jwtsec.TypeJWT)) // the last WithType wins
	tv := jwtsec.BearerVerifier(v, nil, jwtsec.WithAccessTokenType(jwtsec.TypeJWT))

	now := time.Now()
	jwtTyped, err := mustSigner(t, priv).Sign(context.Background(), jwtsec.StandardClaims{
		Issuer: rsIssuer, Subject: "alice", Audience: jwtsec.Audience{rsAudience},
		IssuedAt: jwtsec.NewNumericDate(now), ExpiresAt: jwtsec.NewNumericDate(now.Add(time.Hour)),
	})
	require.NoError(t, err)

	got, err := tv.Verify(context.Background(), jwtTyped)
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Name())

	_, err = tv.Verify(context.Background(), accessToken(t, priv))
	require.ErrorIs(t, err, jwtsec.ErrInvalidType, "the verifier requires the one type it names")
}

// TestBearerVerifierRefusesTokenConfusion pins RFC 9068 §4 and RFC 8725
// §2.8, §3.11 (the audit's RFC 9068 probe: an ID Token and an access token
// minted for another resource server were accepted with 200).
func TestBearerVerifierRefusesTokenConfusion(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	tv := jwtsec.BearerVerifier(rsVerifier(pub), nil)
	now := time.Now()

	idToken, err := mustSigner(t, priv).Sign(context.Background(), jwtsec.StandardClaims{
		Issuer: rsIssuer, Subject: "victim", Audience: jwtsec.Audience{rsAudience},
		IssuedAt: jwtsec.NewNumericDate(now), ExpiresAt: jwtsec.NewNumericDate(now.Add(time.Hour)),
	})
	require.NoError(t, err)

	untyped := forge(t, jwtsec.ES256, priv.Key, `{"alg":"ES256","kid":"ec-1"}`,
		fmt.Sprintf(`{"iss":%q,"sub":"alice","aud":%q,"exp":%d}`, rsIssuer, rsAudience, in(time.Hour)))

	cases := map[string]struct {
		token string
		want  error
	}{
		"an ID Token (typ JWT) with the right audience": {idToken, jwtsec.ErrInvalidType},
		"an untyped token":                   {untyped, jwtsec.ErrInvalidType},
		"an access token for another API":    {accessToken(t, priv, func(c *token.AccessTokenClaims) { c.Audience = "https://billing.example" }), jwtsec.ErrInvalidAudience},
		"an access token of another issuer":  {accessToken(t, priv, func(c *token.AccessTokenClaims) { c.Issuer = "https://evil.example" }), jwtsec.ErrInvalidIssuer},
		"an expired access token":            {accessToken(t, priv, func(c *token.AccessTokenClaims) { c.IssuedAt, c.ExpiresAt = now.Add(-2*time.Hour), now.Add(-time.Hour) }), jwtsec.ErrTokenExpired},
		"an access token with case variants": {forgeAccess(t, priv, `"sub":"alice","Sub":"admin"`), jwtsec.ErrMalformedToken},
		"an access token without sub":        {forgeAccess(t, priv, `"SUB":"admin"`), jwtsec.ErrInvalidClaims},
		"an access token with an empty sub":  {forgeAccess(t, priv, `"sub":""`), jwtsec.ErrInvalidClaims},
	}

	for name, tc := range cases {
		got, err := tv.Verify(context.Background(), tc.token)
		require.ErrorIs(t, err, tc.want, name)
		require.True(t, errors.Is(err, security.ErrInvalidCredentials) || errors.Is(err, security.ErrTokenExpired),
			"a credential failure: %s", name)
		assert.Nil(t, got, name)
	}
}

// forgeAccess signs an at+jwt token for the resource server with the
// given subject members.
func forgeAccess(t *testing.T, priv jwtsec.PrivateKey, sub string) string {
	t.Helper()

	return forge(t, jwtsec.ES256, priv.Key, `{"alg":"ES256","kid":"ec-1","typ":"at+jwt"}`,
		fmt.Sprintf(`{"iss":%q,%s,"aud":%q,"client_id":"web","jti":"j","iat":%d,"exp":%d}`,
			rsIssuer, sub, rsAudience, in(0), in(time.Hour)))
}

// TestWithAudienceRefusesEmptyValues pins review F6: an empty configured
// audience would match a token whose aud is "" — what an authorization
// server with StaticIssuer(iss, "") emitted (audit JWT-10).
func TestWithAudienceRefusesEmptyValues(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { jwtsec.WithAudience("") })
	assert.Panics(t, func() { jwtsec.WithAudience("api", "") })
	assert.NotPanics(t, func() { jwtsec.WithAudience() }, "no audience: no restriction")
	assert.NotPanics(t, func() { jwtsec.WithAudience("api", "other") })
}
