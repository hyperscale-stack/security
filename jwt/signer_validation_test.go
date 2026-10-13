// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/hyperscale-stack/security"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signingKeys are keys of every accepted form and some refused ones.
type signingKeys struct {
	rsa2048, rsa1024 *rsa.PrivateKey
	p256             *ecdsa.PrivateKey
}

func newSigningKeys(t *testing.T) signingKeys {
	t.Helper()

	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the point of the test: an undersized key
	require.NoError(t, err)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return signingKeys{rsa2048: rsa2048, rsa1024: rsa1024, p256: p256}
}

// TestNewSignerValidatesItsKey pins RFC 7518 §3.2-§3.5 and RFC 8725 §3.5 on
// the signing side (audit JWT-10: an RSA-1024 key signed): NewSigner
// refuses, with ErrInvalidKey, a key unfit for its algorithm.
func TestNewSignerValidatesItsKey(t *testing.T) {
	t.Parallel()

	k := newSigningKeys(t)

	refused := map[string]jwtsec.PrivateKey{
		"RSA-1024":                    {KeyID: "k", Algorithm: jwtsec.RS256, Key: k.rsa1024},
		"P-256 key declared ES384":    {KeyID: "k", Algorithm: jwtsec.ES384, Key: k.p256},
		"public key":                  {KeyID: "k", Algorithm: jwtsec.RS256, Key: &k.rsa2048.PublicKey},
		"HMAC bytes declared RS256":   {KeyID: "k", Algorithm: jwtsec.RS256, Key: []byte(strings.Repeat("s", 64))},
		"HS256 secret of 31 bytes":    {KeyID: "k", Algorithm: jwtsec.HS256, Key: []byte(strings.Repeat("s", 31))},
		"HS512 secret of 48 bytes":    {KeyID: "k", Algorithm: jwtsec.HS512, Key: []byte(strings.Repeat("s", 48))},
		"no algorithm":                {KeyID: "k", Key: k.p256},
		"no key":                      {KeyID: "k", Algorithm: jwtsec.ES256},
		"JWK wrapping RSA-1024":       {KeyID: "k", Algorithm: jwtsec.RS256, Key: jose.JSONWebKey{Key: k.rsa1024}},
		"JWK pointer to RSA-1024":     {KeyID: "k", Algorithm: jwtsec.RS256, Key: &jose.JSONWebKey{Key: k.rsa1024}},
		"JWK pointer, P-256 as ES384": {KeyID: "k", Algorithm: jwtsec.ES384, Key: &jose.JSONWebKey{Key: k.p256}},
		"HS384 secret of 47 bytes":    {KeyID: "k", Algorithm: jwtsec.HS384, Key: []byte(strings.Repeat("s", 47))},
		"opaque without public key":   {KeyID: "k", Algorithm: jwtsec.RS256, Key: noPublicOpaque{cryptosigner.Opaque(k.rsa2048)}},
		"nil JWK pointer":             {KeyID: "k", Algorithm: jwtsec.RS256, Key: (*jose.JSONWebKey)(nil)},
		"opaque RSA-1024":             {KeyID: "k", Algorithm: jwtsec.RS256, Key: cryptosigner.Opaque(k.rsa1024)},
		"opaque P-256 declared ES384": {KeyID: "k", Algorithm: jwtsec.ES384, Key: cryptosigner.Opaque(k.p256)},
		"opaque not offering EdDSA":   {KeyID: "k", Algorithm: jwtsec.EdDSA, Key: cryptosigner.Opaque(k.rsa2048)},
		"opaque RSA not offering PS256": {KeyID: "k", Algorithm: jwtsec.PS256,
			Key: limitedOpaque{OpaqueSigner: cryptosigner.Opaque(k.rsa2048), algs: []jose.SignatureAlgorithm{jose.RS256}}},
	}

	for name, key := range refused {
		t.Run("refused "+name, func(t *testing.T) {
			t.Parallel()

			s, err := jwtsec.NewSigner(key)
			require.ErrorIs(t, err, jwtsec.ErrInvalidKey)
			assert.Nil(t, s)

			a, err := jwtsec.NewOAuth2AccessTokenSigner(key)
			require.ErrorIs(t, err, jwtsec.ErrInvalidKey)
			assert.Nil(t, a)
		})
	}

	accepted := map[string]struct {
		key jwtsec.PrivateKey
		pub jwtsec.PublicKey
	}{
		"RSA-2048":           {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: k.rsa2048}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: &k.rsa2048.PublicKey}},
		"P-256":              {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: k.p256}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: &k.p256.PublicKey}},
		"JWK value":          {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.PS256, Key: jose.JSONWebKey{Key: k.rsa2048}}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.PS256, Key: &k.rsa2048.PublicKey}},
		"JWK pointer":        {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: &jose.JSONWebKey{Key: k.rsa2048}}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: &k.rsa2048.PublicKey}},
		"opaque (KMS, HSM)":  {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: cryptosigner.Opaque(k.rsa2048)}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.RS256, Key: &k.rsa2048.PublicKey}},
		"opaque ECDSA":       {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: cryptosigner.Opaque(k.p256)}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: &k.p256.PublicKey}},
		"HS256, 32 bytes":    {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.HS256, Key: []byte(strings.Repeat("s", 32))}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.HS256, Key: []byte(strings.Repeat("s", 32))}},
		"HS512, 64 bytes":    {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.HS512, Key: []byte(strings.Repeat("s", 64))}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.HS512, Key: []byte(strings.Repeat("s", 64))}},
		"HS384, 48 bytes":    {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.HS384, Key: []byte(strings.Repeat("s", 48))}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.HS384, Key: []byte(strings.Repeat("s", 48))}},
		"JWK wrapping a JWK": {jwtsec.PrivateKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: jose.JSONWebKey{Key: jose.JSONWebKey{Key: k.p256}}}, jwtsec.PublicKey{KeyID: "k", Algorithm: jwtsec.ES256, Key: &k.p256.PublicKey}},
	}

	for name, tc := range accepted {
		t.Run("accepted "+name, func(t *testing.T) {
			t.Parallel()

			s, err := jwtsec.NewSigner(tc.key)
			require.NoError(t, err)

			tok, err := s.Sign(context.Background(), jwtsec.StandardClaims{Subject: "alice", ExpiresAt: jwtsec.NewNumericDate(time.Now().Add(time.Hour))})
			require.NoError(t, err)

			_, err = jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{tc.pub}),
				jwtsec.WithAllowedAlgorithms(tc.pub.Algorithm)).Verify(context.Background(), tok, nil)
			require.NoError(t, err, "the token verifies with the public half")
		})
	}
}

// noPublicOpaque is an opaque signer that exposes no public key.
type noPublicOpaque struct{ jose.OpaqueSigner }

func (noPublicOpaque) Public() *jose.JSONWebKey { return nil }

// limitedOpaque is an opaque (KMS-style) signer offering only algs.
type limitedOpaque struct {
	jose.OpaqueSigner

	algs []jose.SignatureAlgorithm
}

func (l limitedOpaque) Algs() []jose.SignatureAlgorithm { return l.algs }

// accessClaims returns complete RFC 9068 claims.
func accessClaims() token.AccessTokenClaims {
	now := time.Now().Truncate(time.Second)

	return token.AccessTokenClaims{
		Issuer: "https://auth.example", Subject: "alice", Audience: "api", ClientID: "my-client",
		Scope: "read", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

// TestOAuth2AccessTokenSignerRefusesIncompleteClaims pins RFC 9068 §2.2
// (iss, exp, aud, sub, client_id, iat REQUIRED; jti is generated): claims
// missing one are not signed (audit JWT-10: an empty aud from
// StaticIssuer(iss, "") was signed), and the refusal is a server-side
// error, never a credential failure (review F16).
func TestOAuth2AccessTokenSignerRefusesIncompleteClaims(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)
	s := mustAccessTokenSigner(t, priv)

	cases := map[string]struct {
		mutate func(*token.AccessTokenClaims)
		names  string // the claim the error names
	}{
		"no iss":          {func(c *token.AccessTokenClaims) { c.Issuer = "" }, "requires iss"},
		"no sub":          {func(c *token.AccessTokenClaims) { c.Subject = "" }, "requires sub"},
		"no aud":          {func(c *token.AccessTokenClaims) { c.Audience = "" }, "requires aud"},
		"no client_id":    {func(c *token.AccessTokenClaims) { c.ClientID = "" }, "requires client_id"},
		"zero iat":        {func(c *token.AccessTokenClaims) { c.IssuedAt = time.Time{} }, "requires iat"},
		"zero exp":        {func(c *token.AccessTokenClaims) { c.ExpiresAt = time.Time{} }, "requires exp"},
		"exp equals iat":  {func(c *token.AccessTokenClaims) { c.ExpiresAt = c.IssuedAt }, "exp is not after iat"},
		"exp before iat":  {func(c *token.AccessTokenClaims) { c.ExpiresAt = c.IssuedAt.Add(-time.Second) }, "exp is not after iat"},
		"iat before 1970": {func(c *token.AccessTokenClaims) { c.IssuedAt = time.Unix(-5, 0) }, "NumericDate"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := accessClaims()
			tc.mutate(&c)

			tok, err := s.SignAccessToken(context.Background(), c)
			require.ErrorIs(t, err, jwtsec.ErrUnsignableClaims)
			assert.Contains(t, err.Error(), tc.names, "the refusal names its cause")
			assert.NotErrorIs(t, err, security.ErrInvalidCredentials, "a server-side error")
			assert.Empty(t, tok, "nothing is signed")
		})
	}

	tok, err := s.SignAccessToken(context.Background(), accessClaims())
	require.NoError(t, err, "complete claims are signed")
	assert.NotEmpty(t, tok)
}
