// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwsHeader decodes the protected header of a compact JWS.
func jwsHeader(t *testing.T, jws string) map[string]any {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(jws, ".", 2)[0])
	require.NoError(t, err)

	var h map[string]any
	require.NoError(t, json.Unmarshal(raw, &h))

	return h
}

// jwsClaims decodes the payload of a compact JWS without verifying it.
func jwsClaims(t *testing.T, jws string) map[string]any {
	t.Helper()

	parts := strings.Split(jws, ".")
	require.Len(t, parts, 3)

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var c map[string]any
	require.NoError(t, json.Unmarshal(raw, &c))

	return c
}

// signWithHeader signs claims with priv through go-jose directly, with the
// given typ header ("" leaves it out), to forge the tokens our own signer
// never produces.
func signWithHeader(t *testing.T, priv jwtsec.PrivateKey, typ string, claims any) string {
	t.Helper()

	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}

	s, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(priv.Algorithm),
		Key:       jose.JSONWebKey{Key: priv.Key, KeyID: priv.KeyID, Algorithm: string(priv.Algorithm)},
	}, opts)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	obj, err := s.Sign(payload)
	require.NoError(t, err)

	out, err := obj.CompactSerialize()
	require.NoError(t, err)

	return out
}

func validClaims() jwtsec.StandardClaims {
	now := time.Now()

	return jwtsec.StandardClaims{
		Issuer:    "https://auth.example",
		Subject:   "alice",
		IssuedAt:  jwtsec.NewNumericDate(now),
		ExpiresAt: jwtsec.NewNumericDate(now.Add(time.Hour)),
	}
}

func TestSignerTypesTokensJWTByDefault(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)

	jws, err := mustSigner(t, priv).Sign(context.Background(), validClaims())
	require.NoError(t, err)
	assert.Equal(t, jwtsec.TypeJWT, jwsHeader(t, jws)["typ"])
}

func TestSignerEmitsTheConfiguredType(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)

	jws, err := mustSigner(t, priv, jwtsec.WithType(jwtsec.TypeAccessToken)).Sign(context.Background(), validClaims())
	require.NoError(t, err)
	assert.Equal(t, "at+jwt", jwsHeader(t, jws)["typ"])
}

func TestWithTypeRefusesAnEmptyType(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { jwtsec.WithType("") })
}

// TestVerifierRequiresTheConfiguredType pins RFC 9068 §4 ("MUST verify that
// the typ header value is at+jwt or application/at+jwt") with the RFC 7515
// §4.1.9 comparison: media types are case-insensitive, and a value without
// "/" reads as if "application/" were prepended.
func TestVerifierRequiresTheConfiguredType(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	verifier := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}), jwtsec.WithType(jwtsec.TypeAccessToken))

	cases := []struct {
		typ string
		ok  bool
	}{
		{"at+jwt", true},
		{"application/at+jwt", true},
		{"AT+JWT", true},
		{"Application/At+Jwt", true},
		{"JWT", false},
		{"application/jwt", false},
		{"at+jwt; charset=utf-8", false},
		{"text/at+jwt", false},
		{"", false},
	}

	for _, tc := range cases {
		t.Run("typ="+tc.typ, func(t *testing.T) {
			t.Parallel()

			jws := signWithHeader(t, priv, tc.typ, validClaims())

			_, err := verifier.Verify(context.Background(), jws, nil)
			if tc.ok {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, jwtsec.ErrInvalidType)
		})
	}
}

// TestVerifierRefusesAMissingTypeWhateverTheRequiredOne: an absent typ never
// matches, even a required type reduced to the bare "application/" prefix.
func TestVerifierRefusesAMissingTypeWhateverTheRequiredOne(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	verifier := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}), jwtsec.WithType("application/"))

	_, err := verifier.Verify(context.Background(), signWithHeader(t, priv, "", validClaims()), nil)
	require.ErrorIs(t, err, jwtsec.ErrInvalidType)
}

// TestVerifierWithoutTypeAcceptsAnyType keeps the verifier backward
// compatible: the typ check is opt-in.
func TestVerifierWithoutTypeAcceptsAnyType(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	verifier := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}))

	for _, typ := range []string{"", "JWT", "at+jwt"} {
		_, err := verifier.Verify(context.Background(), signWithHeader(t, priv, typ, validClaims()), nil)
		require.NoError(t, err, typ)
	}
}

// TestOAuth2AccessTokenSignerFollowsRFC9068 pins RFC 9068 §2.1 (typ at+jwt)
// and §2.2 (jti REQUIRED, unique): an access token is told apart from an
// OpenID Connect ID Token, and a verifier requiring at+jwt refuses the
// latter.
func TestOAuth2AccessTokenSignerFollowsRFC9068(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	adapter := mustAccessTokenSigner(t, priv)

	claims := token.AccessTokenClaims{
		Issuer: "https://auth.example", Subject: "alice", Audience: "api", ClientID: "my-client",
		Scope: "read", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}

	first, err := adapter.SignAccessToken(context.Background(), claims)
	require.NoError(t, err)

	second, err := adapter.SignAccessToken(context.Background(), claims)
	require.NoError(t, err)

	assert.Equal(t, "at+jwt", jwsHeader(t, first)["typ"])

	jti1, _ := jwsClaims(t, first)["jti"].(string)
	jti2, _ := jwsClaims(t, second)["jti"].(string)
	require.NotEmpty(t, jti1)
	assert.NotEqual(t, jti1, jti2, "every access token has its own jti")

	raw, err := base64.RawURLEncoding.DecodeString(jti1)
	require.NoError(t, err, "jti is base64url")
	assert.GreaterOrEqual(t, len(raw), 16, "jti carries at least 128 random bits")

	verifier := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}),
		jwtsec.WithType(jwtsec.TypeAccessToken), jwtsec.WithIssuer("https://auth.example"), jwtsec.WithAudience("api"))

	std, err := verifier.Verify(context.Background(), first, nil)
	require.NoError(t, err)
	assert.Equal(t, jti1, std.JWTID)

	// An ID Token — typ JWT, same key, aud = the resource — is refused.
	idToken, err := mustSigner(t, priv).Sign(context.Background(), jwtsec.StandardClaims{
		Issuer: "https://auth.example", Subject: "alice", Audience: jwtsec.Audience{"api"},
		IssuedAt: jwtsec.NewNumericDate(time.Now()), ExpiresAt: jwtsec.NewNumericDate(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), idToken, nil)
	require.ErrorIs(t, err, jwtsec.ErrInvalidType)
}
