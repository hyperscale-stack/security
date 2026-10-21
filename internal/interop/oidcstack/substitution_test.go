// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tamperTokenResponse makes the token endpoint of issuer answer with the
// members of its JSON response edited — an attacker between the relying
// party and the provider, or a provider gone wrong.
func (o *op) tamperTokenResponse(issuer string, edit func(t map[string]any)) {
	o.faults.set(o.paths(issuer).Token, rule{rewrite: func(body []byte) []byte {
		var resp map[string]any
		if err := json.Unmarshal(body, &resp); err != nil {
			return body
		}

		edit(resp)

		out, err := json.Marshal(resp)
		if err != nil {
			panic(err)
		}

		return out
	}})
}

// rootKey is the root issuer's RS256 key, kid root-rs256.
func rootKey() any { return rsaKeys()[0] }

// attackerKey is a key the provider never published.
func attackerKey() any { return rsaKeys()[10] }

// TestResignedIDTokensAreRefused feeds the client ID Tokens genuinely
// signed — with the provider's own RS256 key unless stated — but wrong in
// one respect each (OpenID Connect Core §3.1.3.7, RFC 8725): every one is
// refused with its exact reason, and no token of the login is exposed.
func TestResignedIDTokensAreRefused(t *testing.T) {
	t.Parallel()

	maxAge := 5 * time.Minute

	var keyURLHits atomic.Int64

	keyURL := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { keyURLHits.Add(1) }))
	t.Cleanup(keyURL.Close)
	// Checked once every parallel case has run: a parent assertion after
	// the loop would run before them.
	t.Cleanup(func() { assert.Zero(t, keyURLHits.Load(), "jku and x5u are never fetched") })

	cases := []struct {
		name   string
		opts   oidcclient.AuthOptions
		forge  func(t *testing.T, o *op, idToken string) string
		want   error
		wrapID bool                     // also matches ErrInvalidIDToken
		config func(*oidcclient.Config) // the relying party's configuration, when it matters
	}{
		{"missing auth_time with max_age", oidcclient.AuthOptions{MaxAge: &maxAge}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { delete(c, "auth_time") })
		}, oidcclient.ErrIDTokenMissingClaim, true, nil},
		{"stale auth_time with max_age", oidcclient.AuthOptions{MaxAge: &maxAge}, func(t *testing.T, o *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { c["auth_time"] = o.clock.now().Add(-2 * time.Hour).Unix() })
		}, oidcclient.ErrIDTokenAuthTime, true, nil},
		{"nonce of another login", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { c["nonce"] = "the-nonce-of-another-login" })
		}, oidcclient.ErrIDTokenNonce, true, nil},
		{"no nonce", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { delete(c, "nonce") })
		}, oidcclient.ErrIDTokenNonce, true, nil},
		{"missing sub", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { delete(c, "sub") })
		}, oidcclient.ErrIDTokenMissingClaim, true, nil},
		{"untrusted extra audience", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { c["aud"] = []string{basicID, "https://evil.example"} })
		}, oidcclient.ErrIDTokenAudience, true, nil},
		{"no aud", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { delete(c, "aud") })
		}, oidcclient.ErrIDTokenAudience, true, nil},
		{"a trusted audience, the client not among them", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { c["aud"] = []string{"https://api.example"} })
		}, oidcclient.ErrIDTokenAudience, true, func(cfg *oidcclient.Config) { cfg.TrustedAudiences = []string{"https://api.example"} }},
		{"azp of another client", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { c["azp"] = otherID })
		}, oidcclient.ErrIDTokenAuthorizedParty, true, nil},
		{"iat beyond the clock skew", oidcclient.AuthOptions{}, func(t *testing.T, o *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { c["iat"] = o.clock.now().Add(10 * time.Minute).Unix() })
		}, oidcclient.ErrIDTokenIssuedAt, true, nil},
		{"expired", oidcclient.AuthOptions{}, func(t *testing.T, o *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { c["exp"] = o.clock.now().Add(-2 * time.Minute).Unix() })
		}, oidcclient.ErrIDTokenExpired, true, nil},
		{"another issuer", oidcclient.AuthOptions{}, func(t *testing.T, o *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), nil, func(c map[string]any) { c["iss"] = o.base + tenantA })
		}, oidcclient.ErrIDTokenIssuer, true, nil},
		{"typed at+jwt", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rootKey(), func(h map[string]any) { h["typ"] = "at+jwt" }, nil)
		}, oidcclient.ErrIDTokenType, true, nil},
		{"PS256 with the RS256 key (one algorithm per key)", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "PS256", rootKey(), nil, nil)
		}, oidcclient.ErrUnknownSigningKey, true, nil},
		{"kid of another issuer's key", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", rsaKeys()[6], func(h map[string]any) { h["kid"] = "tenant-a" }, nil)
		}, oidcclient.ErrUnknownSigningKey, true, nil},
		{"jku, x5u and jwk naming the attacker's key", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", attackerKey(), func(h map[string]any) {
				h["kid"], h["jku"], h["x5u"] = "attacker", keyURL.URL+"/jwks", keyURL.URL+"/x5u"
				h["jwk"] = publicJWK(rsaKeys()[10], "attacker")
			}, nil)
		}, oidcclient.ErrIDTokenMalformed, true, nil},
		{"the provider's kid, the attacker's embedded key", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "RS256", attackerKey(), func(h map[string]any) {
				h["jku"], h["jwk"] = keyURL.URL+"/jwks", publicJWK(rsaKeys()[10], "root-rs256")
			}, nil)
		}, oidcclient.ErrIDTokenMalformed, true, nil},
		{"alg none", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			return resign(t, tok, "none", nil, nil, nil)
		}, oidcclient.ErrIDTokenAlgorithm, true, nil},
		{"HS256 keyed by the provider's public key", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			der, err := x509.MarshalPKIXPublicKey(&rsaKeys()[0].PublicKey)
			require.NoError(t, err)

			return resign(t, tok, "HS256", der, nil, nil)
		}, oidcclient.ErrIDTokenAlgorithm, true, nil},
		{"payload altered, signature kept", oidcclient.AuthOptions{}, func(t *testing.T, _ *op, tok string) string {
			header, claims := jwsParts(t, tok)
			_ = header
			claims["sub"] = bob

			payload, err := json.Marshal(claims)
			require.NoError(t, err)

			parts := strings.Split(tok, ".")

			return parts[0] + "." + b64.EncodeToString(payload) + "." + parts[2]
		}, oidcclient.ErrIDTokenSignature, true, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			o := newOP(t)
			o.tamperTokenResponse(o.base, func(resp map[string]any) {
				if tok, ok := resp["id_token"].(string); ok {
					resp["id_token"] = tc.forge(t, o, tok)
				}
			})

			var mutators []func(*oidcclient.Config)
			if tc.config != nil {
				mutators = append(mutators, tc.config)
			}

			id, err := o.login(t, o.rp(t, o.basic(), mutators...), tc.opts)
			require.ErrorIs(t, err, tc.want)

			if tc.wrapID {
				require.ErrorIs(t, err, oidcclient.ErrInvalidIDToken)
			}

			assert.Nil(t, id, "no token of a failed login is exposed")
		})
	}
}

// TestTokenResponseSubstitution replaces members of a genuine token
// response with other genuine tokens of the same provider: an access token
// of another login (at_hash, Core §3.1.3.8), the ID Token of another
// client's login (aud), the ID Token of an earlier login of the same
// client (nonce), the RFC 9068 at+jwt access token (typ, RFC 8725 §3.11),
// and — when two issuers share a key ring — another issuer's ID Token
// (iss): each refused with its exact reason.
func TestTokenResponseSubstitution(t *testing.T) {
	t.Parallel()

	t.Run("access token of another login", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		c := o.rp(t, o.basic())
		earlier, err := o.login(t, c, oidcclient.AuthOptions{})
		require.NoError(t, err)

		o.tamperTokenResponse(o.base, func(resp map[string]any) { resp["access_token"] = earlier.Tokens.AccessToken.Reveal() })

		_, err = o.login(t, c, oidcclient.AuthOptions{})
		require.ErrorIs(t, err, oidcclient.ErrAccessTokenHash)
	})

	t.Run("ID Token of another client's login", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		other, err := o.login(t, o.rp(t, conn("other", o.base, otherID, secret, oidcclient.AuthMethodClientSecretBasic)), oidcclient.AuthOptions{})
		require.NoError(t, err)

		o.tamperTokenResponse(o.base, func(resp map[string]any) { resp["id_token"] = other.Tokens.IDToken.Reveal() })

		_, err = o.login(t, o.rp(t, o.basic()), oidcclient.AuthOptions{})
		require.ErrorIs(t, err, oidcclient.ErrIDTokenAudience)
	})

	t.Run("ID Token of an earlier login of the same client", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		c := o.rp(t, o.basic())
		earlier, err := o.login(t, c, oidcclient.AuthOptions{})
		require.NoError(t, err)

		o.tamperTokenResponse(o.base, func(resp map[string]any) { resp["id_token"] = earlier.Tokens.IDToken.Reveal() })

		_, err = o.login(t, c, oidcclient.AuthOptions{})
		require.ErrorIs(t, err, oidcclient.ErrIDTokenNonce)
	})

	t.Run("the at+jwt access token as ID Token", func(t *testing.T) {
		t.Parallel()

		o := newOP(t, func(cfg *opConfig) { cfg.jwtAccessTokens = true })
		o.tamperTokenResponse(o.base, func(resp map[string]any) { resp["id_token"] = resp["access_token"] })

		_, err := o.login(t, o.rp(t, o.basic()), oidcclient.AuthOptions{})
		require.ErrorIs(t, err, oidcclient.ErrIDTokenType)
	})

	t.Run("another issuer's ID Token under a shared key ring", func(t *testing.T) {
		t.Parallel()

		o := newOP(t, func(cfg *opConfig) { cfg.sharedRing = true })
		b, err := o.login(t, o.rp(t, conn("shared-b", o.base+tenantB, sharedID, secret, oidcclient.AuthMethodClientSecretBasic)), oidcclient.AuthOptions{})
		require.NoError(t, err)

		o.tamperTokenResponse(o.base+tenantA, func(resp map[string]any) { resp["id_token"] = b.Tokens.IDToken.Reveal() })

		_, err = o.login(t, o.rp(t, conn("shared-a", o.base+tenantA, sharedID, secret, oidcclient.AuthMethodClientSecretBasic)), oidcclient.AuthOptions{})
		require.ErrorIs(t, err, oidcclient.ErrIDTokenIssuer, "the signature verifies: iss is the only guard")
	})
}

// TestUserInfoSubstitution: an Identity carrying another end-user's access
// token — an application mixing up its token store — gets UserInfo claims
// about someone else, which the client refuses (Core §5.3.2).
func TestUserInfoSubstitution(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())

	aliceID, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	o.enduser.set(func(s *script) { s.subject = bob })

	bobID, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	mixed := *aliceID
	mixed.Tokens.AccessToken = bobID.Tokens.AccessToken

	info, err := c.UserInfo(t.Context(), &mixed)
	require.ErrorIs(t, err, oidcclient.ErrUserInfoSubject)
	assert.Nil(t, info)
}

// TestIDTokenUsedAsAnotherToken presents ID Tokens where other tokens are
// expected: as a Bearer access token at UserInfo (never stored: 401
// invalid_token, RFC 6750 §3.1), and as id_token_hint — the at+jwt access
// token, another client's ID Token, another issuer's ID Token — each an
// invalid hint (Core §3.1.2.1: invalid_request).
func TestIDTokenUsedAsAnotherToken(t *testing.T) {
	t.Parallel()

	o := newOP(t, func(cfg *opConfig) { cfg.jwtAccessTokens = true })
	c := o.rp(t, o.basic())

	own, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, o.base+o.paths(o.base).UserInfo, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+own.Tokens.IDToken.Reveal())

	resp, err := o.srv.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`)

	other, err := o.login(t, o.rp(t, conn("other", o.base, otherID, secret, oidcclient.AuthMethodClientSecretBasic)), oidcclient.AuthOptions{})
	require.NoError(t, err)

	tenant, err := o.login(t, o.rp(t, o.tenant(tenantA, tenantAID)), oidcclient.AuthOptions{})
	require.NoError(t, err)

	for name, hint := range map[string]oidcclient.Secret{
		"the at+jwt access token":   own.Tokens.AccessToken,
		"another client's ID Token": other.Tokens.IDToken,
		"another issuer's ID Token": tenant.Tokens.IDToken,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := o.login(t, c, oidcclient.AuthOptions{IDTokenHint: hint})
			requireAuthorizationError(t, err, "invalid_request")
		})
	}
}

// TestUnknownKeysTriggerABoundedRefresh checks the client's JWK Set cache
// against the provider: an unknown kid triggers at most one fetch per
// interval (10 s), a bad signature under a known kid none.
func TestUnknownKeysTriggerABoundedRefresh(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())
	jwks := o.paths(o.base).JWKS

	_, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, o.hits(jwks))

	o.tamperTokenResponse(o.base, func(resp map[string]any) {
		resp["id_token"] = resign(t, resp["id_token"].(string), "RS256", attackerKey(), func(h map[string]any) { h["kid"] = "unknown" }, nil) //nolint:forcetypeassert // test
	})

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey)
	assert.Equal(t, 1, o.hits(jwks), "within the interval: no fetch")

	o.clock.advance(11 * time.Second)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey)
	assert.Equal(t, 2, o.hits(jwks), "one bounded refresh")

	o.tamperTokenResponse(o.base, func(resp map[string]any) {
		resp["id_token"] = resign(t, resp["id_token"].(string), "RS256", attackerKey(), nil, nil) //nolint:forcetypeassert // test
	})
	o.clock.advance(11 * time.Second)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.ErrorIs(t, err, oidcclient.ErrIDTokenSignature)
	assert.Equal(t, 2, o.hits(jwks), "a bad signature under a known kid never refetches")
}
