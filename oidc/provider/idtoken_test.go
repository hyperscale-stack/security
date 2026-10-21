// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// atHash computes OIDC Core §3.1.3.6 at_hash with h.
func atHash(h hash.Hash, accessToken string) string {
	h.Write([]byte(accessToken))
	sum := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// TestIDTokenClaims pins OIDC Core §2, §3.1.3.3 and §3.1.3.6: the claim set
// of an ID Token issued at the code exchange.
func TestIDTokenClaims(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	issuedAt := e.clock.Now()
	resp := e.flow(authorizeQuery())

	header, claims := e.idToken(resp.IDToken)
	assert.Equal(t, map[string]any{"alg": "RS256", "kid": "rsa-a", "typ": "JWT"}, header,
		"no jku, jwk, x5u nor x5c (Core §2)")

	assert.ElementsMatch(t, []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "at_hash"},
		slices.Collect(maps.Keys(claims)))
	assert.Equal(t, testIssuer, claims["iss"])
	assert.Equal(t, "alice", claims["sub"])
	assert.Equal(t, webClientID, claims["aud"], "the client alone, as a string; no azp")
	assert.Equal(t, issuedAt.Unix(), unix(t, claims["iat"]))
	assert.Equal(t, issuedAt.Add(oidcprovider.DefaultIDTokenTTL).Unix(), unix(t, claims["exp"]))
	assert.Equal(t, issuedAt.Unix(), unix(t, claims["auth_time"]))
	assert.Equal(t, testNonce, claims["nonce"])
	assert.Equal(t, []any{"pwd"}, claims["amr"])
	assert.Equal(t, atHash(sha256.New(), resp.AccessToken), claims["at_hash"])
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestIDTokenWithoutNonceHasNoNonce(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	_, claims := e.idToken(e.flow(with(authorizeQuery(), "nonce", "")).IDToken)
	assert.NotContains(t, claims, "nonce")
}

func TestIDTokenCarriesTheAuthenticationEvent(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withConfig(func(c *oidcprovider.Config) { c.IDTokenTTL = 5 * time.Minute }))
	authTime := e.clock.Now().Add(-90 * time.Second)
	e.decide(func(ev *oidcprovider.AuthenticationEvent) {
		ev.AuthTime, ev.ACR, ev.AMR = authTime, "urn:loa:2", []string{"pwd", "otp"}
	}, nil)

	_, claims := e.idToken(e.flow(authorizeQuery()).IDToken)
	assert.Equal(t, authTime.Unix(), unix(t, claims["auth_time"]))
	assert.Equal(t, "urn:loa:2", claims["acr"])
	assert.Equal(t, []any{"pwd", "otp"}, claims["amr"])
	assert.Equal(t, unix(t, claims["iat"])+300, unix(t, claims["exp"]))
}

// TestIDTokenSigningAlgorithms pins Registration §2
// (id_token_signed_response_alg, RS256 by default) and Core §3.1.3.6: the
// at_hash hash follows the alg.
func TestIDTokenSigningAlgorithms(t *testing.T) {
	t.Parallel()

	ps384 := jwtsec.PrivateKey{KeyID: "ps-384", Algorithm: jwtsec.PS384, Key: rsaKeyB}
	es384 := jwtsec.PrivateKey{KeyID: "ec-384", Algorithm: jwtsec.ES384, Key: ec384}
	es512 := jwtsec.PrivateKey{KeyID: "ec-521", Algorithm: jwtsec.ES512, Key: ec521}

	cases := []struct {
		alg  jwtsec.Algorithm
		kid  string
		hash func() hash.Hash
	}{
		{jwtsec.RS256, "rsa-a", sha256.New},
		{jwtsec.ES256, "ec-1", sha256.New},
		{jwtsec.PS384, "ps-384", sha512.New384},
		{jwtsec.ES384, "ec-384", sha512.New384},
		{jwtsec.ES512, "ec-521", sha512.New},
	}

	for _, tc := range cases {
		t.Run(string(tc.alg), func(t *testing.T) {
			t.Parallel()

			e := newEnv(t, withClient(newAlgClient("alg-client", tc.alg)))
			e.keys.set(oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSA(), signingEC(), ps384, es384, es512}})

			code := e.code(with(authorizeQuery(), "client_id", "alg-client"))
			resp := tokens(t, e.exchangeAs(code, "alg-client"))

			header, claims := e.idToken(resp.IDToken)
			assert.Equal(t, string(tc.alg), header["alg"])
			assert.Equal(t, tc.kid, header["kid"])
			assert.Equal(t, atHash(tc.hash(), resp.AccessToken), claims["at_hash"])
			assert.Equal(t, "alg-client", claims["aud"])
		})
	}
}

// TestClientWithoutAnAlgorithmGetsRS256: an IDTokenSigningClient naming no
// algorithm gets the default, RS256 (OIDC Registration §2).
func TestClientWithoutAnAlgorithmGetsRS256(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withClient(newAlgClient("default-client", "")))
	code := e.code(with(authorizeQuery(), "client_id", "default-client"))

	header, _ := e.idToken(tokens(t, e.exchangeAs(code, "default-client")).IDToken)
	assert.Equal(t, string(jwtsec.RS256), header["alg"])
}

// TestIDTokenIssuerIsCheckedAtTheExchange: an issuer the provider no longer
// accepts — an http loopback issuer once the opt-in is gone — gets no ID
// Token (server_error), even for a code issued before.
func TestIDTokenIssuerIsCheckedAtTheExchange(t *testing.T) {
	t.Parallel()

	loopback := withResolver(fixedIssuer{issuer: "http://127.0.0.1:8080"})
	store := memory.New()
	lax := newEnv(t, loopback, withStore(store), withConfig(func(c *oidcprovider.Config) { c.AllowInsecureLoopbackIssuer = true }))
	code := lax.code(authorizeQuery())

	strict := newEnv(t, loopback, withStore(store))
	rec := strict.exchange(code)
	assert.Equal(t, oauth2.CodeServerError, oauthError(t, rec))
	assert.NotContains(t, rec.Body.String(), "id_token")
}

// TestClientAlgorithmWithoutAKey: a client registered for an algorithm no
// signing key serves is refused before any interaction (server_error), and
// at /token if the key disappears in between.
func TestClientAlgorithmWithoutAKey(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withClient(newAlgClient("rs512-client", jwtsec.RS512)))

	params := redirect(t, e.authorize(with(authorizeQuery(), "client_id", "rs512-client")))
	assert.Equal(t, oauth2.CodeServerError, params.Get("error"))

	interactive, _ := e.interaction.calls()
	assert.Empty(t, interactive)

	code := e.code(with(authorizeQuery(), "client_id", es256ClientID))
	e.keys.set(oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSA()}})
	assert.Equal(t, oauth2.CodeServerError, oauthError(t, e.exchangeAs(code, es256ClientID)))
}

// TestIDTokenClaimsFromTheClaimsParameter pins OIDC Core §5.5 and §5.5.1:
// requested ID Token claims are released from the source, filtered by their
// value constraints; null and empty values are omitted (§5.3.2); the
// protocol claims cannot be overridden; scope claims stay at UserInfo
// (§5.4).
func TestIDTokenClaimsFromTheClaimsParameter(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	request := `{"id_token": {
		"email": null, "email_verified": {"value": true}, "phone_number": {"values": ["+1 555"]},
		"nickname": null, "middle_name": null, "address": null, "updated_at": {"value": 1760000000},
		"sub": null, "iss": null, "nonce": null, "auth_time": {"essential": true}, "at_hash": null, "groups": null,
		"sub#x": null
	}}`

	_, claims := e.idToken(e.flow(with(authorizeQuery(), "claims", request, "scope", "openid profile")).IDToken)

	assert.Equal(t, "alice@example.com", claims["email"])
	assert.Equal(t, true, claims["email_verified"])
	assert.NotContains(t, claims, "phone_number", "value constraint unmet")
	assert.NotContains(t, claims, "nickname", "empty string omitted")
	assert.NotContains(t, claims, "middle_name", "null omitted")
	assert.Equal(t, map[string]any{"country": "FR"}, claims["address"])
	assert.Equal(t, int64(1760000000), unix(t, claims["updated_at"]))
	assert.Equal(t, []any{"admins"}, claims["groups"])
	assert.Equal(t, "alice", claims["sub"])
	assert.Equal(t, testIssuer, claims["iss"])
	assert.Equal(t, testNonce, claims["nonce"])
	assert.NotContains(t, claims, "name", "profile claims are UserInfo's (Core §5.4)")
	assert.NotContains(t, claims, "azp")
	assert.NotContains(t, claims, "sub#x", "a tagged protocol claim is reserved too")

	queries := e.claims.recorded()
	require.Len(t, queries, 1)
	assert.Equal(t, oidcprovider.ClaimsForIDToken, queries[0].Target)
	assert.Equal(t, "alice", queries[0].Subject)
	assert.Equal(t, webClientID, queries[0].ClientID)
	assert.Equal(t, testIssuer, queries[0].Issuer)
	assert.ElementsMatch(t, []string{"email", "email_verified", "phone_number", "nickname", "middle_name", "address", "updated_at", "groups"},
		queries[0].Names, "protocol claims are never asked for")
}

// TestCodeExchangeFailures: every refusal at the code exchange persists
// nothing and returns no tokens.
func TestCodeExchangeFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		setup func(*env)
		opts  []envOption
		want  string
	}{
		{"claim value the signer cannot encode", func(e *env) { e.claims.users["alice"]["groups"] = math.Inf(1) }, nil, oauth2.CodeServerError},
		{"unknown subject", func(e *env) { e.claims.removeUser("alice") }, nil, oauth2.CodeInvalidGrant},
		{"claims source failure", func(e *env) { e.claims.fail(errors.New("directory down")) }, nil, oauth2.CodeServerError},
		{"key source failure", func(e *env) { e.keys.fail(errors.New("kms down")) }, nil, oauth2.CodeServerError},
		{"access token audience equal to the client", nil,
			[]envOption{withResolver(audienceIssuer(webClientID))}, oauth2.CodeServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spy := &spyStore{}
			e := newEnv(t, append([]envOption{withSpy(spy)}, tc.opts...)...)
			code := e.code(with(authorizeQuery(), "claims", `{"id_token": {"groups": null}}`))

			if tc.setup != nil {
				tc.setup(e)
			}

			rec := e.exchange(code)
			assert.Equal(t, tc.want, oauthError(t, rec))
			assert.NotContains(t, rec.Body.String(), "access_token")
			assert.NotContains(t, rec.Body.String(), "id_token")
			assert.Zero(t, spy.pairs.Load(), "nothing is persisted")
		})
	}
}

// audienceIssuer resolves the test issuer with the given access-token
// audience.
type audienceIssuer string

func (a audienceIssuer) Resolve(context.Context, *http.Request) (string, string, error) {
	return testIssuer, string(a), nil
}

// TestOpenIDCodeWithoutContextIsRefused pins OIDC Core §3.1.3.2: a code
// redeemed for an ID Token must have been issued for an OpenID request.
func TestOpenIDCodeWithoutContextIsRefused(t *testing.T) {
	t.Parallel()

	for name, data := range map[string]string{
		"no context":              "",
		"undecodable context":     "{not json",
		"unknown context version": `{"v":2,"auth_time":1760000000}`,
		"context without time":    `{"v":1}`,
		"unknown context member":  `{"v":1,"auth_time":1760000000,"x":1}`,
		"trailing data":           `{"v":1,"auth_time":1760000000}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			raw := "forged-code-" + name
			now := e.clock.Now()
			require.NoError(t, e.store.SaveAuthorizationCode(context.Background(), &oauth2.AuthorizationCode{
				Code: raw, CodeHash: oauth2.HashToken(nil, raw), ClientID: webClientID, Subject: "alice",
				RedirectURI: webRedirectURI, Scope: "openid", CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256",
				IssuedAt: now, ExpiresAt: now.Add(time.Minute), Issuer: testIssuer, ExtensionData: data,
			}))

			assert.Equal(t, oauth2.CodeInvalidGrant, oauthError(t, e.exchange(raw)))
		})
	}
}

// TestPlainOAuth2CodeExchange: an OAuth 2.0 grant gets the core's token
// response, without id_token; the provider approved it, so it checks its
// end-user is still valid — a claims query naming no claim.
func TestPlainOAuth2CodeExchange(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	code := e.code(with(authorizeQuery(), "scope", "read"))
	rec := e.exchange(code)

	require.Equal(t, http.StatusOK, rec.Code)
	body := jsonMembers(t, rec)
	assert.ElementsMatch(t, []string{"access_token", "token_type", "expires_in", "scope"}, body)
	assert.Equal(t, []oidcprovider.ClaimsQuery{{
		Issuer: testIssuer, Subject: "alice", ClientID: webClientID, Target: oidcprovider.ClaimsForIDToken,
	}}, e.claims.recorded(), "an account check, no claim asked for")
}

// jsonMembers returns the member names of a JSON object response.
func jsonMembers(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	return slices.Collect(maps.Keys(body))
}

// TestValueConstraintsMatchScalarsOnly pins the Core §5.5.1 equality: a
// value constraint matches JSON scalars — an object, an out-of-range number
// or a value the source cannot encode never matches, so the claim is not
// released.
func TestValueConstraintsMatchScalarsOnly(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.claims.users["alice"]["infinite"] = math.Inf(1)
	e.claims.users["alice"]["score"] = 12.5
	e.claims.users["alice"]["huge"] = json.Number("2e999")

	request := `{"id_token": {
		"address": {"value": {"country": "FR"}}, "updated_at": {"value": 1e999},
		"infinite": {"value": 1}, "score": {"values": [12.50, 13]}, "huge": {"value": 1e999}
	}}`

	_, claims := e.idToken(e.flow(with(authorizeQuery(), "claims", request)).IDToken)
	assert.NotContains(t, claims, "address")
	assert.NotContains(t, claims, "updated_at")
	assert.NotContains(t, claims, "infinite")
	assert.NotContains(t, claims, "huge", "two numbers beyond float64 are not equal")
	assert.Equal(t, json.Number("12.5"), claims["score"], "numbers compare numerically")
}

// TestAuthorizationFailsClosedOnServerSideErrors: a key source or an issuer
// the provider cannot use answers server_error before any interaction.
func TestAuthorizationFailsClosedOnServerSideErrors(t *testing.T) {
	t.Parallel()

	broken := newEnv(t)
	broken.keys.fail(errors.New("kms down"))
	assert.Equal(t, oauth2.CodeServerError, redirect(t, broken.authorize(authorizeQuery())).Get("error"))

	insecure := newEnv(t, withResolver(fixedIssuer{issuer: "http://op.example"}))
	assert.Equal(t, oauth2.CodeServerError, redirect(t, insecure.authorize(authorizeQuery())).Get("error"))

	for _, e := range []*env{broken, insecure} {
		interactive, silent := e.interaction.calls()
		assert.Empty(t, interactive)
		assert.Empty(t, silent)
	}
}
