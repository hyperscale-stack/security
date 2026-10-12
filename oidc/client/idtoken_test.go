// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hyperscale-stack/security"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idCase is one ID Token scenario: setup scripts the OP (under its lock,
// before the Client is built), err is the expected sentinel (nil: valid).
type idCase struct {
	name   string
	setup  func(op *fakeOP)
	config func(*oidcclient.Config)
	opts   oidcclient.AuthOptions
	err    error
	check  func(t *testing.T, id *oidcclient.Identity)
}

func runIDCases(t *testing.T, cases []idCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			if tc.setup != nil {
				op.set(tc.setup)
			}

			var mutators []func(*oidcclient.Config)
			if tc.config != nil {
				mutators = append(mutators, tc.config)
			}

			c := op.client(t, mutators...)
			ar, code := op.begin(t, c, tc.opts)

			id, err := c.Complete(context.Background(), callbackFor(ar, code))
			if tc.err == nil {
				require.NoError(t, err)
				require.NotNil(t, id)

				if tc.check != nil {
					tc.check(t, id)
				}

				return
			}

			require.ErrorIs(t, err, tc.err)
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.Nil(t, id, "no identity, and no token, from a failed login")
		})
	}
}

func setClaim(name string, value any) func(op *fakeOP) {
	return func(op *fakeOP) {
		op.claimsHook = func(_ *grant, claims map[string]any) {
			if value == nil {
				delete(claims, name)

				return
			}

			claims[name] = value
		}
	}
}

func setHeader(name string, value any) func(op *fakeOP) {
	return func(op *fakeOP) {
		op.headerHook = func(h map[string]any) { h[name] = value }
	}
}

// rawPayload makes the OP sign payload(g) verbatim.
func rawPayload(payload func(op *fakeOP, g *grant) string) func(op *fakeOP) {
	return func(op *fakeOP) {
		op.idTokenHook = func(g *grant) string {
			return signJWS(op.t, op.signer, nil, []byte(payload(op, g)))
		}
	}
}

func baseClaims(op *fakeOP, g *grant) string {
	now := op.clock.Now()

	return `"iss":"` + op.issuer + `","aud":"` + testClientID + `","exp":` + itoa(now.Add(5*time.Minute).Unix()) +
		`,"iat":` + itoa(now.Unix()) + `,"nonce":"` + g.nonce + `"`
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func signWith(key signingKey) func(op *fakeOP) {
	return func(op *fakeOP) {
		op.signer = key
		op.jwks = []jose.JSONWebKey{key.jwk()}
	}
}

func TestIDTokenAlgorithms(t *testing.T) {
	t.Parallel()

	runIDCases(t, []idCase{
		{name: "RS256", setup: signWith(keyRSA(jose.RS256, "k"))},
		{name: "RS384", setup: signWith(keyRSA(jose.RS384, "k"))},
		{name: "RS512", setup: signWith(keyRSA(jose.RS512, "k"))},
		{name: "PS256", setup: signWith(keyRSA(jose.PS256, "k"))},
		{name: "PS384", setup: signWith(keyRSA(jose.PS384, "k"))},
		{name: "PS512", setup: signWith(keyRSA(jose.PS512, "k"))},
		{name: "ES256", setup: signWith(keyEC(jose.ES256, "k"))},
		{name: "ES384", setup: signWith(keyEC(jose.ES384, "k"))},
		{name: "ES512", setup: signWith(keyEC(jose.ES512, "k"))},
		{name: "EdDSA", setup: signWith(keyEd("k"))},
		{
			name: "alg none", err: oidcclient.ErrIDTokenAlgorithm,
			setup: func(op *fakeOP) {
				op.idTokenHook = func(g *grant) string {
					header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
					payload := base64.RawURLEncoding.EncodeToString([]byte(`{` + baseClaims(op, g) + `,"sub":"x"}`))

					return header + "." + payload + "."
				}
			},
		},
		{
			name: "HS256 keyed with the client secret", err: oidcclient.ErrIDTokenAlgorithm,
			setup: func(op *fakeOP) {
				op.idTokenHook = func(g *grant) string {
					signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(testClientSecret)}, nil)
					require.NoError(op.t, err)

					jws, err := signer.Sign([]byte(`{` + baseClaims(op, g) + `,"sub":"x"}`))
					require.NoError(op.t, err)

					out, err := jws.CompactSerialize()
					require.NoError(op.t, err)

					return out
				}
			},
		},
		{
			name: "algorithm not advertised", err: oidcclient.ErrIDTokenAlgorithm,
			setup: func(op *fakeOP) { op.metadata["id_token_signing_alg_values_supported"] = []string{"ES256"} },
		},
		{
			name: "algorithm not configured", err: oidcclient.ErrIDTokenAlgorithm,
			config: func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{oidcclient.ES256} },
		},
	})
}

func TestIDTokenSerialization(t *testing.T) {
	t.Parallel()

	token := func(s string) func(op *fakeOP) {
		return func(op *fakeOP) { op.idTokenHook = func(*grant) string { return s } }
	}

	runIDCases(t, []idCase{
		{name: "JWE", err: oidcclient.ErrIDTokenMalformed, setup: token("eyJhbGciOiJSU0EtT0FFUCJ9.a.b.c.d")},
		{name: "JSON serialization", err: oidcclient.ErrIDTokenMalformed, setup: token(`{"payload":"e30","signatures":[]}`)},
		{name: "two parts", err: oidcclient.ErrIDTokenMalformed, setup: token("eyJhbGciOiJSUzI1NiJ9.e30")},
		{name: "garbage", err: oidcclient.ErrIDTokenMalformed, setup: token("!!!")},
		{name: "payload not JSON", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(*fakeOP, *grant) string { return "not json" })},
		{name: "payload JSON array", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(*fakeOP, *grant) string { return "[1]" })},
	})
}

// TestIDTokenHeader checks explicit typing (RFC 8725 §3.11-3.12): an RFC
// 9068 access token or any other typed JWT is not an ID Token; nested JWTs
// and JWS extensions are refused.
func TestIDTokenHeader(t *testing.T) {
	t.Parallel()

	runIDCases(t, []idCase{
		{name: "typ JWT", setup: setHeader("typ", "JWT")},
		{name: "typ jwt lower case", setup: setHeader("typ", "jwt")},
		{name: "typ application/JWT", setup: setHeader("typ", "application/JWT")},
		{name: "typ absent", setup: setHeader("typ", nil)},
		{name: "typ at+jwt", err: oidcclient.ErrIDTokenType, setup: setHeader("typ", "at+jwt")},
		{name: "typ application/at+jwt", err: oidcclient.ErrIDTokenType, setup: setHeader("typ", "application/at+jwt")},
		{name: "typ logout+jwt", err: oidcclient.ErrIDTokenType, setup: setHeader("typ", "logout+jwt")},
		{name: "typ JOSE", err: oidcclient.ErrIDTokenType, setup: setHeader("typ", "JOSE")},
		{name: "typ not a string", err: oidcclient.ErrIDTokenType, setup: setHeader("typ", 42)},
		{name: "cty JWT (nested)", err: oidcclient.ErrIDTokenType, setup: setHeader("cty", "JWT")},
		{name: "crit", err: oidcclient.ErrIDTokenType, setup: func(op *fakeOP) {
			op.headerHook = func(h map[string]any) { h["crit"] = []string{"exp"}; h["exp"] = 1 }
		}},
		{name: "b64", err: oidcclient.ErrIDTokenType, setup: setHeader("b64", true)},
	})
}

// TestAccessTokenNotAcceptedAsIDToken plays the RFC 9068 token confusion:
// a correctly signed access token whose aud is the client and that even
// carries the login's nonce is refused.
func TestAccessTokenNotAcceptedAsIDToken(t *testing.T) {
	t.Parallel()

	runIDCases(t, []idCase{{
		name: "at+jwt with the client as audience", err: oidcclient.ErrIDTokenType,
		setup: func(op *fakeOP) {
			op.idTokenHook = func(g *grant) string {
				payload := `{` + baseClaims(op, g) + `,"sub":"` + testSubject + `","client_id":"` + testClientID +
					`","scope":"openid","jti":"j1"}`

				return signJWS(op.t, op.signer, map[string]any{"typ": "at+jwt"}, []byte(payload))
			}
		},
	}})
}

// TestIDTokenKeySelection checks RFC 8725 §3.1 (a key is used with exactly
// one algorithm), §3.10 (keys only from the issuer's jwks_uri, never from
// jwk/jku/x5u headers) and Core §10.1 (kid).
func TestIDTokenKeySelection(t *testing.T) {
	t.Parallel()

	var evilHits atomic.Int64

	evil := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { evilHits.Add(1) }))
	t.Cleanup(evil.Close)

	signedBy := func(key signingKey, header map[string]any) func(op *fakeOP) {
		return func(op *fakeOP) {
			op.idTokenHook = func(g *grant) string {
				claims := op.idClaims(g)
				payload, err := json.Marshal(claims)
				require.NoError(op.t, err)

				return signJWS(op.t, key, header, payload)
			}
		}
	}

	runIDCases(t, []idCase{
		{name: "unknown kid", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) { op.signer.kid = "ghost" }},
		{
			name: "embedded jwk of the attacker under the published kid", err: oidcclient.ErrIDTokenSignature,
			setup: func(op *fakeOP) {
				op.idTokenHook = func(g *grant) string {
					payload, err := json.Marshal(op.idClaims(g))
					require.NoError(op.t, err)

					signer, err := jose.NewSigner(
						jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: keyEvil("rsa-1").priv, KeyID: "rsa-1"}},
						&jose.SignerOptions{EmbedJWK: true},
					)
					require.NoError(op.t, err)

					jws, err := signer.Sign(payload)
					require.NoError(op.t, err)

					out, err := jws.CompactSerialize()
					require.NoError(op.t, err)

					return out
				}
			},
		},
		{name: "jku header never followed", err: oidcclient.ErrIDTokenSignature, setup: signedBy(keyEvil("rsa-1"), map[string]any{"jku": evil.URL + "/jwks"})},
		{name: "x5u header never followed", err: oidcclient.ErrIDTokenSignature, setup: signedBy(keyEvil("rsa-1"), map[string]any{"x5u": evil.URL + "/cert"})},
		{name: "another key under the published kid", err: oidcclient.ErrIDTokenSignature, setup: signedBy(keyEvil("rsa-1"), nil)},
		{name: "no kid, single key", setup: func(op *fakeOP) { op.signer.kid = ""; op.jwks = []jose.JSONWebKey{keyRSA(jose.RS256, "").jwk()} }},
		{name: "no kid, one compatible key among others", setup: func(op *fakeOP) {
			op.signer.kid = ""
			op.jwks = []jose.JSONWebKey{keyRSA(jose.RS256, "").jwk(), keyEC(jose.ES256, "ec").jwk()}
		}},
		{name: "no kid, two compatible keys", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			op.signer.kid = ""
			op.jwks = []jose.JSONWebKey{keyRSA(jose.RS256, "a").jwk(), keyRSAB("b").jwk()}
		}},
		{name: "JWK alg differs from header alg", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			op.jwks = []jose.JSONWebKey{keyRSA(jose.RS384, "rsa-1").jwk()}
		}},
		{name: "JWK declaring an alg its key cannot verify", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			op.signer = keyEC(jose.ES256, "rsa-1")
			k := keyRSA(jose.RS256, "rsa-1").jwk()
			k.Algorithm = string(jose.ES256)
			op.jwks = []jose.JSONWebKey{k}
		}},
		{name: "key type does not fit the alg", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			op.jwks = []jose.JSONWebKey{keyEC(jose.ES256, "rsa-1").bareJWK()}
		}},
		{name: "curve does not fit the alg", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			op.signer = keyEC(jose.ES384, "ec")
			op.jwks = []jose.JSONWebKey{keyEC(jose.ES256, "ec").bareJWK()}
		}},
		{name: "alg-less RSA key is RS256 only", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			op.signer = keyRSA(jose.PS256, "rsa-1")
			op.jwks = []jose.JSONWebKey{op.signer.bareJWK()}
		}},
		{name: "alg-less RSA key with RS256", setup: func(op *fakeOP) { op.jwks = []jose.JSONWebKey{op.signer.bareJWK()} }},
		{
			name:   "alg-less RSA key, single RSA alg effective",
			config: func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{oidcclient.PS256} },
			setup: func(op *fakeOP) {
				op.signer = keyRSA(jose.PS256, "rsa-1")
				op.jwks = []jose.JSONWebKey{op.signer.bareJWK()}
			},
		},
		{
			name:   "alg-less RSA key, two RSA algs effective without RS256",
			err:    oidcclient.ErrUnknownSigningKey,
			config: func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{oidcclient.PS256, oidcclient.PS384} },
			setup: func(op *fakeOP) {
				op.signer = keyRSA(jose.PS256, "rsa-1")
				op.jwks = []jose.JSONWebKey{op.signer.bareJWK()}
			},
		},
		{
			name:   "alg-less RSA key, one RSA alg among other families",
			config: func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{oidcclient.ES256, oidcclient.PS256} },
			setup: func(op *fakeOP) {
				op.signer = keyRSA(jose.PS256, "rsa-1")
				op.jwks = []jose.JSONWebKey{op.signer.bareJWK()}
			},
		},
		{name: "alg-less EC key bound by its curve", setup: func(op *fakeOP) {
			op.signer = keyEC(jose.ES384, "ec")
			op.jwks = []jose.JSONWebKey{op.signer.bareJWK()}
		}},
		{name: "weak RSA key skipped", err: oidcclient.ErrUnknownSigningKey, setup: signWith(keyWeak("weak"))},
		{name: "encryption key skipped", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			k := op.signer.jwk()
			k.Use = "enc"
			op.jwks = []jose.JSONWebKey{k}
		}},
		{name: "key_ops without verify skipped", err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			op.jwksRaw = jwksWithMember(op.t, op.signer.jwk(), "key_ops", []string{"encrypt"})
		}},
		{name: "key_ops with verify", setup: func(op *fakeOP) {
			op.jwksRaw = jwksWithMember(op.t, op.signer.jwk(), "key_ops", []string{"verify"})
		}},
	})

	assert.Zero(t, evilHits.Load(), "jku and x5u are never fetched")
}

// jwksWithMember returns the JWK Set of key with an extra member.
func jwksWithMember(t *testing.T, key jose.JSONWebKey, name string, value any) []byte {
	t.Helper()

	raw, err := json.Marshal(key)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	m[name] = value

	out, err := json.Marshal(map[string]any{"keys": []any{m}})
	require.NoError(t, err)

	return out
}

func TestIDTokenSignature(t *testing.T) {
	t.Parallel()

	tamper := func(change func(parts []string, op *fakeOP, g *grant) []string) func(op *fakeOP) {
		return func(op *fakeOP) {
			op.idTokenHook = func(g *grant) string {
				payload, err := json.Marshal(op.idClaims(g))
				require.NoError(op.t, err)

				parts := strings.Split(signJWS(op.t, op.signer, nil, payload), ".")

				return strings.Join(change(parts, op, g), ".")
			}
		}
	}

	runIDCases(t, []idCase{
		{name: "tampered payload", err: oidcclient.ErrIDTokenSignature, setup: tamper(func(p []string, op *fakeOP, g *grant) []string {
			claims := op.idClaims(g)
			claims["sub"] = "admin"
			b, _ := json.Marshal(claims)
			p[1] = base64.RawURLEncoding.EncodeToString(b)

			return p
		})},
		{name: "tampered signature", err: oidcclient.ErrIDTokenSignature, setup: tamper(func(p []string, _ *fakeOP, _ *grant) []string {
			sig, _ := base64.RawURLEncoding.DecodeString(p[2])
			sig[0] ^= 0xff
			p[2] = base64.RawURLEncoding.EncodeToString(sig)

			return p
		})},
		{name: "signature stripped", err: oidcclient.ErrIDTokenSignature, setup: tamper(func(p []string, _ *fakeOP, _ *grant) []string {
			p[2] = ""

			return p
		})},
	})
}

// TestIDTokenClaimsJSON checks the strict claims set: RFC 7519 §4 duplicate
// names refused, Core §14 exact (case-sensitive) claim names, RFC 8725 §3.7
// UTF-8, JSON types.
func TestIDTokenClaimsJSON(t *testing.T) {
	t.Parallel()

	runIDCases(t, []idCase{
		{name: "duplicate sub", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(op *fakeOP, g *grant) string {
			return `{` + baseClaims(op, g) + `,"sub":"victim","sub":"attacker"}`
		})},
		{name: "sub and SUB", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(op *fakeOP, g *grant) string {
			return `{` + baseClaims(op, g) + `,"sub":"attacker","SUB":"victim"}`
		})},
		{name: "only Sub", err: oidcclient.ErrIDTokenMissingClaim, setup: rawPayload(func(op *fakeOP, g *grant) string {
			return `{` + baseClaims(op, g) + `,"Sub":"victim"}`
		})},
		{name: "long-s variant of sub", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(op *fakeOP, g *grant) string {
			return `{` + baseClaims(op, g) + `,"sub":"a","\u017fub":"b"}`
		})},
		{name: "nested duplicate", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(op *fakeOP, g *grant) string {
			return `{` + baseClaims(op, g) + `,"sub":"a","address":{"country":"FR","country":"US"}}`
		})},
		{name: "invalid UTF-8", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(op *fakeOP, g *grant) string {
			return `{` + baseClaims(op, g) + ",\"sub\":\"a\",\"name\":\"\xff\"}"
		})},
		{name: "lone surrogate", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(op *fakeOP, g *grant) string {
			return `{` + baseClaims(op, g) + `,"sub":"a","name":"\udc00"}`
		})},
		{name: "iss not a string", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("iss", 42)},
		{name: "exp as a string", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("exp", "1900000000")},
		{name: "exp not finite", err: oidcclient.ErrIDTokenMalformed, setup: rawPayload(func(op *fakeOP, g *grant) string {
			return `{"iss":"` + op.issuer + `","aud":"` + testClientID + `","exp":1e400,"iat":` + itoa(op.clock.Now().Unix()) +
				`,"nonce":"` + g.nonce + `","sub":"a"}`
		})},
		{name: "exp negative", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("exp", -1)},
		{name: "exp beyond year 9999", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("exp", 1e300)},
		{name: "aud not a string", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("aud", 42)},
		{name: "aud array with a number", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("aud", []any{testClientID, 42})},
		{name: "amr not an array", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("amr", "pwd")},
		{name: "at_hash not a string", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("at_hash", 42)},
		{name: "fractional dates", setup: func(op *fakeOP) {
			op.claimsHook = func(_ *grant, claims map[string]any) {
				claims["iat"] = float64(op.clock.Now().Unix()) + 0.5
				claims["exp"] = float64(op.clock.Now().Add(time.Minute).Unix()) + 0.25
			}
		}},
		{name: "amr and acr exposed", setup: func(op *fakeOP) {
			op.claimsHook = func(_ *grant, claims map[string]any) {
				claims["amr"] = []string{"pwd", "otp"}
				claims["acr"] = "urn:acr:gold"
			}
		}, check: func(t *testing.T, id *oidcclient.Identity) {
			t.Helper()
			assert.Equal(t, []string{"pwd", "otp"}, id.AMR)
			assert.Equal(t, "urn:acr:gold", id.ACR)
		}},
	})
}

func TestIDTokenIssuerAndSubject(t *testing.T) {
	t.Parallel()

	runIDCases(t, []idCase{
		{name: "other issuer", err: oidcclient.ErrIDTokenIssuer, setup: setClaim("iss", "https://evil.example.com")},
		{name: "issuer with trailing slash", err: oidcclient.ErrIDTokenIssuer, setup: func(op *fakeOP) {
			op.claimsHook = func(_ *grant, c map[string]any) { c["iss"] = op.issuer + "/" }
		}},
		{name: "no issuer", err: oidcclient.ErrIDTokenIssuer, setup: setClaim("iss", nil)},
		{name: "no subject", err: oidcclient.ErrIDTokenMissingClaim, setup: setClaim("sub", nil)},
		{name: "empty subject", err: oidcclient.ErrIDTokenMissingClaim, setup: setClaim("sub", "")},
		{name: "subject too long", err: oidcclient.ErrIDTokenMissingClaim, setup: setClaim("sub", strings.Repeat("s", 256))},
		{name: "subject with control", err: oidcclient.ErrIDTokenMissingClaim, setup: setClaim("sub", "a\nb")},
		{name: "subject non-ASCII", err: oidcclient.ErrIDTokenMissingClaim, setup: setClaim("sub", "é")},
		{name: "subject of 255 characters", setup: setClaim("sub", strings.Repeat("s", 255))},
		{name: "subject with a space", setup: setClaim("sub", "DOMAIN\\jane doe"), check: func(t *testing.T, id *oidcclient.Identity) {
			t.Helper()
			assert.Equal(t, "DOMAIN\\jane doe", id.Subject)
		}},
	})
}

func TestIDTokenAudience(t *testing.T) {
	t.Parallel()

	runIDCases(t, []idCase{
		{name: "other client", err: oidcclient.ErrIDTokenAudience, setup: setClaim("aud", "other-client")},
		{name: "missing", err: oidcclient.ErrIDTokenAudience, setup: setClaim("aud", nil)},
		{name: "empty array", err: oidcclient.ErrIDTokenAudience, setup: setClaim("aud", []string{})},
		{name: "array with the client", setup: setClaim("aud", []string{testClientID})},
		{name: "untrusted extra audience", err: oidcclient.ErrIDTokenAudience, setup: setClaim("aud", []string{testClientID, "https://api.example.com"})},
		{
			name: "trusted extra audience", setup: setClaim("aud", []string{testClientID, "https://api.example.com"}),
			config: func(c *oidcclient.Config) { c.TrustedAudiences = []string{"https://api.example.com"} },
			check: func(t *testing.T, id *oidcclient.Identity) {
				t.Helper()
				assert.Equal(t, []string{testClientID, "https://api.example.com"}, id.Audience)
			},
		},
		{name: "azp of another party", err: oidcclient.ErrIDTokenAuthorizedParty, setup: setClaim("azp", "other-client")},
		{name: "azp of the client", setup: setClaim("azp", testClientID)},
		{name: "azp empty", err: oidcclient.ErrIDTokenAuthorizedParty, setup: setClaim("azp", "")},
	})
}

// TestIDTokenTimes checks exp (RFC 7519 §4.1.4), iat bounds and nbf with
// the default one-minute skew, at the exact boundaries. The transaction is
// created at testNow, which is also the validation time.
func TestIDTokenTimes(t *testing.T) {
	t.Parallel()

	skew := time.Minute
	at := func(d time.Duration) int64 { return testNow.Add(d).Unix() }

	runIDCases(t, []idCase{
		{name: "exp missing", err: oidcclient.ErrIDTokenMissingClaim, setup: setClaim("exp", nil)},
		{name: "exp at now minus skew", err: oidcclient.ErrIDTokenExpired, setup: setClaim("exp", at(-skew))},
		{name: "exp one second later", setup: setClaim("exp", at(-skew+time.Second))},
		{name: "exp long past", err: oidcclient.ErrIDTokenExpired, setup: setClaim("exp", at(-time.Hour))},
		{name: "iat missing", err: oidcclient.ErrIDTokenMissingClaim, setup: setClaim("iat", nil)},
		{name: "iat beyond skew in the future", err: oidcclient.ErrIDTokenIssuedAt, setup: setClaim("iat", at(skew+time.Second))},
		{name: "iat at the future skew edge", setup: setClaim("iat", at(skew))},
		{name: "iat before the request", err: oidcclient.ErrIDTokenIssuedAt, setup: setClaim("iat", at(-skew-time.Second))},
		{name: "iat at the past skew edge", setup: setClaim("iat", at(-skew))},
		{name: "nbf beyond skew", err: oidcclient.ErrIDTokenNotYetValid, setup: setClaim("nbf", at(skew+time.Second))},
		{name: "nbf at the skew edge", setup: setClaim("nbf", at(skew))},
		{name: "nbf not a number", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("nbf", "soon")},
		{
			name: "custom skew", err: oidcclient.ErrIDTokenExpired, setup: setClaim("exp", at(-10*time.Second)),
			config: func(c *oidcclient.Config) { c.ClockSkew = 5 * time.Second },
		},
	})
}

// TestIDTokenBoundsFromTheRequest checks that the iat lower bound and the
// max_age bound are measured from the authorization request, not from the
// callback: the user may spend minutes at the provider.
func TestIDTokenBoundsFromTheRequest(t *testing.T) {
	t.Parallel()

	fiveMinutes := 5 * time.Minute

	cases := map[string]struct {
		opts  oidcclient.AuthOptions
		claim string
		value int64
	}{
		"iat at the request minus skew":       {claim: "iat", value: testNow.Add(-time.Minute).Unix()},
		"auth_time at max_age before request": {opts: oidcclient.AuthOptions{MaxAge: &fiveMinutes}, claim: "auth_time", value: testNow.Add(-fiveMinutes - time.Minute).Unix()},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t)
			ar, code := op.begin(t, c, tc.opts) // the transaction is created at testNow

			op.clock.Advance(3 * time.Minute) // the user takes three minutes at the provider
			op.set(setClaim(tc.claim, tc.value))

			_, err := c.Complete(context.Background(), callbackFor(ar, code))
			require.NoError(t, err)
		})
	}
}

func TestIDTokenNonce(t *testing.T) {
	t.Parallel()

	runIDCases(t, []idCase{
		{name: "missing", err: oidcclient.ErrIDTokenNonce, setup: setClaim("nonce", nil)},
		{name: "different", err: oidcclient.ErrIDTokenNonce, setup: setClaim("nonce", "n-0S6_WzA2Mj")},
		{name: "empty", err: oidcclient.ErrIDTokenNonce, setup: setClaim("nonce", "")},
		{name: "not a string", err: oidcclient.ErrIDTokenMalformed, setup: setClaim("nonce", 42)},
	})

	t.Run("nonce of another login", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		c := op.client(t)

		victim, code := op.begin(t, c, oidcclient.AuthOptions{})
		_, otherCode := op.begin(t, c, oidcclient.AuthOptions{})

		op.set(func(op *fakeOP) {
			nonce := op.grants[otherCode].nonce
			op.claimsHook = func(_ *grant, claims map[string]any) { claims["nonce"] = nonce }
		})

		_, err := c.Complete(context.Background(), callbackFor(victim, code))
		require.ErrorIs(t, err, oidcclient.ErrIDTokenNonce)
	})
}

// TestIDTokenAuthTime checks max_age (Core §3.1.2.1, §3.1.3.7): auth_time
// becomes REQUIRED and no older than max_age before the request, minus
// skew.
func TestIDTokenAuthTime(t *testing.T) {
	t.Parallel()

	skew := time.Minute
	fiveMinutes := 5 * time.Minute
	zero := time.Duration(0)
	at := func(d time.Duration) int64 { return testNow.Add(d).Unix() }

	runIDCases(t, []idCase{
		{name: "max_age, auth_time missing", err: oidcclient.ErrIDTokenMissingClaim, opts: oidcclient.AuthOptions{MaxAge: &fiveMinutes}, setup: setClaim("auth_time", nil)},
		{name: "max_age, too old", err: oidcclient.ErrIDTokenAuthTime, opts: oidcclient.AuthOptions{MaxAge: &fiveMinutes}, setup: setClaim("auth_time", at(-fiveMinutes-skew-time.Second))},
		{name: "max_age, at the edge", opts: oidcclient.AuthOptions{MaxAge: &fiveMinutes}, setup: setClaim("auth_time", at(-fiveMinutes-skew)),
			check: func(t *testing.T, id *oidcclient.Identity) {
				t.Helper()
				assert.Equal(t, testNow.Add(-fiveMinutes-skew), id.AuthTime)
			}},
		{name: "max_age, in the future", err: oidcclient.ErrIDTokenAuthTime, opts: oidcclient.AuthOptions{MaxAge: &fiveMinutes}, setup: setClaim("auth_time", at(skew+time.Second))},
		{name: "max_age 0, fresh", opts: oidcclient.AuthOptions{MaxAge: &zero}, setup: setClaim("auth_time", at(-skew))},
		{name: "max_age 0, stale", err: oidcclient.ErrIDTokenAuthTime, opts: oidcclient.AuthOptions{MaxAge: &zero}, setup: setClaim("auth_time", at(-skew-time.Second))},
		{name: "no max_age, absent", setup: setClaim("auth_time", nil)},
		{name: "no max_age, future", err: oidcclient.ErrIDTokenAuthTime, setup: setClaim("auth_time", at(skew+time.Second))},
		{name: "not a number", err: oidcclient.ErrIDTokenMalformed, opts: oidcclient.AuthOptions{MaxAge: &fiveMinutes}, setup: setClaim("auth_time", "yesterday")},
	})
}

// TestIDTokenACR checks decision D4: with acr_values sent, the acr claim
// is REQUIRED and one of them.
func TestIDTokenACR(t *testing.T) {
	t.Parallel()

	requested := oidcclient.AuthOptions{ACRValues: []string{"urn:acr:gold", "urn:acr:silver"}}

	runIDCases(t, []idCase{
		{name: "one of the requested", opts: requested, setup: setClaim("acr", "urn:acr:silver"), check: func(t *testing.T, id *oidcclient.Identity) {
			t.Helper()
			assert.Equal(t, "urn:acr:silver", id.ACR)
		}},
		{name: "another class", err: oidcclient.ErrIDTokenACR, opts: requested, setup: setClaim("acr", "urn:acr:bronze")},
		{name: "missing", err: oidcclient.ErrIDTokenACR, opts: requested, setup: setClaim("acr", nil)},
		{name: "not requested", setup: setClaim("acr", "0")},
		{name: "not a string", err: oidcclient.ErrIDTokenMalformed, opts: requested, setup: setClaim("acr", 1)},
	})
}

// TestIDTokenAccessTokenHash checks at_hash (Core §3.1.3.8, §3.2.2.9).
func TestIDTokenAccessTokenHash(t *testing.T) {
	t.Parallel()

	runIDCases(t, []idCase{
		{name: "absent", setup: setClaim("at_hash", nil)},
		{name: "wrong", err: oidcclient.ErrAccessTokenHash, setup: setClaim("at_hash", leftHalfHash(jose.RS256, "something else"))},
		{name: "full hash instead of left half", err: oidcclient.ErrAccessTokenHash, setup: setClaim("at_hash", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))},
		{name: "access token substituted", err: oidcclient.ErrAccessTokenHash, setup: func(op *fakeOP) {
			op.claimsHook = func(_ *grant, claims map[string]any) { claims["at_hash"] = leftHalfHash(jose.RS256, testAccessToken) }
			op.accessToken = "attacker-access-token"
		}},
		{name: "ES384 uses SHA-384", setup: signWith(keyEC(jose.ES384, "k"))},
		{name: "EdDSA uses SHA-512", setup: signWith(keyEd("k"))},
		{name: "EdDSA with a SHA-256 at_hash", err: oidcclient.ErrAccessTokenHash, setup: func(op *fakeOP) {
			signWith(keyEd("k"))(op)
			op.claimsHook = func(_ *grant, claims map[string]any) { claims["at_hash"] = leftHalfHash(jose.RS256, testAccessToken) }
		}},
	})
}
