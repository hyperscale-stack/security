// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCurveAlgorithm(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ES256, curveAlgorithm(elliptic.P256()))
	assert.Equal(t, ES384, curveAlgorithm(elliptic.P384()))
	assert.Equal(t, ES512, curveAlgorithm(elliptic.P521()))
	assert.Equal(t, Algorithm(""), curveAlgorithm(elliptic.P224()), "no JWS algorithm for P-224")
}

// TestVerifierReportsRefreshFailures pins that an unknown kid whose
// refresh fails without a usable set is a key set outage, not an invalid
// token.
func TestVerifierReportsRefreshFailures(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := NewSigner(PrivateKey{KeyID: "k", Algorithm: ES256, Key: priv})
	require.NoError(t, err)

	tok, err := signer.Sign(context.Background(), map[string]any{"sub": "a", "exp": 4102444800})
	require.NoError(t, err)

	// A provider that can refresh: an empty set, then a failing refresh,
	// which the verifier attempts once.
	keys := NewMockJWKSProvider(t)
	keys.EXPECT().KeySet(mock.Anything).Return(&staticKeySet{}, nil).Once()

	refresher := NewMockkeyRefresher(t)
	refresher.EXPECT().refreshKeySet(mock.Anything).Return(nil, errors.New("upstream down")).Once()

	p := struct {
		*MockJWKSProvider
		*MockkeyRefresher
	}{keys, refresher}

	_, err = NewVerifier(p).Verify(context.Background(), tok, nil)
	require.ErrorIs(t, err, ErrKeySetUnavailable)
}

// FuzzParseJWKS checks the JWK Set parser on hostile documents: it never
// panics, its errors stay short (review F1), and every key it keeps is
// public material that passes PublicKey.Validate for its algorithm — an
// RSA key without alg for RS256, its algorithm left for the verifier to
// bind.
func FuzzParseJWKS(f *testing.F) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(f, err)

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(f, err)

	doc, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &ec.PublicKey, KeyID: "ec", Algorithm: "ES256", Use: "sig"},
		{Key: &rsaKey.PublicKey, KeyID: "rsa"},
		{Key: edPub, KeyID: "ed"},
		{Key: rsaKey, KeyID: "private", Algorithm: "RS256"},
		{Key: []byte(strings.Repeat("s", 32)), KeyID: "oct", Algorithm: "HS256"},
	}})
	require.NoError(f, err)

	for _, seed := range []string{
		string(doc), `{"keys":[]}`, `{"keys":[{"kty":"XYZ"}]}`, `{"keys":[1]}`, `{"keys":1e999}`,
		`{"keys":[],"x":1` + strings.Repeat("0", 400) + `}`, `{"keys":[{"kty":"EC","crv":"P-256","x":1,"y":2}]}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		keys, ignored, err := parseJWKS(data)
		if err != nil {
			require.Less(t, len(err.Error()), 400, "a short error")

			return
		}

		require.LessOrEqual(t, len(keys)+ignored, maxJWKSKeys)

		for _, k := range keys {
			require.True(t, k.publicMaterial(), "public material only")

			if k.impliedRSA {
				require.Empty(t, k.Algorithm, "bound by the verifier")
				require.NoError(t, PublicKey{Algorithm: RS256, Key: k.Key}.Validate())

				continue
			}

			require.NoError(t, k.Validate())
		}
	})
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}

// TestOriginOf pins the RFC 6454 §4 origin the redirect pin compares
// (review F6): scheme, host and port, with the scheme's default port,
// ASCII-only case folding and canonical IP literals.
func TestOriginOf(t *testing.T) {
	t.Parallel()

	same := map[string][2]string{
		"default https port":      {"https://idp.example/a", "https://idp.example:443/b"},
		"default http port":       {"http://idp.example/a", "http://idp.example:80/"},
		"case of scheme and host": {"HTTPS://IDP.Example/a", "https://idp.example/b"},
		"upper-case A and Z":      {"https://ZA.example/a", "https://za.example/b"},
		"IPv6 literal forms":      {"https://[::1]:8443/a", "https://[0:0:0:0:0:0:0:1]:8443/b"},
		"IPv4 default port":       {"https://127.0.0.1/a", "https://127.0.0.1:443/b"},
		"port with a leading 0":   {"https://idp.example:8443/a", "https://idp.example:08443/b"},
	}

	for name, pair := range same {
		assert.Equal(t, originOf(mustURL(t, pair[0])), originOf(mustURL(t, pair[1])), name)
	}

	different := map[string][2]string{
		"scheme":                   {"https://idp.example/a", "http://idp.example/a"},
		"scheme on the same port":  {"https://idp.example:8443/a", "http://idp.example:8443/a"},
		"port":                     {"https://idp.example/a", "https://idp.example:8443/a"},
		"http on port 443":         {"http://idp.example:443/a", "https://idp.example/a"},
		"host":                     {"https://idp.example/a", "https://evil.example/a"},
		"suffix":                   {"https://idp.example/a", "https://idp.example.evil/a"},
		"non-ASCII case variant":   {"https://keys.example/a", "https://\u212aeys.example/a"},
		"IPv4-mapped IPv6 literal": {"https://127.0.0.1/a", "https://[::ffff:127.0.0.1]/a"},
	}

	for name, pair := range different {
		assert.NotEqual(t, originOf(mustURL(t, pair[0])), originOf(mustURL(t, pair[1])), name)
	}
}

// TestPinRedirects pins the CheckRedirect of the pinned client (review
// F6): the client's own policy decides first — net/http's limit of 10
// redirects without one — then every hop must stay on the JWK Set URL's
// origin; the client given is not modified.
func TestPinRedirects(t *testing.T) {
	t.Parallel()

	request := func(raw string) *http.Request { return &http.Request{URL: mustURL(t, raw)} }
	first := request("https://idp.example/jwks")

	plain := &http.Client{}
	check := pinRedirects(plain, first.URL).CheckRedirect

	require.Nil(t, plain.CheckRedirect, "the client given is not modified")
	require.NoError(t, check(request("https://IDP.example:443/v2/jwks"), []*http.Request{first}))
	require.ErrorIs(t, check(request("https://evil.example/jwks"), []*http.Request{first}), outbound.ErrRedirectNotAllowed)
	require.ErrorIs(t, check(request("https://evil.example/jwks"), []*http.Request{first, request("https://idp.example/v2")}),
		outbound.ErrRedirectNotAllowed, "every hop is compared with the JWK Set URL")

	nine, ten := make([]*http.Request, 9), make([]*http.Request, 10)
	for i := range ten {
		ten[i] = first

		if i < len(nine) {
			nine[i] = first
		}
	}

	require.NoError(t, check(request("https://idp.example/jwks"), nine))
	require.ErrorIs(t, check(request("https://idp.example/jwks"), ten), outbound.ErrRedirectNotAllowed, "net/http's limit")

	policy := errors.New("hop limit")
	own := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return policy }}
	refuse := pinRedirects(own, first.URL).CheckRedirect
	require.Equal(t, policy, refuse(request("https://idp.example/v2"), []*http.Request{first}),
		"the client's policy decides first, its error returned as is (net/http compares it with ErrUseLastResponse)")

	allowAll := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	require.NoError(t, pinRedirects(allowAll, first.URL).CheckRedirect(request("https://idp.example/jwks"), ten),
		"the client's own policy replaces net/http's limit")
}
