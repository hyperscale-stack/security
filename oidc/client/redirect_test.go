// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"strconv"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wellKnown is the discovery path of a root issuer.
const wellKnown = "/.well-known/openid-configuration"

// maxRedirects returns a Config mutator allowing n redirects.
func maxRedirects(n int) func(*oidcclient.Config) {
	return func(cfg *oidcclient.Config) { cfg.Outbound.MaxRedirects = n }
}

// impostor returns an OP on another origin than honest's whose discovery
// document claims honest's issuer, with its own endpoints and keys — what
// OpenID Connect Discovery 1.0 §7.2 warns about.
func impostor(t *testing.T, honest *fakeOP) *fakeOP {
	t.Helper()

	evil := newFakeOP(t)
	evil.set(func(op *fakeOP) {
		op.issuer = honest.issuer
		op.metadata = op.defaultMetadata()
		op.signer = keyEvil("evil-1")
		op.jwks = []jose.JSONWebKey{op.signer.jwk()}
	})

	return evil
}

// TestDiscoveryRedirectStaysOnTheIssuerOrigin checks that the discovery
// request never follows a redirect to another origin, whatever
// MaxRedirects allows: the document is only trusted through TLS to the
// issuer (Discovery §4.3, §7.2), so another origin would get its endpoints
// and keys trusted by writing the expected issuer string.
func TestDiscoveryRedirectStaysOnTheIssuerOrigin(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 5} {
		t.Run("MaxRedirects "+strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()

			honest := newFakeOP(t)
			evil := impostor(t, honest)
			honest.set(func(op *fakeOP) { op.redirects = map[string]string{wellKnown: evil.srv.URL + wellKnown} })

			_, err := oidcclient.New(context.Background(), honest.config(maxRedirects(n)))
			require.ErrorIs(t, err, oidcclient.ErrDiscovery)
			require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
			assert.Zero(t, evil.hitCount(wellKnown), "the other origin is never contacted")
		})
	}

	t.Run("after a same-origin hop", func(t *testing.T) {
		t.Parallel()

		honest := newFakeOP(t)
		evil := impostor(t, honest)
		honest.set(func(op *fakeOP) {
			op.redirects = map[string]string{
				wellKnown:         "/v2" + wellKnown,
				"/v2" + wellKnown: evil.srv.URL + wellKnown,
			}
		})

		_, err := oidcclient.New(context.Background(), honest.config(maxRedirects(5)))
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
		assert.Equal(t, 1, honest.hitCount("/v2"+wellKnown), "the same-origin hop is followed")
		assert.Zero(t, evil.hitCount(wellKnown))
	})
}

// TestDiscoveryRedirectWithinTheIssuerOrigin checks that MaxRedirects keeps
// its meaning on the issuer's origin: same-origin hops are followed up to
// the limit, never beyond, and not at all by default.
func TestDiscoveryRedirectWithinTheIssuerOrigin(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		redirects func(op *fakeOP) map[string]string
		max       int
		ok        bool
	}{
		"relative location": {
			redirects: func(*fakeOP) map[string]string { return map[string]string{wellKnown: "/v2" + wellKnown} },
			max:       1, ok: true,
		},
		"absolute location": {
			redirects: func(op *fakeOP) map[string]string {
				return map[string]string{wellKnown: op.srv.URL + "/v2" + wellKnown}
			},
			max: 1, ok: true,
		},
		"two hops within the limit": {
			redirects: func(*fakeOP) map[string]string {
				return map[string]string{wellKnown: "/v2" + wellKnown, "/v2" + wellKnown: "/v3" + wellKnown}
			},
			max: 2, ok: true,
		},
		"two hops beyond the limit": {
			redirects: func(*fakeOP) map[string]string {
				return map[string]string{wellKnown: "/v2" + wellKnown, "/v2" + wellKnown: "/v3" + wellKnown}
			},
			max: 1,
		},
		"no redirect by default": {
			redirects: func(*fakeOP) map[string]string { return map[string]string{wellKnown: "/v2" + wellKnown} },
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.redirects = tc.redirects(op) })

			c, err := oidcclient.New(context.Background(), op.config(maxRedirects(tc.max)))
			if !tc.ok {
				require.ErrorIs(t, err, oidcclient.ErrDiscovery)
				require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)

				return
			}

			require.NoError(t, err)

			id, err := op.login(t, c)
			require.NoError(t, err)
			assert.Equal(t, testSubject, id.Subject)
		})
	}
}

// TestKeySetRedirectStaysOnTheJWKSOrigin checks that the JWK Set request
// never follows a redirect to another origin than the jwks_uri's, whatever
// MaxRedirects allows: the keys of an ID Token come from the jwks_uri the
// issuer's metadata names (Discovery §3), not from wherever it redirects.
func TestKeySetRedirectStaysOnTheJWKSOrigin(t *testing.T) {
	t.Parallel()

	t.Run("to another origin", func(t *testing.T) {
		t.Parallel()

		honest := newFakeOP(t)
		evil := impostor(t, honest)
		honest.set(func(op *fakeOP) {
			op.signer = keyEvil("evil-1") // what the other origin's keys verify
			op.redirects = map[string]string{"/jwks": evil.srv.URL + "/jwks"}
		})

		id, err := honest.login(t, honest.client(t, maxRedirects(5)))
		require.ErrorIs(t, err, oidcclient.ErrKeySet)
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
		assert.Nil(t, id)
		assert.Zero(t, evil.hitCount("/jwks"), "the other origin is never contacted")
	})

	t.Run("from another jwks_uri origin back to the issuer's", func(t *testing.T) {
		t.Parallel()

		honest := newFakeOP(t)
		keys := newFakeOP(t)
		keys.set(func(op *fakeOP) { op.redirects = map[string]string{"/jwks": honest.srv.URL + "/jwks"} })
		honest.set(func(op *fakeOP) { op.metadata["jwks_uri"] = keys.srv.URL + "/jwks" })

		_, err := honest.login(t, honest.client(t, maxRedirects(5)))
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed, "pinned to the jwks_uri's origin, not the issuer's")
		assert.Zero(t, honest.hitCount("/jwks"))
	})
}

// TestKeySetRedirectWithinTheJWKSOrigin checks that a same-origin redirect
// of the JWK Set is followed when MaxRedirects allows it.
func TestKeySetRedirectWithinTheJWKSOrigin(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) {
		op.metadata["jwks_uri"] = op.srv.URL + "/keys"
		op.redirects = map[string]string{"/keys": "/jwks"}
	})

	id, err := op.login(t, op.client(t, maxRedirects(1)))
	require.NoError(t, err)
	assert.Equal(t, testSubject, id.Subject)
	assert.Equal(t, 1, op.hitCount("/keys"))
	assert.Equal(t, 1, op.hitCount("/jwks"))
}

// TestKeySetOnAnotherOriginThanTheIssuer checks that a jwks_uri on another
// origin than the issuer — Google's layout — keeps working: the pin is the
// origin of the URL requested, not the issuer's.
func TestKeySetOnAnotherOriginThanTheIssuer(t *testing.T) {
	t.Parallel()

	honest := newFakeOP(t)
	keys := newFakeOP(t)
	keys.set(func(op *fakeOP) { op.jwks = []jose.JSONWebKey{honest.signer.jwk()} })
	honest.set(func(op *fakeOP) { op.metadata["jwks_uri"] = keys.srv.URL + "/jwks" })

	id, err := honest.login(t, honest.client(t))
	require.NoError(t, err)
	assert.Equal(t, testSubject, id.Subject)
	assert.Equal(t, 1, keys.hitCount("/jwks"))
	assert.Zero(t, honest.hitCount("/jwks"))
}
