// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The RS256 key of the root issuer before and after a rotation.
var (
	oldRS256 = func() jwtsec.PrivateKey { return rsaKey(0, jwtsec.RS256, "root-rs256") }
	newRS256 = func() jwtsec.PrivateKey { return rsaKey(11, jwtsec.RS256, "root-rs256-2") }
)

// rotatedRing is the root ring with its RS256 signing key replaced by
// signing, and published as further verification keys.
func rotatedRing(t *testing.T, signing jwtsec.PrivateKey, published ...jwtsec.PrivateKey) oidcprovider.KeyRing {
	t.Helper()

	ring := rootRing()
	ring.Signing[0] = signing
	ring.Published = publicKeys(t, published...)

	return ring
}

// TestDocumentedRotationIsInvisibleToTheClient follows the rotation the
// provider documents (KeyRing, OpenID Connect Core §10.1.1) with our
// client: (1) publish the next key and wait for relying parties to refresh
// their cached sets — an hour for our client (its key-set TTL); (2) sign
// with it, the former key still published; (3) drop the former key once
// what it signed has expired. Every login succeeds, and the client never
// needs an unknown-kid refresh.
func TestDocumentedRotationIsInvisibleToTheClient(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())
	jwks := o.paths(o.base).JWKS

	_, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, o.hits(jwks))

	// (1) The next key is published.
	o.keys.set(o.base, rotatedRing(t, oldRS256(), newRS256()))
	o.clock.advance(time.Hour + time.Minute)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)
	assert.Equal(t, 2, o.hits(jwks), "the expired cache refreshed, learning the next key")

	// (2) The next key signs; the former one stays published.
	o.keys.set(o.base, rotatedRing(t, newRS256(), oldRS256()))

	id, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	header, _ := jwsParts(t, id.Tokens.IDToken.Reveal())
	assert.Equal(t, "root-rs256-2", header["kid"])
	assert.Equal(t, 2, o.hits(jwks), "no unknown-kid refresh was needed")

	// (3) The former key is dropped.
	o.clock.advance(oidcprovider.DefaultIDTokenTTL)
	o.keys.set(o.base, rotatedRing(t, newRS256()))

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)
}

// TestAbruptRotationWithinTheRefreshInterval: a key that signs without
// having been published first is unknown to the client's cache; the client
// refetches the set on an unknown kid, but at most once per 10 s — a login
// right after its last fetch fails closed (ErrUnknownSigningKey), the next
// one after the interval succeeds. Publish keys before using them.
func TestAbruptRotationWithinTheRefreshInterval(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())

	_, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	o.keys.set(o.base, rotatedRing(t, newRS256(), oldRS256()))

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey)

	o.clock.advance(11 * time.Second)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)
}

// TestKeyWithdrawalWindow measures how long our client keeps accepting a
// key the provider withdrew — a leaked key, say: ID Tokens forged with it
// verify until the client's cached key set is an hour old, and fail after
// (OpenID Connect Core §10.1.1). Building a new Client empties the cache at
// once.
func TestKeyWithdrawalWindow(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())

	_, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	// The provider withdraws the leaked key and signs with a new one; the
	// attacker re-signs the ID Tokens with the leaked key.
	o.keys.set(o.base, rotatedRing(t, newRS256()))
	o.tamperTokenResponse(o.base, func(resp map[string]any) {
		resp["id_token"] = resign(t, resp["id_token"].(string), "RS256", rootKey(), func(h map[string]any) { h["kid"] = "root-rs256" }, nil) //nolint:forcetypeassert // test
	})

	o.clock.advance(30 * time.Minute)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err, "within the cache lifetime the withdrawn key still verifies")

	_, err = o.login(t, o.rp(t, o.basic()), oidcclient.AuthOptions{})
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey, "a new Client fetches the current set")

	o.clock.advance(31 * time.Minute)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey, "after an hour the cached set is refreshed")
}
