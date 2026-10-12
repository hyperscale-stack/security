// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwksJSON marshals the public keys into an RFC 7517 JWKS document.
func jwksJSON(t *testing.T, keys ...jose.JSONWebKey) []byte {
	t.Helper()

	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	require.NoError(t, err)

	return b
}

func sigKey(pub jwtsec.PublicKey) jose.JSONWebKey {
	return jose.JSONWebKey{Key: pub.Key, KeyID: pub.KeyID, Algorithm: string(pub.Algorithm), Use: "sig"}
}

func TestSignerAccessors(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)
	signer := mustSigner(t, priv)

	assert.Equal(t, jwtsec.ES256, signer.Algorithm())
	assert.Equal(t, "ec-1", signer.KeyID())
}

func TestAlgorithmString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "RS256", jwtsec.RS256.String())
	assert.Equal(t, "EdDSA", jwtsec.EdDSA.String())
}

func TestStaticJWKSActive(t *testing.T) {
	t.Parallel()

	priv, pub := genRSA(t)

	withSigner, err := jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}, priv).KeySet(context.Background())
	require.NoError(t, err)

	active, ok := withSigner.Active()
	require.True(t, ok)
	assert.Equal(t, priv.KeyID, active.KeyID)

	// A verifier-only key set has no active signing key.
	verifierOnly, err := jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub}).KeySet(context.Background())
	require.NoError(t, err)

	_, ok = verifierOnly.Active()
	assert.False(t, ok)
}

func TestWithAllowedAlgorithmsPanicsOnEmpty(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { jwtsec.WithAllowedAlgorithms() })
}

func TestAudienceJSON(t *testing.T) {
	t.Parallel()

	marshal := func(a jwtsec.Audience) string {
		b, err := a.MarshalJSON()
		require.NoError(t, err)

		return string(b)
	}

	assert.Equal(t, "null", marshal(jwtsec.Audience{}))
	assert.Equal(t, `"solo"`, marshal(jwtsec.Audience{"solo"}))
	assert.Equal(t, `["a","b"]`, marshal(jwtsec.Audience{"a", "b"}))

	var single jwtsec.Audience
	require.NoError(t, single.UnmarshalJSON([]byte(`"one"`)))
	assert.Equal(t, jwtsec.Audience{"one"}, single)

	var multi jwtsec.Audience
	require.NoError(t, multi.UnmarshalJSON([]byte(`["x","y"]`)))
	assert.Equal(t, jwtsec.Audience{"x", "y"}, multi)

	var empty jwtsec.Audience
	require.NoError(t, empty.UnmarshalJSON(nil))
	assert.Nil(t, empty)

	var bad jwtsec.Audience
	assert.Error(t, bad.UnmarshalJSON([]byte(`{bad`)))
}

func TestNumericDate(t *testing.T) {
	t.Parallel()

	// A nil NumericDate yields the zero time.
	var nilDate *jwtsec.NumericDate
	assert.True(t, nilDate.Time().IsZero())

	ts := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, ts, jwtsec.NewNumericDate(ts).Time())

	// JSON round trip through an integer UNIX timestamp.
	b, err := jwtsec.NewNumericDate(ts).MarshalJSON()
	require.NoError(t, err)

	var decoded jwtsec.NumericDate
	require.NoError(t, decoded.UnmarshalJSON(b))
	assert.Equal(t, ts.Unix(), decoded.Time().Unix())

	assert.Error(t, decoded.UnmarshalJSON([]byte(`"not-a-number"`)))
}
