// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func TestRemoteJWKSFetchAndCache(t *testing.T) {
	t.Parallel()

	_, pub := genRSA(t)
	doc := jwksJSON(t, sigKey(pub))

	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)

	provider := jwtsec.NewRemoteJWKS(srv.URL, jwtsec.WithCacheTTL(time.Hour))

	// First call fetches.
	set, err := provider.KeySet(context.Background())
	require.NoError(t, err)

	got, ok := set.ByKeyID(pub.KeyID)
	require.True(t, ok)
	assert.Equal(t, pub.KeyID, got.KeyID)

	// Second call within the TTL is served from cache — no extra HTTP hit.
	_, err = provider.KeySet(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load(), "second KeySet must hit the cache")
}

func TestRemoteJWKSWithHTTPClient(t *testing.T) {
	t.Parallel()

	_, pub := genEd25519(t)
	doc := jwksJSON(t, sigKey(pub))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)

	provider := jwtsec.NewRemoteJWKS(srv.URL,
		jwtsec.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))

	set, err := provider.KeySet(context.Background())
	require.NoError(t, err)

	_, ok := set.ByKeyID(pub.KeyID)
	assert.True(t, ok)
}

func TestRemoteJWKSFiltersNonSigningKeys(t *testing.T) {
	t.Parallel()

	_, sig := genRSA(t)
	_, enc := genECDSA(t)

	encKey := sigKey(enc)
	encKey.Use = "enc" // not a signing key — must be skipped

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksJSON(t, sigKey(sig), encKey))
	}))
	t.Cleanup(srv.Close)

	set, err := jwtsec.NewRemoteJWKS(srv.URL).KeySet(context.Background())
	require.NoError(t, err)

	_, ok := set.ByKeyID(sig.KeyID)
	assert.True(t, ok, "sig key kept")

	_, ok = set.ByKeyID(enc.KeyID)
	assert.False(t, ok, "enc key filtered out")
}

func TestRemoteJWKSErrors(t *testing.T) {
	t.Parallel()

	t.Run("http error with no cache fails", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		_, err := jwtsec.NewRemoteJWKS(srv.URL).KeySet(context.Background())
		require.Error(t, err)
	})

	t.Run("malformed JSON fails", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		t.Cleanup(srv.Close)

		_, err := jwtsec.NewRemoteJWKS(srv.URL).KeySet(context.Background())
		require.Error(t, err)
	})

	t.Run("empty key set fails", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		t.Cleanup(srv.Close)

		_, err := jwtsec.NewRemoteJWKS(srv.URL).KeySet(context.Background())
		require.Error(t, err)
	})
}

func TestRemoteJWKSStaleCacheFallback(t *testing.T) {
	t.Parallel()

	_, pub := genRSA(t)
	doc := jwksJSON(t, sigKey(pub))

	var fail atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)

			return
		}

		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)

	// TTL 0 forces a refetch on every call.
	provider := jwtsec.NewRemoteJWKS(srv.URL, jwtsec.WithCacheTTL(0))

	// Prime the cache.
	_, err := provider.KeySet(context.Background())
	require.NoError(t, err)

	// Upstream now fails — the stale snapshot must still be returned.
	fail.Store(true)

	set, err := provider.KeySet(context.Background())
	require.NoError(t, err, "stale cache must be served when upstream is down")

	_, ok := set.ByKeyID(pub.KeyID)
	assert.True(t, ok)
}

func TestSignerAccessors(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)
	signer := jwtsec.NewSigner(priv)

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
