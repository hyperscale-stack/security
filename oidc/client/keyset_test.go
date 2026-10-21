// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyRotation checks Core §10.1.1: a token signed with a kid the
// cached set does not hold makes the Client fetch the set again.
func TestKeyRotation(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)
	assert.Equal(t, 1, op.hitCount("/jwks"))

	op.set(func(op *fakeOP) {
		op.jwks = []jose.JSONWebKey{op.signer.jwk(), keyRSAB("rsa-2").jwk()}
		op.signer = keyRSAB("rsa-2")
	})

	op.clock.Advance(11 * time.Second)

	id, err := op.login(t, c)
	require.NoError(t, err)
	assert.Equal(t, testSubject, id.Subject)
	assert.Equal(t, 2, op.hitCount("/jwks"))
}

// TestUnknownKidIsRateLimited checks that unknown kids cannot drive
// unbounded fetches: one refresh, then none for ten seconds.
func TestUnknownKidIsRateLimited(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) { op.signer.kid = "ghost" })
	c := op.client(t)

	_, err := op.login(t, c)
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey)
	assert.Equal(t, 1, op.hitCount("/jwks"), "the first use fetched the set; the refresh is rate limited")

	op.clock.Advance(9 * time.Second)

	_, err = op.login(t, c)
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey)
	assert.Equal(t, 1, op.hitCount("/jwks"), "no fetch within ten seconds")

	op.clock.Advance(time.Second)

	_, err = op.login(t, c)
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey)
	assert.Equal(t, 2, op.hitCount("/jwks"), "one fetch once ten seconds passed")
}

// TestKeyRefreshSingleFlight checks that concurrent logins meeting a new
// kid share one fetch, and that every one of them succeeds.
func TestKeyRefreshSingleFlight(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)

	const logins = 50

	type pending struct {
		ar   *oidcclient.AuthRequest
		code string
	}

	ready := make([]pending, logins)
	for i := range ready {
		ar, code := op.begin(t, c, oidcclient.AuthOptions{})
		ready[i] = pending{ar, code}
	}

	gate := make(chan struct{})
	entered := make(chan struct{}, 1)

	op.set(func(op *fakeOP) {
		op.jwks = []jose.JSONWebKey{op.signer.jwk(), keyRSAB("rsa-2").jwk()}
		op.signer = keyRSAB("rsa-2")
		op.jwksGate = gate
		op.jwksEntered = entered
	})
	op.clock.Advance(11 * time.Second)

	var (
		wg   sync.WaitGroup
		wins atomic.Int64
	)

	for _, p := range ready {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, err := c.Complete(context.Background(), callbackFor(p.ar, p.code)); err == nil {
				wins.Add(1)
			}
		}()
	}

	receive(t, entered)
	time.Sleep(50 * time.Millisecond) // let the other logins reach the in-flight fetch
	close(gate)
	wg.Wait()

	assert.Equal(t, int64(logins), wins.Load(), "every login succeeds")
	assert.Equal(t, 2, op.hitCount("/jwks"), "one fetch for all of them")
}

// TestUnknownKidRefreshCancelled checks that a caller giving up while the
// refresh triggered by an unknown kid is in flight gets its context error.
func TestUnknownKidRefreshCancelled(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)

	gate := make(chan struct{})
	entered := make(chan struct{}, 1)

	op.set(func(op *fakeOP) {
		op.signer = keyRSAB("rsa-2")
		op.jwks = []jose.JSONWebKey{op.signer.jwk()}
		op.jwksGate = gate
		op.jwksEntered = entered
	})
	op.clock.Advance(11 * time.Second)

	ar, code := op.begin(t, c, oidcclient.AuthOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		_, err := c.Complete(ctx, callbackFor(ar, code))
		done <- err
	}()

	receive(t, entered)
	cancel()
	require.ErrorIs(t, receive(t, done), context.Canceled)
	close(gate)
}

// TestKeySetTTL checks that a key the provider stopped publishing stops
// being accepted once the cached set is an hour old.
func TestKeySetTTL(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)

	op.set(func(op *fakeOP) { op.jwks = []jose.JSONWebKey{keyRSAB("rsa-2").jwk()} })

	op.clock.Advance(5*time.Minute - time.Second)

	_, err = op.login(t, c)
	require.NoError(t, err, "still cached")

	op.clock.Advance(time.Second)

	_, err = op.login(t, c)
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey, "refreshed after five minutes: rsa-1 is gone")
}

// TestKeySetStaleOnFailure checks that a failing JWK Set endpoint does not
// break logins with known keys for up to 24 hours, then fails closed.
func TestKeySetStaleOnFailure(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)

	op.set(func(op *fakeOP) { op.jwksStatus = http.StatusInternalServerError })

	op.clock.Advance(2 * time.Hour)

	_, err = op.login(t, c)
	require.NoError(t, err, "stale keys serve while the endpoint fails")

	op.clock.Advance(22*time.Hour + time.Second)

	_, err = op.login(t, c)
	require.ErrorIs(t, err, oidcclient.ErrKeySet, "older than 24 hours: fail closed")
}

// TestFailingKeySetIsRateLimited checks that a failing jwks_uri — possibly
// a hostile tenant's — is fetched at most once per 10 seconds, whatever the
// number of logins.
func TestFailingKeySetIsRateLimited(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) { op.jwksStatus = http.StatusInternalServerError })
	c := op.client(t)

	for range 20 {
		_, err := op.login(t, c)
		require.ErrorIs(t, err, oidcclient.ErrKeySet)
	}

	assert.Equal(t, 1, op.hitCount("/jwks"))

	op.clock.Advance(11 * time.Second)

	_, err := op.login(t, c)
	require.ErrorIs(t, err, oidcclient.ErrKeySet)
	assert.Equal(t, 2, op.hitCount("/jwks"))
}

// TestNoRefetchOnBadSignature checks that a bad signature under a known
// kid never triggers a fetch.
func TestNoRefetchOnBadSignature(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)

	op.set(func(op *fakeOP) { op.signer = keyEvil("rsa-1") })
	op.clock.Advance(time.Minute)

	_, err = op.login(t, c)
	require.ErrorIs(t, err, oidcclient.ErrIDTokenSignature)
	assert.Equal(t, 1, op.hitCount("/jwks"))
}

// TestKidlessRotation checks that a provider with a single kid-less key
// can rotate it: a token no cached key verifies triggers one refresh.
func TestKidlessRotation(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) {
		op.signer.kid = ""
		op.jwks = []jose.JSONWebKey{op.signer.jwk()}
	})
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)

	op.set(func(op *fakeOP) {
		op.signer = keyRSAB("")
		op.jwks = []jose.JSONWebKey{op.signer.jwk()}
	})
	op.clock.Advance(11 * time.Second)

	_, err = op.login(t, c)
	require.NoError(t, err)
	assert.Equal(t, 2, op.hitCount("/jwks"))
}

// TestKeyFetchSurvivesCancellation checks that a caller giving up does not
// abort the shared fetch: the next login finds the key without fetching.
func TestKeyFetchSurvivesCancellation(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	op.set(func(op *fakeOP) {
		op.jwksGate = gate
		op.jwksEntered = entered
	})
	c := op.client(t)

	ar, code := op.begin(t, c, oidcclient.AuthOptions{})
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		_, err := c.Complete(ctx, callbackFor(ar, code))
		done <- err
	}()

	receive(t, entered)
	cancel()
	require.ErrorIs(t, receive(t, done), context.Canceled)

	close(gate)

	require.Eventually(t, func() bool {
		_, err := op.login(t, c)

		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, 1, op.hitCount("/jwks"), "the cancelled caller's fetch completed and was cached")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestKeySetParsing checks the JWK Set handling: RFC 7517 §5 ignores keys
// it cannot use, Discovery §3 forbids private and symmetric keys (the set is
// refused), and the document is parsed strictly and bounded.
func TestKeySetParsing(t *testing.T) {
	t.Parallel()

	publicJSON := func(op *fakeOP) map[string]any {
		raw, err := json.Marshal(op.signer.jwk())
		require.NoError(op.t, err)

		var m map[string]any
		require.NoError(op.t, json.Unmarshal(raw, &m))

		return m
	}

	set := func(keys ...any) []byte {
		b, err := json.Marshal(map[string]any{"keys": keys})
		if err != nil {
			panic(err)
		}

		return b
	}

	cases := map[string]struct {
		setup func(op *fakeOP)
		err   error
	}{
		"unknown key type skipped": {setup: func(op *fakeOP) {
			op.jwksRaw = set(map[string]any{"kty": "AKP", "alg": "ML-DSA-65", "kid": "pq", "pub": "AAAA"}, publicJSON(op))
		}},
		"unsupported curve skipped": {setup: func(op *fakeOP) {
			op.jwksRaw = set(map[string]any{"kty": "EC", "crv": "secp256k1", "kid": "k1", "x": "AA", "y": "AA"}, publicJSON(op))
		}},
		"malformed x5t skipped": {setup: func(op *fakeOP) {
			bad := publicJSON(op)
			bad["kid"] = "other"
			bad["x5t"] = "!!"
			op.jwksRaw = set(bad, publicJSON(op))
		}},
		"jwk-set content type": {setup: func(op *fakeOP) { op.jwksType = "application/jwk-set+json" }},
		"private RSA key refuses the set": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) {
			private := publicJSON(op)
			private["kid"] = "leaked"
			private["d"] = "AAAA"
			op.jwksRaw = set(private, publicJSON(op))
		}},
		"symmetric key refuses the set": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) {
			op.jwksRaw = set(map[string]any{"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"}, publicJSON(op))
		}},
		"malformed private member refuses the set": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) {
			private := publicJSON(op)
			private["kid"] = "leaked"
			private["p"] = 42
			op.jwksRaw = set(private, publicJSON(op))
		}},
		"too many keys": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) {
			keys := make([]any, 101)
			for i := range keys {
				keys[i] = publicJSON(op)
			}
			op.jwksRaw = set(keys...)
		}},
		"no keys member": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) { op.jwksRaw = []byte(`{"k":[]}`) }},
		"duplicate keys member": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) {
			op.jwksRaw = []byte(`{"keys":[],"keys":[]}`)
		}},
		"case-variant member in a key": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) {
			k := publicJSON(op)
			k["KID"] = "x"
			op.jwksRaw = set(k)
		}},
		"html content type": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) { op.jwksType = "text/html" }},
		"server error":      {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) { op.jwksStatus = http.StatusBadGateway }},
		"empty set":         {err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) { op.jwksRaw = []byte(`{"keys":[]}`) }},
		"key not an object": {err: oidcclient.ErrKeySet, setup: func(op *fakeOP) { op.jwksRaw = []byte(`{"keys":[1]}`) }},
		"oversized RSA key skipped": {err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			huge := make([]byte, 1100)
			huge[0], huge[len(huge)-1] = 0x80, 0x01
			op.jwksRaw = set(map[string]any{"kty": "RSA", "kid": "rsa-1", "alg": "RS256", "n": b64(huge), "e": "AQAB"})
		}},
		"key declaring an encryption algorithm skipped": {err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			k := publicJSON(op)
			k["alg"] = "RSA-OAEP-256"
			delete(k, "use")
			op.jwksRaw = set(k)
		}},
		"malformed key_ops skipped": {err: oidcclient.ErrUnknownSigningKey, setup: func(op *fakeOP) {
			k := publicJSON(op)
			k["key_ops"] = "verify"
			op.jwksRaw = set(k)
		}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(tc.setup)
			c := op.client(t)

			id, err := op.login(t, c)
			if tc.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tc.err)
			assert.Nil(t, id)
		})
	}

	t.Run("oversized set", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) {
			k := publicJSON(op)
			k["padding"] = strings.Repeat("p", 8192)
			op.jwksRaw = set(k)
		})
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.Outbound.MaxResponseBytes = 4096 })

		_, err := op.login(t, c)
		require.ErrorIs(t, err, oidcclient.ErrKeySet)
	})
}
