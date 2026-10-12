// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	clientmemory "github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProviderStorageFailuresReachTheClient fails the provider's storage
// at each step of a login: the authorization endpoint answers a redirected
// server_error the client returns as an authorization error, the token
// endpoint a 500 server_error the client returns as a failed token request
// (it reads error bodies of 400 and 401 answers only, RFC 6749 §5.2),
// UserInfo a 500 — never an identity or claims.
func TestProviderStorageFailuresReachTheClient(t *testing.T) {
	t.Parallel()

	t.Run("saving the code", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		o.store.mu.Lock()
		o.store.failSave = errStorageDown
		o.store.mu.Unlock()

		id, err := o.login(t, o.rp(t, o.basic()), oidcclient.AuthOptions{})
		requireAuthorizationError(t, err, "server_error")
		assert.Nil(t, id)
		assert.Zero(t, o.hits(o.paths(o.base).Token))
	})

	t.Run("saving the tokens", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		o.store.mu.Lock()
		o.store.failPair = errStorageDown
		o.store.mu.Unlock()

		id, err := o.login(t, o.rp(t, o.basic()), oidcclient.AuthOptions{})
		require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint, "a 500 server_error: the client reports the status only")

		var tokErr *oidcclient.TokenError
		assert.NotErrorAs(t, err, &tokErr)
		assert.Nil(t, id)
	})

	t.Run("reading the access token at UserInfo", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		c := o.rp(t, o.basic())

		id, err := o.login(t, c, oidcclient.AuthOptions{})
		require.NoError(t, err)

		o.store.mu.Lock()
		o.store.failLookup = errStorageDown
		o.store.mu.Unlock()

		info, err := c.UserInfo(t.Context(), id)
		require.ErrorIs(t, err, oidcclient.ErrUserInfo)
		assert.Nil(t, info)
	})
}

// downStore is a transaction store whose Consume fails.
type downStore struct{ oidcclient.TransactionStore }

var errTransactionStoreDown = errors.New("transaction store unavailable")

func (downStore) Consume(context.Context, string, string, time.Time) (*oidcclient.Transaction, error) {
	return nil, errTransactionStoreDown
}

// TestTransactionStoreDownAtTheCallback: the relying party's store failing
// at the callback fails the login closed, before the code is redeemed.
func TestTransactionStoreDownAtTheCallback(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic(), func(cfg *oidcclient.Config) { cfg.Store = downStore{clientmemory.New()} })

	id, err := o.login(t, c, oidcclient.AuthOptions{})
	require.ErrorIs(t, err, errTransactionStoreDown)
	assert.Nil(t, id)
	assert.Zero(t, o.hits(o.paths(o.base).Token))
}

// TestTokenResponseLostAfterCommit: the provider issues and stores the
// tokens, then the connection drops before the client reads them. The
// client fails the login without retrying the code — a retry would be a
// replay that revokes them (RFC 6749 §4.1.2) — and the tokens it never
// received are never exposed. The transaction stays consumed: the same
// callback delivered again (the user reloading the page) never reaches the
// token endpoint. The user's next login succeeds.
func TestTokenResponseLostAfterCommit(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())
	token := o.paths(o.base).Token

	o.faults.set(token, rule{drop: true})

	ar, loc := o.begin(t, c, oidcclient.AuthOptions{})

	id, err := c.Complete(t.Context(), callbackOf(loc, ar.Binding))
	require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint)
	assert.Nil(t, id)
	assert.Equal(t, 1, o.hits(token), "the code is redeemed once, never retried")

	o.faults.clear(token)

	id, err = c.Complete(t.Context(), callbackOf(loc, ar.Binding))
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound, "a consumed transaction is never restored")
	assert.Nil(t, id)
	assert.Equal(t, 1, o.hits(token), "the redelivered callback never reaches the token endpoint")

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)
}

// TestTokenEndpointTimeout: a token endpoint that does not answer within
// the client's outbound timeout fails the login within that bound.
func TestTokenEndpointTimeout(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic(), func(cfg *oidcclient.Config) { cfg.Outbound.Timeout = time.Second })
	token := o.paths(o.base).Token

	o.faults.set(token, rule{delay: 3 * time.Second})

	start := time.Now()

	id, err := o.login(t, c, oidcclient.AuthOptions{})
	require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint)
	assert.Nil(t, id)
	assert.Less(t, time.Since(start), 3*time.Second, "bounded by the outbound timeout")
	assert.Equal(t, 1, o.hits(token))
}

// TestJWKSOutage: while the JWK Set endpoint fails, cached keys keep
// verifying; a key the cache lacks cannot be learned — the login fails
// closed — until the endpoint answers again.
func TestJWKSOutage(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())
	jwks := o.paths(o.base).JWKS

	_, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	o.faults.set(jwks, rule{replace: &reply{status: http.StatusInternalServerError, contentType: "text/plain", body: "down"}})

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err, "the cached keys still verify")

	o.keys.set(o.base, rotatedRing(t, newRS256(), oldRS256()))
	o.clock.advance(11 * time.Second)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.ErrorIs(t, err, oidcclient.ErrUnknownSigningKey)

	o.faults.clear(jwks)
	o.clock.advance(11 * time.Second)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err, "the key is learned once the endpoint answers")
}

// TestDiscoveryOutage: a provider whose discovery document fails cannot be
// configured (ErrDiscovery); a Client built before keeps working.
func TestDiscoveryOutage(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())

	o.faults.set(o.paths(o.base).Discovery, rule{replace: &reply{status: http.StatusServiceUnavailable, contentType: "text/plain", body: "down"}})

	_, err := oidcclient.New(t.Context(), o.config(o.basic()))
	require.ErrorIs(t, err, oidcclient.ErrDiscovery)

	_, err = o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)
}
