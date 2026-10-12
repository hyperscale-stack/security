// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	clientmemory "github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raceCallbacks delivers the callback of one login n times at once,
// spread over replicas, and returns the identities and errors.
func raceCallbacks(t *testing.T, replicas []*oidcclient.Client, cb oidcclient.Callback, n int) ([]*oidcclient.Identity, []error) {
	t.Helper()

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		ids   = make([]*oidcclient.Identity, n)
		errs  = make([]error, n)
	)

	for i := range n {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			ids[i], errs[i] = replicas[i%len(replicas)].Complete(t.Context(), cb)
		}()
	}

	close(start)
	wg.Wait()

	return ids, errs
}

// requireOneWinner requires exactly one identity, every other callback
// failing because the transaction was already consumed.
func requireOneWinner(t *testing.T, ids []*oidcclient.Identity, errs []error) {
	t.Helper()

	winners := 0

	for i, id := range ids {
		if id != nil {
			winners++

			continue
		}

		require.ErrorIs(t, errs[i], oidcclient.ErrTransactionNotFound)
	}

	require.Equal(t, 1, winners, "exactly one callback completes the login")
}

// TestConcurrentCallbacksAcrossReplicas delivers one callback 50 times at
// once to two replicas of the relying party — two Clients sharing the
// transaction store and the transaction keys, as two instances of an
// application: exactly one completes the login, and the provider's token
// endpoint is reached exactly once. Replicas configured with unrelated
// transaction keys fail the login instead of accepting it.
func TestConcurrentCallbacksAcrossReplicas(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	store := clientmemory.New()
	shared := func(cfg *oidcclient.Config) { cfg.Store = store }
	replicas := []*oidcclient.Client{o.rp(t, o.basic(), shared), o.rp(t, o.basic(), shared)}

	ar, loc := o.begin(t, replicas[0], oidcclient.AuthOptions{})

	ids, errs := raceCallbacks(t, replicas, callbackOf(loc, ar.Binding), 50)
	requireOneWinner(t, ids, errs)
	assert.Equal(t, 1, o.hits(o.paths(o.base).Token))

	t.Run("replicas with unrelated keys", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		store := clientmemory.New()
		starting := o.rp(t, o.basic(), func(cfg *oidcclient.Config) { cfg.Store = store })
		completing := o.rp(t, o.basic(), func(cfg *oidcclient.Config) {
			cfg.Store, cfg.TransactionKeys = store, [][]byte{[]byte("another replica's transaction key!!")}
		})

		ar, loc := o.begin(t, starting, oidcclient.AuthOptions{})

		id, err := completing.Complete(t.Context(), callbackOf(loc, ar.Binding))
		require.ErrorIs(t, err, oidcclient.ErrTransactionIntegrity)
		assert.Nil(t, id)
		assert.Zero(t, o.hits(o.paths(o.base).Token))
	})
}

// TestParallelLoginsStayIsolated runs 16 logins at once — two end-users at
// two issuers — through the same provider and relying-party Clients: every
// identity and UserInfo response belongs to its own end-user and issuer.
func TestParallelLoginsStayIsolated(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	clients := map[string]*oidcclient.Client{
		o.base:           o.rp(t, o.basic()),
		o.base + tenantA: o.rp(t, o.tenant(tenantA, tenantAID)),
	}

	type outcome struct {
		issuer, user string
		id           *oidcclient.Identity
		info         *oidcclient.UserInfo
		err          error
	}

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out []outcome
	)

	for i := range 16 {
		issuer := []string{o.base, o.base + tenantA}[i%2]
		user := []string{alice, bob}[(i/2)%2]

		wg.Add(1)

		go func() {
			defer wg.Done()

			c := clients[issuer]

			res := outcome{issuer: issuer, user: user}

			ar, err := c.Begin(t.Context(), oidcclient.AuthOptions{LoginHint: user})
			if err == nil {
				resp, gerr := o.browser().Get(ar.URL)
				if gerr == nil {
					_ = resp.Body.Close()

					res.id, res.err = c.Complete(t.Context(), callbackOf(mustLocation(resp), ar.Binding))
					if res.err == nil {
						res.info, res.err = c.UserInfo(t.Context(), res.id)
					}
				} else {
					res.err = gerr
				}
			} else {
				res.err = err
			}

			mu.Lock()
			out = append(out, res)
			mu.Unlock()
		}()
	}

	wg.Wait()

	require.Len(t, out, 16)

	for _, res := range out {
		require.NoError(t, res.err)
		assert.Equal(t, res.issuer, res.id.Issuer)
		assert.Equal(t, res.user, res.id.Subject)
		assert.Equal(t, res.user, res.info.Subject)
	}
}

// mustLocation is the Location of a redirect; it panics on another
// response (the caller runs on a goroutine: no t.FailNow).
func mustLocation(resp *http.Response) *url.URL {
	loc, err := resp.Location()
	if err != nil {
		panic(errors.Join(errors.New("a redirect back to the relying party"), err))
	}

	return loc
}
