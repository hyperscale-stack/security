// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentCodeExchange: of many exchanges of one code, at most one
// succeeds — with an ID Token — and the claims source is asked once: only
// the exchange that consumed the code reaches the extension. (A loser's
// replay may revoke the winner's family first: zero successes is legal.)
func TestConcurrentCodeExchange(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	code := e.code(authorizeQuery())

	const racers = 50

	var (
		wg        sync.WaitGroup
		successes atomic.Int32
	)

	start := make(chan struct{})

	for range racers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			rec := e.exchange(code)
			if rec.Code == http.StatusOK {
				successes.Add(1)
				assert.Contains(t, rec.Body.String(), `"id_token"`)

				return
			}

			assert.NotContains(t, rec.Body.String(), "id_token")
		}()
	}

	close(start)
	wg.Wait()

	assert.LessOrEqual(t, successes.Load(), int32(1))
	assert.LessOrEqual(t, len(e.claims.recorded()), 1)
}

// TestConcurrentIssuanceDuringRotation runs full flows while the signing
// key rotates (run with -race): every ID Token verifies against the union
// of the published keys.
func TestConcurrentIssuanceDuringRotation(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	ringA := oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSA()}, Published: []jwtsec.PublicKey{publicOf(signingRSAB())}}
	ringB := oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSAB()}, Published: []jwtsec.PublicKey{publicOf(signingRSA())}}
	union := []jwtsec.PublicKey{publicOf(signingRSA()), publicOf(signingRSAB())}

	stop := make(chan struct{})

	var rotator sync.WaitGroup

	rotator.Add(1)

	go func() {
		defer rotator.Done()

		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}

			if i%2 == 0 {
				e.keys.set(ringA)
			} else {
				e.keys.set(ringB)
			}
		}
	}()

	var wg sync.WaitGroup

	idTokens := make(chan string, 20)

	for range 20 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			loc, err := url.Parse(e.authorize(authorizeQuery()).Header().Get("Location"))
			if err != nil || loc.Query().Get("code") == "" {
				t.Errorf("no code: %v %v", err, loc)

				return
			}

			rec := e.exchange(loc.Query().Get("code"))

			var resp tokenResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.IDToken == "" {
				t.Errorf("no ID Token: %d %s", rec.Code, rec.Body.String())

				return
			}

			idTokens <- resp.IDToken
		}()
	}

	wg.Wait()
	close(stop)
	rotator.Wait()
	close(idTokens)

	count := 0

	for raw := range idTokens {
		count++

		_, claims := decodeJWT(t, raw, union)
		require.Equal(t, "alice", claims["sub"])
	}

	assert.Equal(t, 20, count)
}
