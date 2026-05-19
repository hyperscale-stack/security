// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareSuccessStoresAuthInContext(t *testing.T) {
	t.Parallel()

	authed := newAuth("alice").verified()
	engine := security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "test", result: authed}),
		scriptedExtractor{auth: newAuth("alice")},
	)

	var seen security.Authentication

	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, _ = security.FromContext(r.Context())
	})

	rec := httptest.NewRecorder()
	httpsec.Middleware(engine)(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	require.NotNil(t, seen)
	assert.True(t, seen.IsAuthenticated())
	assert.Equal(t, "alice", seen.Principal().Subject())
	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

func TestMiddlewareDeniesAnonymousByDefault(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(), scriptedExtractor{})

	rec := httptest.NewRecorder()
	httpsec.Middleware(engine)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next must not run")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
}

func TestMiddlewareLetsAnonymousThroughWhenOptedIn(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(), scriptedExtractor{})

	rec := httptest.NewRecorder()
	called := false
	httpsec.Middleware(engine, httpsec.WithAnonymousFallback(true))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			auth, _ := security.FromContext(r.Context())
			assert.False(t, auth.IsAuthenticated(), "anonymous is unauthenticated")
			w.WriteHeader(http.StatusTeapot)
		}),
	).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.True(t, called)
	assert.Equal(t, http.StatusTeapot, rec.Result().StatusCode)
}

func TestMiddlewareErrorMappingShortCircuits(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want int
	}{
		{"unsupported", security.ErrUnsupportedCredential, http.StatusBadRequest},
		{"invalid", security.ErrInvalidCredentials, http.StatusUnauthorized},
		{"expired", security.ErrTokenExpired, http.StatusUnauthorized},
		{"not_found", security.ErrTokenNotFound, http.StatusUnauthorized},
		{"unknown", errors.New("boom"), http.StatusUnauthorized},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			engine := security.NewEngine(
				security.NewManager(&scriptedAuthn{name: "x", err: c.err}),
				scriptedExtractor{auth: newAuth("alice")},
			)

			rec := httptest.NewRecorder()
			httpsec.Middleware(engine)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				t.Fatal("next must not run on auth error")
			})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			assert.Equal(t, c.want, rec.Result().StatusCode)
		})
	}
}

func TestMiddlewareWWWAuthenticateIncludesRealm(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "x", err: security.ErrTokenExpired}),
		scriptedExtractor{auth: newAuth("alice")},
	)

	rec := httptest.NewRecorder()
	httpsec.Middleware(engine, httpsec.WithRealm("hyperscale"))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("must not run") }),
	).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	ww := rec.Header().Get("WWW-Authenticate")
	assert.True(t, strings.Contains(ww, `realm="hyperscale"`),
		"realm must be included; got %q", ww)
	assert.True(t, strings.Contains(ww, `error="invalid_token"`),
		"OAuth2 error parameter must be present for token expiry; got %q", ww)
}

func TestMiddlewareCustomErrorMapperIsHonored(t *testing.T) {
	t.Parallel()

	custom := &customMapper{}
	engine := security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "x", err: security.ErrInvalidCredentials}),
		scriptedExtractor{auth: newAuth("alice")},
	)

	rec := httptest.NewRecorder()
	httpsec.Middleware(engine, httpsec.WithErrorMapper(custom))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("must not run") }),
	).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.True(t, custom.invoked.Load())
}

type customMapper struct{ invoked atomicBool }

func (m *customMapper) Map(w http.ResponseWriter, _ *http.Request, _ error) {
	m.invoked.Store(true)
	w.WriteHeader(http.StatusTeapot)
}

// atomicBool is a tiny race-safe boolean used by tests; std atomic.Bool
// would do as well but is only available in modern Go versions.
type atomicBool struct {
	v sync.Mutex
	s bool
}

func (a *atomicBool) Store(b bool) {
	a.v.Lock()
	defer a.v.Unlock()
	a.s = b
}

func (a *atomicBool) Load() bool {
	a.v.Lock()
	defer a.v.Unlock()
	return a.s
}

func TestMiddlewareIsRaceSafeUnderConcurrentRequests(t *testing.T) {
	t.Parallel()

	authed := newAuth("alice").verified()
	engine := security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "x", result: authed}),
		scriptedExtractor{auth: newAuth("alice")},
	)

	mw := httpsec.Middleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))

	var wg sync.WaitGroup

	for range 100 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			if rec.Result().StatusCode != http.StatusOK {
				t.Errorf("got %d", rec.Result().StatusCode)
			}
		}()
	}

	wg.Wait()
}
