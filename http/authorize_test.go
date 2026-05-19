// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeGrantsLetsNextRun(t *testing.T) {
	t.Parallel()

	called := false
	h := httpsec.Authorize(scriptedADM{}, fakeAttr("scope:read"))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(security.WithAuthentication(req.Context(), newAuth("alice").verified()))

	h.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
}

func TestAuthorizeDeniesWithForbidden(t *testing.T) {
	t.Parallel()

	h := httpsec.Authorize(scriptedADM{err: security.ErrAccessDenied}, fakeAttr("scope:read"))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("must not run") }),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(security.WithAuthentication(req.Context(), newAuth("alice").verified()))

	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode)
}

func TestAuthorizeInsufficientScopeIncludesOAuthErrorParam(t *testing.T) {
	t.Parallel()

	h := httpsec.Authorize(scriptedADM{err: security.ErrInsufficientScope}, fakeAttr("scope:write"))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("must not run") }),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(security.WithAuthentication(req.Context(), newAuth("alice").verified()))

	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
}

func TestAuthorizeUsesAnonymousWhenNoAuthInContext(t *testing.T) {
	t.Parallel()

	// scriptedADM deny -> Authorize must surface 403 even without a prior
	// Middleware step (Authentication == Anonymous).
	h := httpsec.Authorize(scriptedADM{err: security.ErrAccessDenied}, fakeAttr("scope:read"))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("must not run") }),
	)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode)
}
