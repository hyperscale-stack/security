// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gilcrest/alice"
	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/authentication"
	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestHandlerStopsAtFirstSuccessfulProvider locks the v0 bug fix: previously
// the Handler iterated through every Provider whose IsSupported returned true,
// letting a later provider overwrite the authenticated state produced by an
// earlier one. The fix introduces a break after a successful Authenticate.
func TestHandlerStopsAtFirstSuccessfulProvider(t *testing.T) {
	t.Parallel()

	first := &authentication.MockProvider{}
	second := &authentication.MockProvider{}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	first.On("IsSupported", mock.AnythingOfType("*credential.UsernamePasswordCredential")).
		Return(true).Once()
	first.On("Authenticate",
		mock.AnythingOfType("*http.Request"),
		mock.AnythingOfType("*credential.UsernamePasswordCredential"),
	).Return(func(r *http.Request, _ credential.Credential) *http.Request { return r }, nil).Once()

	chain := alice.New(
		authentication.FilterHandler(authentication.NewHTTPBasicFilter()),
		authentication.Handler(first, second),
	)

	w := httptest.NewRecorder()
	chain.ThenFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	first.AssertExpectations(t)
	second.AssertNotCalled(t, "IsSupported")
	second.AssertNotCalled(t, "Authenticate")
}

// TestHandlerFallsThroughWhenNoProviderSupports preserves the v0 contract: if
// no provider supports the credential, the request flows through as anonymous
// and the downstream AuthorizeHandler is responsible for the rejection.
func TestHandlerFallsThroughWhenNoProviderSupports(t *testing.T) {
	t.Parallel()

	p := &authentication.MockProvider{}
	p.On("IsSupported", mock.Anything).Return(false).Once()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

	chain := alice.New(
		authentication.FilterHandler(authentication.NewHTTPBasicFilter()),
		authentication.Handler(p),
	)

	w := httptest.NewRecorder()
	chain.ThenFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // marker
	}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusTeapot, w.Result().StatusCode)
	p.AssertExpectations(t)
	p.AssertNotCalled(t, "Authenticate")
}

// TestHandlerMapsTypedErrorsToStatus checks the errors.Is-based mapping
// introduced in Phase 0.
func TestHandlerMapsTypedErrorsToStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want int
	}{
		{"unsupported_credential", security.ErrUnsupportedCredential, http.StatusBadRequest},
		{"invalid_credentials", security.ErrInvalidCredentials, http.StatusUnauthorized},
		{"client_secret_mismatch", security.ErrClientSecretMismatch, http.StatusUnauthorized},
		{"token_expired", security.ErrTokenExpired, http.StatusUnauthorized},
		{"token_not_found", security.ErrTokenNotFound, http.StatusUnauthorized},
		{"unknown_error_defaults_to_401", errors.New("unexpected"), http.StatusUnauthorized},
		{"wrapped_unsupported", fmt.Errorf("ctx: %w", security.ErrUnsupportedCredential), http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := &authentication.MockProvider{}
			p.On("IsSupported", mock.Anything).Return(true).Once()
			p.On("Authenticate", mock.Anything, mock.Anything).
				Return(func(r *http.Request, _ credential.Credential) *http.Request { return r }, tc.err).
				Once()

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")

			chain := alice.New(
				authentication.FilterHandler(authentication.NewHTTPBasicFilter()),
				authentication.Handler(p),
			)

			w := httptest.NewRecorder()
			chain.ThenFunc(func(_ http.ResponseWriter, _ *http.Request) {
				t.Fatal("downstream handler should not run on auth error")
			}).ServeHTTP(w, req)

			resp := w.Result()
			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, tc.want, resp.StatusCode)
			assert.Equal(t, "Access denied\n", string(body), "v0 body shape preserved")
			p.AssertExpectations(t)
		})
	}
}
