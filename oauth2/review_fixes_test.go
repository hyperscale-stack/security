// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetadataAdvertisesTheServedResponseModes: the RFC 8414 document lists
// response_modes_supported — whose omission means ["query", "fragment"] (RFC
// 8414 §2) — as the one mode /authorize serves for the advertised response
// type, and that mode is served while the other is refused.
func TestMetadataAdvertisesTheServedResponseModes(t *testing.T) {
	t.Parallel()

	env := newExtensionEnv(t, nil)

	rec := httptest.NewRecorder()
	env.srv.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var doc struct {
		ResponseTypes []string `json:"response_types_supported"`
		ResponseModes []string `json:"response_modes_supported"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	assert.Equal(t, []string{"code"}, doc.ResponseTypes)
	assert.Equal(t, []string{"query"}, doc.ResponseModes)

	for _, mode := range doc.ResponseModes {
		q := authorizeQuery()
		q.Set("response_mode", mode)

		rec := env.authorize(q, approve)
		require.Equal(t, http.StatusFound, rec.Code, mode)
		assert.NotEmpty(t, mustLocation(t, rec).Query().Get("code"), mode)
	}

	q := authorizeQuery()
	q.Set("response_mode", "fragment")
	assert.Equal(t, http.StatusBadRequest, env.authorize(q, approve).Code, "an unadvertised mode is refused")
}

// typedNil is a nil *oauth2.Error in a non-nil error interface: the Go
// pitfall a callback falls into by returning a *oauth2.Error variable left
// nil.
func typedNil() error {
	var e *oauth2.Error

	return e
}

// TestTypedNilErrorIsHarmless: the *Error methods and IsCode tolerate a nil
// receiver.
func TestTypedNilErrorIsHarmless(t *testing.T) {
	t.Parallel()

	err := typedNil()

	assert.NotPanics(t, func() { _ = err.Error() })
	assert.Nil(t, errors.Unwrap(err))
	assert.Empty(t, oauth2.IsCode(err))
	assert.False(t, errors.Is(err, oauth2.ErrUnredirectableRequest))
	assert.NotPanics(t, func() { _ = errors.Join(err).Error() })
}

// TestTypedNilErrorsFromCallbacksAreServerErrors: a typed-nil *Error
// returned by an authorization hook, the ConsentFunc, the token-response
// hook or a grant is answered server_error — never a panic that drops the
// connection after the code was consumed.
func TestTypedNilErrorsFromCallbacksAreServerErrors(t *testing.T) {
	t.Parallel()

	authorizeCases := map[string]*fakeExtension{
		"ValidateAuthorizeRequest": {validate: func(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error) {
			return nil, typedNil()
		}},
		"CompleteAuthorization": {complete: func(context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time) (oauth2.ExtensionGrant, error) {
			return oauth2.ExtensionGrant{}, typedNil()
		}},
	}

	for name, ext := range authorizeCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newExtensionEnv(t, ext)

			rec := env.authorize(oidcQuery(), approve)
			require.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, oauth2.CodeServerError, mustLocation(t, rec).Query().Get("error"))
			assert.Equal(t, []string{oauth2.CodeServerError}, env.sink.codes())
		})
	}

	t.Run("ConsentFunc", func(t *testing.T) {
		t.Parallel()

		env := newExtensionEnv(t, nil)

		rec := env.authorize(oidcQuery(), decide(nil, typedNil()))
		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, oauth2.CodeServerError, mustLocation(t, rec).Query().Get("error"))

		hooked := env.sink.collected()
		require.Len(t, hooked, 1)
		assert.NotPanics(t, func() { _ = hooked[0].Error() })
	})

	t.Run("ExtendTokenResponse", func(t *testing.T) {
		t.Parallel()

		env := newExtensionEnv(t, failingExtension(typedNil()))

		rec := env.exchange(env.code(t, oidcQuery(), approve))
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, oauth2.CodeServerError, jsonBody(t, rec)["error"])
		requireNoTokens(t, rec)
	})

	t.Run("grant", func(t *testing.T) {
		t.Parallel()

		cfg := hookServerConfig(memory.New())
		cfg.Grants = []oauth2.Grant{failingGrant{err: typedNil()}}

		srv, err := oauth2.NewServer(cfg)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token", url.Values{"grant_type": {"urn:test:failing"}}, true))
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, oauth2.CodeServerError, tokenErrorBody(t, rec)["error"])
	})
}
