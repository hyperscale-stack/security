// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/internal/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uniqueScopes returns n distinct scope tokens joined by SP — the shape of
// the audit's quadratic-cost requests.
func uniqueScopes(n int) string {
	var b strings.Builder

	for i := range n {
		if i > 0 {
			b.WriteByte(' ')
		}

		fmt.Fprintf(&b, "s%07d", i)
	}

	return b.String()
}

// TestAuthorizeRefusesMalformedScope pins RFC 6749 §3.3 at /authorize: a
// scope value is SP-separated NQCHAR tokens, at most 100 of them and 4096
// bytes. Anything else is answered invalid_scope ("malformed", §4.1.2.1)
// before the extension or the ConsentFunc runs — including the 40 000
// unique tokens whose quadratic narrowing cost seconds of CPU per request.
func TestAuthorizeRefusesMalformedScope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		scope string
		cause error
	}{
		{"tab separator", "read\twrite", scopes.ErrMalformed},
		{"line feed separator", "read\nwrite", scopes.ErrMalformed},
		{"quote", `read "write"`, scopes.ErrMalformed},
		{"non-ASCII token", "read lecture:é", scopes.ErrMalformed},
		{"101 tokens, repetitions included", strings.TrimSpace(strings.Repeat("read ", 101)), scopes.ErrTooLarge},
		{"4097 bytes", strings.Repeat("r", 4097), scopes.ErrTooLarge},
		{"40 000 unique tokens", uniqueScopes(40_000), scopes.ErrTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// 1 MiB requests: the scope bounds, not the request-size bound
			// (64 KiB by default, which alone refuses the 40 000 tokens),
			// answer every case.
			ext := &fakeExtension{}
			env := newExtensionEnv(t, ext, withMaxRequestBytes(1<<20))

			q := authorizeQuery()
			q.Set("scope", tc.scope)

			consented := false
			rec := env.authorize(q, func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
				consented = true

				return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
			})
			require.Equal(t, http.StatusFound, rec.Code)

			params := mustLocation(t, rec).Query()
			assert.Equal(t, oauth2.CodeInvalidScope, params.Get("error"))
			assert.Empty(t, params.Get("code"))
			assert.False(t, consented, "the ConsentFunc never runs")

			validated, _, _ := ext.calls()
			assert.Zero(t, validated, "the extension never runs")
			assert.True(t, env.sink.matches(tc.cause), "OnError gets the cause")
		})
	}
}

// TestAuthorizeScopeIsCanonical: the request's scope is read as a set (RFC
// 6749 §3.3: order and repetitions add nothing) and handed on single-SP
// joined, duplicates dropped — to the ConsentFunc and into the code.
func TestAuthorizeScopeIsCanonical(t *testing.T) {
	t.Parallel()

	env := newExtensionEnv(t, &fakeExtension{})

	q := authorizeQuery()
	q.Set("scope", "  read   read write ")

	var seen string

	code := env.code(t, q, func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		seen = ar.Scope

		return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
	})
	assert.Equal(t, "read write", seen)

	rec := env.exchange(code)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "read write", jsonBody(t, rec)["scope"])
}

// TestTokenRefusesMalformedScope pins RFC 6749 §3.3 at /token: the scope of
// a client_credentials request is parsed like the authorization endpoint's
// (invalid_scope, §5.2) and issued canonical.
func TestTokenRefusesMalformedScope(t *testing.T) {
	t.Parallel()

	refused := []struct {
		name  string
		scope string
		cause error
	}{
		{"tab separator", "read\twrite", scopes.ErrMalformed},
		{"backslash", `read\write`, scopes.ErrMalformed},
		{"101 tokens", strings.TrimSpace(strings.Repeat("read ", 101)), scopes.ErrTooLarge},
	}

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newExtensionEnv(t, &fakeExtension{})
			rec := env.token(url.Values{"grant_type": {"client_credentials"}, "scope": {tc.scope}})
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, oauth2.CodeInvalidScope, jsonBody(t, rec)["error"])
			assert.NotContains(t, rec.Body.String(), "access_token")
			assert.True(t, env.sink.matches(tc.cause), "OnError gets the cause")
		})
	}

	t.Run("canonical", func(t *testing.T) {
		t.Parallel()

		env := newExtensionEnv(t, &fakeExtension{})
		rec := env.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"write  read write"}})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "write read", jsonBody(t, rec)["scope"])
	})
}

// TestRefreshNarrowingIsCanonical pins RFC 6749 §6 with the §3.3 syntax: a
// narrowing scope is parsed strictly — a malformed one is refused before
// anything is consumed — and issued canonical; one with no token at all is
// treated as omitted (the original scope).
func TestRefreshNarrowingIsCanonical(t *testing.T) {
	t.Parallel()

	env := newExtensionEnv(t, &fakeExtension{})

	q := authorizeQuery()
	q.Set("scope", "read write")

	issued := jsonBody(t, env.exchange(env.code(t, q, approve)))
	rt, _ := issued["refresh_token"].(string)
	require.NotEmpty(t, rt)

	narrow := func(rt, scope string) map[string]any {
		t.Helper()

		rec := env.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {scope}})

		return jsonBody(t, rec)
	}

	refused := narrow(rt, "read\twrite")
	assert.Equal(t, oauth2.CodeInvalidScope, refused["error"])
	assert.True(t, env.sink.matches(scopes.ErrMalformed))

	// The refusal consumed nothing: the token still narrows.
	narrowed := narrow(rt, "write  read write")
	assert.Equal(t, "write read", narrowed["scope"])

	next, _ := narrowed["refresh_token"].(string)
	require.NotEmpty(t, next)

	blank := narrow(next, "   ")
	assert.Equal(t, "read write", blank["scope"], "no token: the original scope")
}

// TestExtensionScopeSyntax: an ExtensionGrant.Scope is parsed like a
// request's; a malformed one fails closed with server_error, nothing
// issued.
func TestExtensionScopeSyntax(t *testing.T) {
	t.Parallel()

	ext := &fakeExtension{
		complete: func(context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time) (oauth2.ExtensionGrant, error) {
			return oauth2.ExtensionGrant{Scope: "read\twrite"}, nil
		},
	}
	env := newExtensionEnv(t, ext)

	q := authorizeQuery()
	q.Set("scope", "read write")

	rec := env.authorize(q, approve)
	require.Equal(t, http.StatusFound, rec.Code)

	params := mustLocation(t, rec).Query()
	assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
	assert.Empty(t, params.Get("code"))
	assert.True(t, env.sink.matches(scopes.ErrMalformed))
}
