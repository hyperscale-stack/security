// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeCountingStore counts the codes and tokens the authorization endpoint
// persists.
type writeCountingStore struct {
	*memory.Store

	writes atomic.Int32
}

func (s *writeCountingStore) SaveAuthorizationCode(ctx context.Context, code *oauth2.AuthorizationCode) error {
	s.writes.Add(1)

	return s.Store.SaveAuthorizationCode(ctx, code) //nolint:wrapcheck // test double
}

func (s *writeCountingStore) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	s.writes.Add(1)

	return s.Store.SaveTokenPair(ctx, pair) //nolint:wrapcheck // test double
}

// codeGrant is the authorization_code grant over store: /authorize serves
// the code flow only on a server registering it.
func codeGrant(store oauth2.Storage) oauth2.Grant {
	return grant.NewAuthorizationCode(grant.Config{Storage: store, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour})
}

// responseModeServer is a Profile20 server — the implicit flow can be
// enabled — over a counting store, reporting to sink, behind resolver.
func responseModeServer(t *testing.T, resolver oauth2.IssuerResolver, sink *errorSink) (*oauth2.Server, *writeCountingStore) {
	t.Helper()

	store := &writeCountingStore{Store: memory.New()}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile: oauth2.Profile20, Storage: store, IssuerResolver: resolver,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			testClientID: &oauth2.DefaultClient{
				GrantTypeValues: allGrantTypes,
				IDValue:         testClientID, RedirectURIValues: []string{redirectURI}, ScopeValues: []string{"read"},
			},
		}},
		Grants:     []oauth2.Grant{codeGrant(store)},
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		OnError:    sink.hook,
	})
	require.NoError(t, err)

	return srv, store
}

// runResponseMode runs /authorize on srv with q; implicit enables the
// implicit flow. It reports whether the ConsentFunc ran.
func runResponseMode(srv *oauth2.Server, q url.Values, implicit bool) (*httptest.ResponseRecorder, bool) {
	consented := false
	consent := func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		consented = true

		return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
	}

	cfg := oauth2.AuthorizeConfig{}
	if implicit {
		cfg = oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}
	}

	rec := runAuthorizeCfg(srv, cfg, q, consent)

	return rec, consented
}

// withMode returns q with response_mode set to mode; "-" leaves it absent.
func withMode(q url.Values, mode string) url.Values {
	if mode != "-" {
		q.Set("response_mode", mode)
	}

	return q
}

// TestAuthorizeAcceptsTheDefaultResponseMode: an absent or empty
// response_mode (RFC 6749 §3.1: a parameter without a value is omitted),
// or the flow's own one — query for code, fragment for token (OAuth 2.0
// Multiple Response Type Encoding Practices §2.1) — is served as before.
func TestAuthorizeAcceptsTheDefaultResponseMode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, mode string
		implicit   bool
	}{
		{"code, absent", "-", false},
		{"code, empty", "", false},
		{"code, query", "query", false},
		{"token, absent", "-", true},
		{"token, empty", "", true},
		{"token, fragment", "fragment", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, _ := responseModeServer(t, oauth2.StaticIssuer("https://auth.example", "api"), &errorSink{})

			q := authorizeQuery()
			if tc.implicit {
				q = implicitQuery()
			}

			rec, consented := runResponseMode(srv, withMode(q, tc.mode), tc.implicit)
			require.Equal(t, http.StatusFound, rec.Code)
			assert.True(t, consented)

			loc := mustLocation(t, rec)
			if tc.implicit {
				fragment, err := url.ParseQuery(loc.Fragment)
				require.NoError(t, err)
				assert.NotEmpty(t, fragment.Get("access_token"))

				return
			}

			assert.NotEmpty(t, loc.Query().Get("code"))
		})
	}
}

// TestAuthorizeRefusesUnsupportedResponseModes: any other response_mode —
// the other flow's mode, form_post, a case variant, an unknown value —
// cannot be honored, nor can the answer be encoded: a bare 400, never
// redirected (OIDC Core 1.0 incorporating errata set 2 §3.1.2.6), reported
// to the hook as invalid_request, before the ConsentFunc and with nothing
// persisted.
func TestAuthorizeRefusesUnsupportedResponseModes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, responseType, mode string
		implicit                 bool
	}{
		{"code, fragment", "code", "fragment", false},
		{"code, form_post", "code", "form_post", false},
		{"code, QUERY", "code", "QUERY", false},
		{"code, unknown", "code", "web_message", false},
		{"token, query", "token", "query", true},
		{"token, form_post", "token", "form_post", true},
		// The implicit flow disabled, a token request is answered in the
		// query: fragment cannot be honored.
		{"token disabled, fragment", "token", "fragment", false},
		{"unknown response type, fragment", "magic", "fragment", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sink := &errorSink{}
			srv, store := responseModeServer(t, oauth2.StaticIssuer("https://auth.example", "api"), sink)

			q := authorizeQuery()
			q.Set("response_type", tc.responseType)

			rec, consented := runResponseMode(srv, withMode(q, tc.mode), tc.implicit)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Empty(t, rec.Header().Get("Location"), "never redirected")
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
			assert.False(t, consented)
			assert.Zero(t, store.writes.Load())
			assert.Equal(t, []string{oauth2.CodeInvalidRequest}, sink.codes())
		})
	}
}

// TestResponseModeIsCheckedBeforeAnyRedirect: an unsupported response_mode
// wins over every error that would be redirected — the response type, the
// scope, PKCE — since none of them can be encoded.
func TestResponseModeIsCheckedBeforeAnyRedirect(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		resolver oauth2.IssuerResolver
		mutate   func(url.Values)
	}{
		{"scope not allowed", oauth2.StaticIssuer("https://auth.example", "api"), func(q url.Values) { q.Set("scope", "admin") }},
		{"malformed PKCE", oauth2.StaticIssuer("https://auth.example", "api"), func(q url.Values) { q.Set("code_challenge", "short") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sink := &errorSink{}
			srv, _ := responseModeServer(t, tc.resolver, sink)

			q := authorizeQuery()
			tc.mutate(q)

			rec, _ := runResponseMode(srv, withMode(q, "form_post"), false)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Empty(t, rec.Header().Get("Location"))
			assert.Equal(t, []string{oauth2.CodeInvalidRequest}, sink.codes())
		})
	}
}

// TestUnsupportedResponseTypeAnsweredInTheQueryMode: an unknown response
// type with response_mode=query is answered as before, in the query.
func TestUnsupportedResponseTypeAnsweredInTheQueryMode(t *testing.T) {
	t.Parallel()

	srv, _ := responseModeServer(t, oauth2.StaticIssuer("https://auth.example", "api"), &errorSink{})

	q := authorizeQuery()
	q.Set("response_type", "magic")

	rec, _ := runResponseMode(srv, withMode(q, "query"), false)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, oauth2.CodeUnsupportedResponseType, mustLocation(t, rec).Query().Get("error"))
}
