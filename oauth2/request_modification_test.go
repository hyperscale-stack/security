// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requestEdits rewrite one security-relevant field of the AuthorizeRequest
// a callback is handed — or, for "client identity", the client it shares
// with the server.
var requestEdits = map[string]func(*oauth2.AuthorizeRequest){
	"response type":  func(ar *oauth2.AuthorizeRequest) { ar.ResponseType = "token" },
	"redirect URI":   func(ar *oauth2.AuthorizeRequest) { ar.RedirectURI = "https://evil.example/cb" },
	"scope":          func(ar *oauth2.AuthorizeRequest) { ar.Scope = "openid read write" },
	"state":          func(ar *oauth2.AuthorizeRequest) { ar.State = "forged" },
	"code challenge": func(ar *oauth2.AuthorizeRequest) { ar.CodeChallenge = "" },
	"PKCE method":    func(ar *oauth2.AuthorizeRequest) { ar.CodeChallengeMethod = "plain" },
	"nonce":          func(ar *oauth2.AuthorizeRequest) { ar.Nonce = "attacker-nonce" },
	"issuer":         func(ar *oauth2.AuthorizeRequest) { ar.Issuer = "https://evil.example" },
	"client replaced": func(ar *oauth2.AuthorizeRequest) {
		ar.Client = &oauth2.DefaultClient{GrantTypeValues: allGrantTypes, IDValue: "evil"}
	},
	"client removed": func(ar *oauth2.AuthorizeRequest) { ar.Client = nil },
	"client identity": func(ar *oauth2.AuthorizeRequest) {
		ar.Client.(*oauth2.DefaultClient).IDValue = "rebound-client" //nolint:forcetypeassert // test client
	},
}

// requireFailedClosed asserts that rec answers a request a callback
// modified: a server_error redirected to the validated redirect URI with
// the validated state, nothing persisted, ErrAuthorizeRequestModified at
// the hook.
func requireFailedClosed(t *testing.T, env *extensionEnv, store *writeCountingStore, rec *httptest.ResponseRecorder) {
	t.Helper()

	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, redirectURI, loc.Scheme+"://"+loc.Host+loc.Path, "the validated redirect URI")

	params := loc.Query()
	assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
	assert.Equal(t, "xyz-state", params.Get("state"), "the validated state")
	assert.False(t, params.Has("code"))
	assert.Zero(t, store.writes.Load(), "nothing persisted")

	hooked := env.sink.collected()
	require.Len(t, hooked, 1)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(hooked[0]))
	assert.ErrorIs(t, hooked[0], oauth2.ErrAuthorizeRequestModified)
}

// TestConsentFuncModifyingItsRequestFailsClosed: the request a ConsentFunc
// is handed is read-only — narrowing goes through Consent.Scope. Rewriting
// a field of it, or the identity of the client it shares, fails the
// authorization with server_error instead of being ignored.
func TestConsentFuncModifyingItsRequestFailsClosed(t *testing.T) {
	t.Parallel()

	for name, edit := range requestEdits {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &writeCountingStore{Store: memory.New()}
			env := newExtensionEnv(t, nil, withStore(store))

			rec := env.authorize(oidcQuery(), func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
				edit(ar)

				return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
			})

			requireFailedClosed(t, env, store, rec)
		})
	}
}

// TestExtensionModifyingItsRequestFailsClosed: the extension's hooks are
// held to the same rule — and the ConsentFunc never runs after a
// ValidateAuthorizeRequest that modified its request.
func TestExtensionModifyingItsRequestFailsClosed(t *testing.T) {
	t.Parallel()

	for name, edit := range requestEdits {
		for _, hook := range []string{"validate", "complete"} {
			t.Run(hook+"/"+name, func(t *testing.T) {
				t.Parallel()

				ext := &fakeExtension{}
				if hook == "validate" {
					ext.validate = func(_ context.Context, _ *http.Request, ar *oauth2.AuthorizeRequest) (any, error) {
						edit(ar)

						return nil, nil
					}
				} else {
					ext.complete = func(_ context.Context, ar *oauth2.AuthorizeRequest, _ oauth2.Consent, _ time.Time) (oauth2.ExtensionGrant, error) {
						edit(ar)

						return oauth2.ExtensionGrant{}, nil
					}
				}

				store := &writeCountingStore{Store: memory.New()}
				env := newExtensionEnv(t, ext, withStore(store))

				consented := false
				rec := env.authorize(oidcQuery(), func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
					consented = true

					return approve(w, r, ar)
				})

				requireFailedClosed(t, env, store, rec)
				assert.Equal(t, hook == "complete", consented)
			})
		}
	}
}

// TestImplicitFlowCallbackModifyingItsRequestFailsClosed: the implicit flow
// fails closed the same way, in the fragment.
func TestImplicitFlowCallbackModifyingItsRequestFailsClosed(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	store := &writeCountingStore{Store: memory.New()}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile: oauth2.Profile20, Storage: store, OnError: sink.hook,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			testClientID: &oauth2.DefaultClient{
				GrantTypeValues: allGrantTypes, IDValue: testClientID, RedirectURIValues: []string{redirectURI},
				ScopeValues: []string{"read", "write"},
			},
		}},
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.NoError(t, err)

	rec := runAuthorizeCfg(srv, oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}, implicitQuery(),
		func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			ar.Scope = "read write"

			return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
		})
	require.Equal(t, http.StatusFound, rec.Code)

	fragment, err := url.ParseQuery(mustLocation(t, rec).Fragment)
	require.NoError(t, err)
	assert.Equal(t, oauth2.CodeServerError, fragment.Get("error"))
	assert.False(t, fragment.Has("access_token"))
	assert.Zero(t, store.writes.Load())
	assert.Equal(t, []string{oauth2.CodeServerError}, sink.codes())
}
