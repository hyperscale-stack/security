// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// policyEnv is a server with every shipped grant but the legacy password
// one and every client-authentication method, over a counting memory store,
// reporting to sink.
type policyEnv struct {
	srv   *oauth2.Server
	store *writeCountingStore
	sink  *errorSink
}

// newPolicyEnv builds a policyEnv under profile, serving clients.
func newPolicyEnv(t *testing.T, profile oauth2.Profile, clients ...oauth2.Client) *policyEnv {
	t.Helper()

	env := &policyEnv{store: &writeCountingStore{Store: memory.New()}, sink: &errorSink{}}

	registry := make(map[string]oauth2.Client, len(clients))
	for _, c := range clients {
		registry[c.ID()] = c
	}

	gcfg := grant.Config{
		Storage:       env.store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		OnError:       env.sink.hook,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        profile,
		Storage:        env.store,
		ClientStore:    &staticClientStore{clients: registry},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants: []oauth2.Grant{
			grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg), grant.NewClientCredentials(gcfg),
		},
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
		OnError:    env.sink.hook,
	})
	require.NoError(t, err)

	env.srv = srv

	return env
}

// token posts form to /token, with HTTP Basic credentials when secret is
// set (client_secret_basic), the form alone otherwise.
func (env *policyEnv) token(form url.Values, id, secret string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if secret != "" {
		req.SetBasicAuth(id, secret)
	}

	rec := httptest.NewRecorder()
	env.srv.TokenHandler().ServeHTTP(rec, req)

	return rec
}

// consenting is a ConsentFunc approving as alice with scope as
// Consent.Scope.
func consenting(scope string) oauth2.ConsentFunc {
	return func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		return &oauth2.Consent{Approved: true, Subject: "alice", Scope: scope}, nil
	}
}

// TestConsentCannotBroadenTheRequest pins the Consent.Scope contract and RFC
// 6749 §3.3: the consent step narrows the requested scope, never broadens
// it — not even a request without scope, whose grant it could otherwise
// fill with any scope, registered for the client or not. The request is
// already a subset of the client's registration, so a grant never exceeds
// request ∩ registration. A consent naming no scope — empty, or SPs only —
// grants exactly what was requested.
func TestConsentCannotBroadenTheRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, requested, consented string
		want                       string // the granted scope; "" with refused
		refused                    bool
	}{
		{"empty request, scopes outside the registration", "", "admin delete-everything", "", true},
		{"empty request, a registered scope", "", "read", "", true},
		{"a scope outside the request", "read", "read write", "", true},
		{"a malformed consent scope", "read write", "read\twrite", "", true},
		{"narrowed", "read write", "read", "read", false},
		{"narrowed, repetitions dropped", "read write", "write  write", "write", false},
		{"no consent scope", "read write", "", "read write", false},
		{"a blank consent scope", "read write", "   ", "read write", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &writeCountingStore{Store: memory.New()}
			env := newExtensionEnv(t, &fakeExtension{}, withStore(store))

			q := authorizeQuery()
			q.Set("scope", tc.requested)

			rec := env.authorize(q, consenting(tc.consented))
			require.Equal(t, http.StatusFound, rec.Code)

			params := mustLocation(t, rec).Query()
			if tc.refused {
				assert.Equal(t, oauth2.CodeInvalidScope, params.Get("error"))
				assert.Empty(t, params.Get("code"))
				assert.Zero(t, store.writes.Load(), "nothing persisted")

				return
			}

			tokens := env.exchange(params.Get("code"))
			require.Equal(t, http.StatusOK, tokens.Code, tokens.Body.String())
			assert.Equal(t, tc.want, jsonBody(t, tokens)["scope"])
		})
	}
}

// TestImplicitConsentCannotBroadenTheRequest: the implicit flow applies the
// same rule; its refusal travels in the fragment.
func TestImplicitConsentCannotBroadenTheRequest(t *testing.T) {
	t.Parallel()

	store := &writeCountingStore{Store: memory.New()}
	env := newExtensionEnv(t, &fakeExtension{}, withStore(store), withProfile(oauth2.Profile20))

	q := implicitQuery()
	q.Del("scope")

	rec := runAuthorizeCfg(env.srv, oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()},
		q, consenting("admin"))
	require.Equal(t, http.StatusFound, rec.Code)

	frag, err := url.ParseQuery(mustLocation(t, rec).Fragment)
	require.NoError(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, frag.Get("error"))
	assert.Empty(t, frag.Get("access_token"))
	assert.Zero(t, store.writes.Load(), "nothing persisted")
}

// TestClientCredentialsRequiresAConfidentialClient pins RFC 6749 §4.4: "The
// client credentials grant type MUST only be used by confidential clients".
// A public client — whose client_id is no credential, RFC 6749 §2.3 — and an
// untyped one, which the server cannot know to be confidential, are refused
// with unauthorized_client (§5.2) whatever they declare and however they
// authenticate; nothing is issued. The "none" method itself never
// authenticates a confidential or untyped client.
func TestClientCredentialsRequiresAConfidentialClient(t *testing.T) {
	t.Parallel()

	grants := []string{oauth2.GrantTypeClientCredentials}
	scopes := []string{"admin", "superuser"}
	clients := []oauth2.Client{
		&oauth2.DefaultClient{
			IDValue: "spa", TypeValue: oauth2.ClientPublic, RedirectURIValues: []string{redirectURI},
			GrantTypeValues: grants, ScopeValues: scopes,
		},
		&oauth2.DefaultClient{IDValue: "untyped", Secret: "untyped-secret", GrantTypeValues: grants, ScopeValues: scopes},
		&oauth2.DefaultClient{
			IDValue: "machine", Secret: "machine-secret", TypeValue: oauth2.ClientConfidential,
			GrantTypeValues: grants, ScopeValues: scopes,
		},
	}

	form := func(extra ...string) url.Values {
		f := url.Values{"grant_type": {oauth2.GrantTypeClientCredentials}, "scope": {"admin superuser"}}
		for i := 0; i+1 < len(extra); i += 2 {
			f.Set(extra[i], extra[i+1])
		}

		return f
	}

	cases := []struct {
		name       string
		form       url.Values
		id, secret string
		status     int
		code       string
	}{
		{"public client via none", form("client_id", "spa"), "", "", http.StatusBadRequest, oauth2.CodeUnauthorizedClient},
		{"untyped client via client_secret_basic", form(), "untyped", "untyped-secret", http.StatusBadRequest, oauth2.CodeUnauthorizedClient},
		{
			"untyped client via client_secret_post", form("client_id", "untyped", "client_secret", "untyped-secret"), "", "",
			http.StatusBadRequest, oauth2.CodeUnauthorizedClient,
		},
		{"untyped client via none", form("client_id", "untyped"), "", "", http.StatusUnauthorized, oauth2.CodeInvalidClient},
		{"confidential client via none", form("client_id", "machine"), "", "", http.StatusUnauthorized, oauth2.CodeInvalidClient},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newPolicyEnv(t, oauth2.Profile20BCP, clients...)

			rec := env.token(tc.form, tc.id, tc.secret)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			assert.Equal(t, tc.code, jsonBody(t, rec)["error"])
			assert.NotContains(t, rec.Body.String(), "access_token")
			assert.Zero(t, env.store.writes.Load(), "nothing issued")
		})
	}

	t.Run("confidential client via client_secret_basic", func(t *testing.T) {
		t.Parallel()

		env := newPolicyEnv(t, oauth2.Profile20BCP, clients...)

		rec := env.token(form(), "machine", "machine-secret")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "admin superuser", jsonBody(t, rec)["scope"])
	})
}
