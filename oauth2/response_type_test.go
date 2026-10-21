// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestAuthorizeMissingResponseTypeIsInvalidRequest pins RFC 6749 §4.1.1
// (response_type is REQUIRED), §3.1 (an empty occurrence is omitted) and
// §4.1.2.1 (invalid_request: "The request is missing a required
// parameter"): a request without response_type is answered invalid_request
// — in the query, naming the issuer, echoing the state, nothing saved —
// while an unknown value keeps unsupported_response_type.
func TestAuthorizeMissingResponseTypeIsInvalidRequest(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mutate            func(url.Values)
		code, description string
	}{
		"absent":           {func(q url.Values) { q.Del("response_type") }, oauth2.CodeInvalidRequest, "response_type is required"},
		"empty occurrence": {func(q url.Values) { q.Set("response_type", "") }, oauth2.CodeInvalidRequest, "response_type is required"},
		"unknown":          {func(q url.Values) { q.Set("response_type", "magic") }, oauth2.CodeUnsupportedResponseType, "response_type is not supported"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, 0, nil, nil)
			q := boundsQuery()
			tc.mutate(q)

			rec := serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
			params := redirectParams(t, rec, false)
			assert.Equal(t, tc.code, params.Get("error"))
			assert.Equal(t, tc.description, params.Get("error_description"))
			assert.Equal(t, testIssuer, params.Get("iss"))
			assert.Equal(t, "bounds-state", params.Get("state"))
			assert.False(t, params.Has("code"))
			assert.Zero(t, env.store.writes.Load())
		})
	}
}

// codeGrantlessServer is a server of profile p without the
// authorization_code grant — client_credentials only — over a counting
// store, whose client "machine" declares the authorization_code and
// implicit grants.
func codeGrantlessServer(t *testing.T, p oauth2.Profile) (*oauth2.Server, *writeCountingStore) {
	t.Helper()

	store := &writeCountingStore{Store: memory.New()}
	gcfg := grant.Config{Storage: store, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile: p,
		Storage: store,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			"machine": confidentialClient([]string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeImplicit}, []string{"read"}),
		}},
		IssuerResolver: oauth2.StaticIssuer(testIssuer, "api"),
		Grants:         []oauth2.Grant{grant.NewClientCredentials(gcfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.NoError(t, err)

	return srv, store
}

// TestAuthorizeRefusesTheCodeFlowWithoutItsGrant keeps /authorize
// consistent with what the metadata advertises (RFC 8414 §2
// response_types_supported): a server without the authorization_code grant
// mints no code that nothing could redeem — response_type=code is answered
// unsupported_response_type, in the query, before the ConsentFunc runs and
// with nothing saved — while its implicit flow, when enabled, still works.
func TestAuthorizeRefusesTheCodeFlowWithoutItsGrant(t *testing.T) {
	t.Parallel()

	for _, p := range []oauth2.Profile{oauth2.Profile20, oauth2.Profile20BCP} {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()

			srv, store := codeGrantlessServer(t, p)
			cfg := oauth2.AuthorizeConfig{}

			if p == oauth2.Profile20 {
				cfg = oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}
			}

			consented := false
			rec := runAuthorizeCfg(srv, cfg, machineQuery(),
				func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
					consented = true

					return approve(w, r, ar)
				})

			params := redirectParams(t, rec, false)
			assert.Equal(t, oauth2.CodeUnsupportedResponseType, params.Get("error"))
			assert.Equal(t, "the authorization_code grant is not enabled", params.Get("error_description"))
			assert.Equal(t, testIssuer, params.Get("iss"))
			assert.False(t, params.Has("code"))
			assert.False(t, consented, "the ConsentFunc never runs")
			assert.Zero(t, store.writes.Load())

			if p != oauth2.Profile20 {
				return
			}

			q := machineQuery()
			q.Set("response_type", "token")
			q.Del("code_challenge")
			q.Del("code_challenge_method")

			fragment := redirectParams(t, runAuthorizeCfg(srv, cfg, q, approve), true)
			assert.NotEmpty(t, fragment.Get("access_token"), "the implicit flow still works")
		})
	}
}
