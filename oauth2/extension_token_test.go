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
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The second client of the extension tests.
const (
	otherClientID     = "client-other"
	otherClientSecret = "secret-other" //nolint:gosec // test fixture
)

// contextData is the grant context the extension tests record.
const contextData = `{"auth_time":1791795600,"note":"\"\/<é> "}`

// recordingExtension records the issuances and answers an id_token naming
// the grant type.
func recordingExtension() *fakeExtension {
	return &fakeExtension{
		complete: func(context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time) (oauth2.ExtensionGrant, error) {
			return oauth2.ExtensionGrant{Data: contextData}, nil
		},
		extend: func(_ context.Context, ti oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
			return oauth2.TokenResponseExtension{IDToken: "id-token-" + ti.GrantType}, nil
		},
	}
}

// TestExtendTokenResponseInputs: the hook is handed, for the code exchange
// and for each refresh, the client the grant is bound to, a copy of the
// access token about to be persisted — its raw value the one the response
// carries — with the grant's issuer, subject, scope and context, and the
// code's nonce at the exchange only (OIDC Core §12.2).
func TestExtendTokenResponseInputs(t *testing.T) {
	t.Parallel()

	ext := recordingExtension()
	env := newExtensionEnv(t, ext)

	rec := env.exchange(env.code(t, oidcQuery(), approve))
	require.Equal(t, http.StatusOK, rec.Code)

	body := jsonBody(t, rec)
	assert.Equal(t, "id-token-authorization_code", body["id_token"])

	env.clock.Advance(time.Hour)

	refreshed := env.refresh(body["refresh_token"].(string))
	require.Equal(t, http.StatusOK, refreshed.Code)

	refreshBody := jsonBody(t, refreshed)
	assert.Equal(t, "id-token-refresh_token", refreshBody["id_token"])

	require.Len(t, ext.issuances, 2)

	for i, want := range []struct {
		grantType, nonce, accessToken string
		issuedAt                      time.Time
	}{
		{oauth2.GrantTypeAuthorizationCode, "n-0S6_WzA2Mj", body["access_token"].(string), env.clock.Now().Add(-time.Hour)},
		{oauth2.GrantTypeRefreshToken, "", refreshBody["access_token"].(string), env.clock.Now()},
	} {
		ti := ext.issuances[i]
		assert.True(t, ti.RefreshTokenIssued, "the exchange and the BCP rotation persist a refresh token")
		assert.Equal(t, want.grantType, ti.GrantType)
		assert.Equal(t, testClientID, ti.Client.ID())
		assert.Equal(t, want.nonce, ti.Nonce)
		assert.Equal(t, want.accessToken, ti.Access.Token)
		assert.Equal(t, oauth2.HashToken(nil, want.accessToken), ti.Access.TokenHash)
		assert.Equal(t, "alice", ti.Access.Subject)
		assert.Equal(t, "openid read", ti.Access.Scope)
		assert.Equal(t, "https://auth.example", ti.Access.Issuer)
		assert.Equal(t, contextData, ti.Access.ExtensionData)
		assert.Equal(t, "api", ti.Access.Audience)
		assert.Equal(t, want.issuedAt, ti.Access.IssuedAt)
	}
}

// TestTokenResponseMembersWithoutExtension: without an extension — or
// with one adding nothing — the token responses carry exactly the RFC 6749
// §5.1 members they always did, and the no-store headers.
func TestTokenResponseMembersWithoutExtension(t *testing.T) {
	t.Parallel()

	for name, ext := range map[string]oauth2.Extension{"none": nil, "silent": &fakeExtension{}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newExtensionEnv(t, ext)

			rec := env.exchange(env.code(t, oidcQuery(), approve))
			require.Equal(t, http.StatusOK, rec.Code)

			body := jsonBody(t, rec)
			assert.Equal(t, []string{"access_token", "expires_in", "refresh_token", "scope", "token_type"}, keys(body))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))

			rec = env.refresh(body["refresh_token"].(string))
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, []string{"access_token", "expires_in", "refresh_token", "scope", "token_type"}, keys(jsonBody(t, rec)))

			rec = env.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}})
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, []string{"access_token", "expires_in", "scope", "token_type"}, keys(jsonBody(t, rec)))
		})
	}
}

// TestExtensionCannotOverrideStandardMembers: an id_token crafted to
// smuggle members into the JSON body stays one string member; the RFC 6749
// §5.1 members are the server's.
func TestExtensionCannotOverrideStandardMembers(t *testing.T) {
	t.Parallel()

	const smuggled = `x","access_token":"evil","token_type":"none`

	ext := &fakeExtension{
		extend: func(context.Context, oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
			return oauth2.TokenResponseExtension{IDToken: smuggled}, nil
		},
	}
	env := newExtensionEnv(t, ext)

	rec := env.exchange(env.code(t, oidcQuery(), approve))
	require.Equal(t, http.StatusOK, rec.Code)

	body := jsonBody(t, rec)
	assert.Equal(t, []string{"access_token", "expires_in", "id_token", "refresh_token", "scope", "token_type"}, keys(body))
	assert.Equal(t, smuggled, body["id_token"])
	assert.Equal(t, oauth2.TokenTypeBearer, body["token_type"])
	assert.Equal(t, ext.issuances[0].Access.Token, body["access_token"])
}

// TestExtensionNotCalledWhenTheExchangeFails: every exchange the core
// refuses — another client, issuer or redirect_uri, a missing, malformed
// or wrong verifier, an expired or replayed code — is refused before the
// token-response hook runs, and persists nothing.
func TestExtensionNotCalledWhenTheExchangeFails(t *testing.T) {
	t.Parallel()

	const wrongVerifier = "wrong-verifier-wrong-verifier-wrong-verifier-0123"

	cases := map[string]func(*extensionEnv, string) *httptest.ResponseRecorder{
		"another client": func(env *extensionEnv, code string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			env.srv.TokenHandler().ServeHTTP(rec,
				basicForm("/oauth2/token", codeExchangeForm(code), otherClientID, otherClientSecret))

			return rec
		},
		"another redirect_uri": func(env *extensionEnv, code string) *httptest.ResponseRecorder {
			form := codeExchangeForm(code)
			form.Set("redirect_uri", "https://app.example/other")

			return env.token(form)
		},
		"missing verifier": func(env *extensionEnv, code string) *httptest.ResponseRecorder {
			form := codeExchangeForm(code)
			form.Del("code_verifier")

			return env.token(form)
		},
		"malformed verifier": func(env *extensionEnv, code string) *httptest.ResponseRecorder {
			form := codeExchangeForm(code)
			form.Set("code_verifier", "x")

			return env.token(form)
		},
		"wrong verifier": func(env *extensionEnv, code string) *httptest.ResponseRecorder {
			form := codeExchangeForm(code)
			form.Set("code_verifier", wrongVerifier)

			return env.token(form)
		},
		"expired code": func(env *extensionEnv, code string) *httptest.ResponseRecorder {
			env.clock.Advance(11 * time.Minute)

			return env.exchange(code)
		},
		"unknown code": func(env *extensionEnv, _ string) *httptest.ResponseRecorder {
			return env.exchange("never-issued")
		},
	}

	for name, exchange := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ext := recordingExtension()
			store := &writeCountingStore{Store: memory.New()}
			env := newExtensionEnv(t, ext, withStore(store), withSecondClient())

			code := env.code(t, oidcQuery(), approve)
			writes := store.writes.Load()

			rec := exchange(env, code)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.NotContains(t, jsonBody(t, rec), "id_token")
			assert.Empty(t, ext.issuances)
			assert.Equal(t, writes, store.writes.Load(), "nothing persisted")
		})
	}

	t.Run("replayed code", func(t *testing.T) {
		t.Parallel()

		ext := recordingExtension()
		env := newExtensionEnv(t, ext)
		code := env.code(t, oidcQuery(), approve)

		require.Equal(t, http.StatusOK, env.exchange(code).Code)

		rec := env.exchange(code)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.NotContains(t, jsonBody(t, rec), "id_token")
		assert.Len(t, ext.issuances, 1, "only the first exchange reached the hook")
	})

	t.Run("another issuer", func(t *testing.T) {
		t.Parallel()

		ext := recordingExtension()
		env := newExtensionEnv(t, ext, withResolver(hostIssuer{}))

		req := httptest.NewRequest(http.MethodGet, "/authorize?"+oidcQuery().Encode(), nil)
		req.Host = "a.example"

		rec := httptest.NewRecorder()
		env.srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, approve).ServeHTTP(rec, req)

		code := mustLocation(t, rec).Query().Get("code")
		require.NotEmpty(t, code)

		rec = tokenAt(env.srv, "b.example", codeExchangeForm(code))
		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Empty(t, ext.issuances)
	})
}

// withSecondClient registers otherClientID next to the test client.
func withSecondClient() envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config) {
		clients := s.ClientStore.(*staticClientStore) //nolint:forcetypeassert // test wiring
		clients.clients[otherClientID] = &oauth2.DefaultClient{
			GrantTypeValues: allGrantTypes,
			IDValue:         otherClientID, Secret: otherClientSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{redirectURI}, ScopeValues: []string{"openid", "read", "write"},
		}
	}
}

// TestExtensionNotCalledByGrantsWithoutAuthorization: client_credentials
// and the legacy password grant mint tokens without an authorization to
// extend: the hook never runs and they answer no id_token.
func TestExtensionNotCalledByGrantsWithoutAuthorization(t *testing.T) {
	t.Parallel()

	ext := recordingExtension()
	store := memory.New()
	gcfg := grant.Config{Storage: store, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile: oauth2.Profile20, Storage: store, Extension: ext,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			testClientID: &oauth2.DefaultClient{
				GrantTypeValues: allGrantTypes, IDValue: testClientID, Secret: testClientSecret,
				TypeValue: oauth2.ClientConfidential, ScopeValues: []string{"openid"},
			},
		}},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		Grants: []oauth2.Grant{
			grant.NewClientCredentials(gcfg),
			grant.NewLegacyPassword(gcfg, staticOwner{}),
		},
	})
	require.NoError(t, err)

	for _, form := range []url.Values{
		{"grant_type": {"client_credentials"}, "scope": {"openid"}},
		{"grant_type": {"password"}, "username": {"alice"}, "password": {"pw"}, "scope": {"openid"}},
	} {
		rec := httptest.NewRecorder()
		srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token", form, true))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotContains(t, jsonBody(t, rec), "id_token")
	}

	assert.Empty(t, ext.issuances)
}

// staticOwner authenticates every resource owner as alice.
type staticOwner struct{}

func (staticOwner) VerifyResourceOwner(context.Context, string, string) (string, error) {
	return "alice", nil
}
