// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package integrations_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyStubGrant registers a "password" grant_type without pulling in any
// implementation — it only needs to be present for NewServer's profile
// check to trip.
type legacyStubGrant struct{ typ string }

func (g legacyStubGrant) Type() string { return g.typ }
func (g legacyStubGrant) Handle(context.Context, oauth2.GrantRequest) (*oauth2.GrantResponse, error) {
	return nil, oauth2.ErrServerError
}

func TestTokenEndpointMissingGrantType(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(url.Values{}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, oauth2.CodeInvalidRequest, body["error"])
}

func TestTokenEndpointUnsupportedGrantType(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	form := url.Values{}
	form.Set("grant_type", "password") // not registered

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, oauth2.CodeUnsupportedGrantType, body["error"])
}

func TestTokenEndpointGetIsRejected(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/token", nil))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMetadataEndpointAdvertisesConfiguration(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	rec := httptest.NewRecorder()
	srv.MetadataHandler().ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))

	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "https://auth.example", body["issuer"])

	grants, _ := body["grant_types_supported"].([]any)
	assert.Len(t, grants, 2, "client_credentials + refresh_token")

	methods, _ := body["token_endpoint_auth_methods_supported"].([]any)
	assert.Contains(t, methods, "client_secret_basic")
	assert.Contains(t, methods, "client_secret_post")

	pkce, _ := body["code_challenge_methods_supported"].([]any)
	assert.Equal(t, []any{"S256"}, pkce, "BCP profile mandates S256-only PKCE")
}

func TestRevokeEndpointAlwaysReturns200(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	form := url.Values{}
	form.Set("token", "whatever-token-even-if-unknown")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	rec := httptest.NewRecorder()
	srv.RevokeHandler().ServeHTTP(rec, req)

	// RFC 7009 §2.2: the response MUST NOT reveal whether the token existed.
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestIntrospectEndpointReportsInactiveForUnknownToken(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	form := url.Values{}
	form.Set("token", "definitely-not-a-real-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	rec := httptest.NewRecorder()
	srv.IntrospectHandler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, false, body["active"])
}

// TestProfileBCPRefusesLegacyGrantsAtBoot asserts that NewServer refuses to
// register the legacy password / implicit grants under the BCP profile.
func TestProfileBCPRefusesLegacyGrantsAtBoot(t *testing.T) {
	t.Parallel()

	store := memory.New()
	clients := &staticClientStore{clients: map[string]oauth2.Client{
		clientID: &oauth2.DefaultClient{IDValue: clientID, Secret: clientSecret},
	}}

	_, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{legacyStubGrant{typ: "password"}},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "password")
}

// clientForm builds a POST form request authenticated as the demo client.
func clientForm(path string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	return req
}

// TestIntrospectAndRevokeOnIssuedTokens proves the token-hashing fix: a
// token minted by a grant is found by /introspect and /revoke — issuance
// and the lookup endpoints hash the token the same way.
func TestIntrospectAndRevokeOnIssuedTokens(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)

	// Mint an access token over client_credentials.
	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, clientForm("/oauth2/token",
		url.Values{"grant_type": {"client_credentials"}, "scope": {"api:read"}}))
	require.Equal(t, http.StatusOK, rec.Code)

	var issued map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issued))
	accessToken, _ := issued["access_token"].(string)
	require.NotEmpty(t, accessToken)

	introspect := func(t *testing.T) bool {
		t.Helper()

		rec := httptest.NewRecorder()
		srv.IntrospectHandler().ServeHTTP(rec, clientForm("/oauth2/introspect",
			url.Values{"token": {accessToken}}))
		require.Equal(t, http.StatusOK, rec.Code)

		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		active, _ := body["active"].(bool)

		return active
	}

	// The freshly issued token introspects as active.
	assert.True(t, introspect(t), "a grant-issued token must be introspectable")

	// Revoking it then makes it introspect as inactive.
	rec = httptest.NewRecorder()
	srv.RevokeHandler().ServeHTTP(rec, clientForm("/oauth2/revoke", url.Values{"token": {accessToken}}))
	require.Equal(t, http.StatusOK, rec.Code)

	assert.False(t, introspect(t), "a revoked token must introspect as inactive")
}
