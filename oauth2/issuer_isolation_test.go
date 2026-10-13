// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// atHost posts form to path on host as the test client, through h.
func atHost(h http.Handler, host, path string, form url.Values) *httptest.ResponseRecorder {
	req := formRequest(path, form, true)
	req.Host = host

	return serve(h, req)
}

// realmTokens runs the code flow at a.example on a realm server and
// returns the access and refresh tokens its test client obtained.
func realmTokens(t *testing.T, srv *oauth2.Server) (string, string) {
	t.Helper()

	rec := tokenAt(srv, "a.example", codeExchangeForm(codeAt(t, srv, "a.example")))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	body := jsonBody(t, rec)
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	require.NotEmpty(t, at)
	require.NotEmpty(t, rt)

	return at, rt
}

// introspectedActive reports what /introspect at host says of raw.
func introspectedActive(t *testing.T, srv *oauth2.Server, host, raw string) bool {
	t.Helper()

	rec := atHost(srv.IntrospectHandler(), host, "/oauth2/introspect", url.Values{"token": {raw}})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	active, _ := jsonBody(t, rec)["active"].(bool)
	if !active {
		assert.JSONEq(t, inactiveBody, rec.Body.String(), "a bare inactive answer")
	}

	return active
}

// TestIntrospectionIsBoundToTheRequestIssuer pins issuer isolation at
// /introspect (OIDC Core §16.15, RFC 7662 §4): a token of another issuer is
// inactive at this one — for the client it was issued to too — even though
// the client is registered at both.
func TestIntrospectionIsBoundToTheRequestIssuer(t *testing.T) {
	t.Parallel()

	srv, _ := newRealmServer(t, hostIssuer{})
	at, rt := realmTokens(t, srv)

	assert.True(t, introspectedActive(t, srv, "a.example", at))
	assert.True(t, introspectedActive(t, srv, "a.example", rt))
	assert.False(t, introspectedActive(t, srv, "b.example", at), "the access token of another issuer")
	assert.False(t, introspectedActive(t, srv, "b.example", rt), "the refresh token of another issuer")
}

// TestRevocationIsBoundToTheRequestIssuer pins issuer isolation at /revoke
// (RFC 7009 §2.1): a token of another issuer is not revoked — the answer
// is 200 all the same — while a token recorded without issuer, written
// before tokens recorded one, is still revoked by its client: revocation
// only takes away.
func TestRevocationIsBoundToTheRequestIssuer(t *testing.T) {
	t.Parallel()

	srv, store := newRealmServer(t, hostIssuer{})
	at, rt := realmTokens(t, srv)

	for _, raw := range []string{at, rt} {
		rec := atHost(srv.RevokeHandler(), "b.example", "/oauth2/revoke", url.Values{"token": {raw}})
		require.Equal(t, http.StatusOK, rec.Code)
	}

	assert.True(t, introspectedActive(t, srv, "a.example", at), "untouched by a revocation at another issuer")
	assert.True(t, introspectedActive(t, srv, "a.example", rt), "untouched by a revocation at another issuer")

	rec := atHost(srv.RevokeHandler(), "a.example", "/oauth2/revoke", url.Values{"token": {at}})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.False(t, introspectedActive(t, srv, "a.example", at))
	assert.False(t, introspectedActive(t, srv, "a.example", rt), "the family went with it")

	legacy := newClientPair("legacy-rt", "fam-legacy")
	legacy.Access.Issuer, legacy.Refresh.Issuer = "", ""
	seedPair(t, store, legacy)

	rec = atHost(srv.RevokeHandler(), "a.example", "/oauth2/revoke", url.Values{"token": {legacy.Access.Token}})
	require.Equal(t, http.StatusOK, rec.Code)

	_, err := store.LookupAccessToken(t.Context(), legacy.Access.TokenHash)
	assert.Error(t, err, "an issuer-less token is revoked by its client")
}

// isolationEnv is a boundsEnv whose "machine" holds an access and a refresh
// token ("iso-rt"), and which also serves the confidential resource server
// "rs" (secret "rs-secret"), behind policy.
func isolationEnv(t *testing.T, policy oauth2.IntrospectionPolicy, pairs ...*oauth2.TokenPair) *boundsEnv {
	t.Helper()

	env := newBoundsEnv(t, 0, nil, nil)
	env.clients.clients["rs"] = &oauth2.DefaultClient{IDValue: "rs", Secret: "rs-secret", TypeValue: oauth2.ClientConfidential}

	cfg := env.srv.Config()
	cfg.IntrospectionPolicy = policy

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	env.srv = srv

	for _, p := range pairs {
		require.NoError(t, env.store.Store.SaveTokenPair(t.Context(), p))
	}

	return env
}

// machinePair is a pair of "machine", issued under issuer.
func machinePair(name, issuer string) *oauth2.TokenPair {
	pair := newClientPair(name, "fam-"+name)
	pair.Access.ClientID, pair.Refresh.ClientID = "machine", "machine"
	pair.Access.Issuer, pair.Refresh.Issuer = issuer, issuer

	return pair
}

// introspectAs introspects raw at env as the client id.
func introspectAs(t *testing.T, env *boundsEnv, id, secret, raw string) bool {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(url.Values{"token": {raw}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)

	rec := serve(env.srv.IntrospectHandler(), req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	active, _ := jsonBody(t, rec)["active"].(bool)

	return active
}

// TestRefreshTokensIntrospectOnlyForTheirClientByDefault: refresh tokens
// are meant for the authorization server and their client (RFC 6749 §1.5):
// without an IntrospectionPolicy, /introspect discloses one to its own
// client only — a resource server still sees access tokens. A policy, when
// set, decides.
func TestRefreshTokensIntrospectOnlyForTheirClientByDefault(t *testing.T) {
	t.Parallel()

	pair := machinePair("iso", "https://auth.example")

	env := isolationEnv(t, nil, pair)
	assert.False(t, introspectAs(t, env, "rs", "rs-secret", pair.Refresh.Token), "another client's refresh token")
	assert.True(t, introspectAs(t, env, "machine", "machine-secret", pair.Refresh.Token), "its own refresh token")
	assert.True(t, introspectAs(t, env, "rs", "rs-secret", pair.Access.Token), "a resource server sees access tokens")

	allowAll := func(context.Context, oauth2.Client, oauth2.IntrospectedToken) (bool, error) { return true, nil }
	env = isolationEnv(t, allowAll, pair)
	assert.True(t, introspectAs(t, env, "rs", "rs-secret", pair.Refresh.Token), "a policy decides")
}

// TestPolicySeesOnlyTokensOfTheRequestIssuer: the IntrospectionPolicy runs
// for tokens of the issuer the request resolved to only — so the token's
// Issuer it gets is the request's — and a token of another issuer, or
// recorded without issuer, is inactive without consulting it.
func TestPolicySeesOnlyTokensOfTheRequestIssuer(t *testing.T) {
	t.Parallel()

	var (
		calls  atomic.Int32
		issuer atomic.Value
	)

	spy := func(_ context.Context, _ oauth2.Client, tok oauth2.IntrospectedToken) (bool, error) {
		calls.Add(1)
		issuer.Store(tok.Issuer)

		return true, nil
	}

	own := machinePair("own", "https://auth.example")
	other := machinePair("other", "https://other.example")
	legacy := machinePair("legacy", "")

	env := isolationEnv(t, spy, own, other, legacy)

	assert.False(t, introspectAs(t, env, "rs", "rs-secret", other.Access.Token))
	assert.False(t, introspectAs(t, env, "rs", "rs-secret", legacy.Access.Token), "an issuer-less token at an issuer")
	assert.Zero(t, calls.Load(), "the policy never sees another issuer's token")

	assert.True(t, introspectAs(t, env, "rs", "rs-secret", own.Access.Token))
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, "https://auth.example", issuer.Load())
}
