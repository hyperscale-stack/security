// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unmatchableClient is a confidential client that cannot verify a secret:
// the generated Client mock implements oauth2.Client, not
// oauth2.SecretMatcher.
func unmatchableClient(t *testing.T) *oauth2.MockClient {
	t.Helper()

	client := oauth2.NewMockClient(t)
	client.EXPECT().ID().Return("unmatchable").Maybe()
	client.EXPECT().Type().Return(oauth2.ClientConfidential).Maybe()
	client.EXPECT().RedirectURIs().Return(nil).Maybe()
	client.EXPECT().GrantTypes().Return([]string{oauth2.GrantTypeClientCredentials}).Maybe()
	client.EXPECT().Scopes().Return([]string{"read"}).Maybe()
	client.EXPECT().AuthMethods().Return(nil).Maybe()

	return client
}

// clientAuthFailures are client authentications every endpoint refuses,
// each with the detail of its refusal.
func clientAuthFailures(t *testing.T) []struct {
	name, detail string
	cause        error
	req          func(path string, form url.Values) *http.Request
} {
	t.Helper()

	basicAs := func(id, secret string) func(string, url.Values) *http.Request {
		return func(path string, form url.Values) *http.Request {
			req := boundsPost(path, strings.NewReader(form.Encode()))
			req.SetBasicAuth(id, secret)

			return req
		}
	}
	bodyAs := func(extra url.Values) func(string, url.Values) *http.Request {
		return func(path string, form url.Values) *http.Request {
			body := url.Values{}
			for k, v := range form {
				body[k] = v
			}

			for k, v := range extra {
				body[k] = v
			}

			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			return req
		}
	}

	return []struct {
		name, detail string
		cause        error
		req          func(path string, form url.Values) *http.Request
	}{
		{name: "unknown client (basic)", detail: "unknown client", req: basicAs("ghost", "secret")},
		{name: "unknown client (post)", detail: "unknown client", req: bodyAs(url.Values{"client_id": {"ghost"}, "client_secret": {"x"}})},
		{name: "unknown client (none)", detail: "unknown client", req: bodyAs(url.Values{"client_id": {"ghost"}})},
		{name: "wrong secret (basic)", detail: "client authentication failed", req: basicAs("machine", "wrong")},
		{name: "wrong secret (post)", detail: "client authentication failed", req: bodyAs(url.Values{"client_id": {"machine"}, "client_secret": {"wrong"}})},
		{name: "method not allowed", detail: "method not allowed for client", req: bodyAs(url.Values{"client_id": {"basiconly"}, "client_secret": {"basiconly-secret"}})},
		{name: "none for a confidential client", detail: "none method reserved to public clients", req: bodyAs(url.Values{"client_id": {"machine"}})},
		{name: "client unable to verify a secret", detail: "client cannot verify secret", req: basicAs("unmatchable", "secret")},
		{name: "malformed Basic header", detail: "malformed Basic Authorization header", req: func(path string, form url.Values) *http.Request {
			req := boundsPost(path, strings.NewReader(form.Encode()))
			req.Header.Set("Authorization", "Basic %%%")

			return req
		}},
		{name: "empty Basic password", detail: "missing client_id or client_secret", req: basicAs("machine", "")},
		{name: "no credentials", detail: "no client authentication method matched", req: bodyAs(nil)},
		{name: "client of another issuer", detail: "unknown client", cause: oauth2.ErrClientNotAtIssuer, req: basicAs("elsewhere", "elsewhere-secret")},
	}
}

// failuresEnv is a boundsEnv also serving "basiconly" (client_secret_basic
// only), "unmatchable" (no SecretMatcher) and "elsewhere" (registered at
// another issuer).
func failuresEnv(t *testing.T) *boundsEnv {
	t.Helper()

	env := newBoundsEnv(t, 0, nil, nil)

	basicOnly := confidentialClient([]string{oauth2.GrantTypeClientCredentials}, []string{"read"})
	basicOnly.IDValue, basicOnly.Secret, basicOnly.AuthMethodValues = "basiconly", "basiconly-secret", []string{"client_secret_basic"}
	env.clients.clients["basiconly"] = basicOnly

	elsewhere := confidentialClient([]string{oauth2.GrantTypeClientCredentials}, []string{"read"})
	elsewhere.IDValue, elsewhere.Secret, elsewhere.IssuerValues = "elsewhere", "elsewhere-secret", []string{"https://other.example"}
	env.clients.clients["elsewhere"] = elsewhere

	env.clients.clients["unmatchable"] = unmatchableClient(t)

	return env
}

// requireConstantInvalidClient asserts the one answer every failed client
// authentication gets — 401 invalid_client, "client authentication
// failed", the Basic challenge — and that the hook got the refusal it
// replaced: its detailed description, and cause.
func requireConstantInvalidClient(t *testing.T, env *boundsEnv, rec *httptest.ResponseRecorder, detail string, cause error) {
	t.Helper()

	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"error":"invalid_client","error_description":"client authentication failed"}`, rec.Body.String())
	assert.Equal(t, `Basic realm="oauth2"`, rec.Header().Get("WWW-Authenticate"))

	reported := env.sink.collected()
	require.Len(t, reported, 1)

	var envelope *oauth2.Error

	require.ErrorAs(t, reported[0], &envelope)
	assert.Equal(t, oauth2.CodeInvalidClient, envelope.Code)

	var detailed *oauth2.Error

	require.ErrorAs(t, envelope.Unwrap(), &detailed, "the refusal it replaced is in the cause")
	assert.Equal(t, detail, detailed.Description)

	if cause != nil {
		assert.ErrorIs(t, reported[0], cause)
	}
}

// TestClientAuthenticationFailuresLookAlike pins RFC 6749 §5.2 without the
// enumeration oracle: whatever made a client authentication fail — an
// unknown client, a client of another issuer, a wrong secret, a method the
// client may not use, a malformed credential — /token, /revoke and
// /introspect answer the very same bytes; only the ErrorHook learns the
// detail.
func TestClientAuthenticationFailuresLookAlike(t *testing.T) {
	t.Parallel()

	endpoints := []struct {
		path    string
		form    url.Values
		handler func(*oauth2.Server) http.Handler
	}{
		{"/oauth2/token", url.Values{"grant_type": {"client_credentials"}}, (*oauth2.Server).TokenHandler},
		{"/oauth2/revoke", url.Values{"token": {"ghost"}}, (*oauth2.Server).RevokeHandler},
		{"/oauth2/introspect", url.Values{"token": {"ghost"}}, (*oauth2.Server).IntrospectHandler},
	}

	for _, ep := range endpoints {
		for _, tc := range clientAuthFailures(t) {
			t.Run(ep.path+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				env := failuresEnv(t)
				rec := serve(ep.handler(env.srv), tc.req(ep.path, ep.form))

				requireConstantInvalidClient(t, env, rec, tc.detail, tc.cause)
			})
		}
	}
}

// errPublicCaller stands for the introspection refusal of a public caller:
// the hook gets its description.
var errPublicCaller = errors.New("introspection requires confidential client authentication")

// TestIntrospectionOfAPublicCallerLooksAlike: a public client — whose
// client_id authenticates nothing — gets the same invalid_client bytes at
// /introspect as any other failed caller.
func TestIntrospectionOfAPublicCallerLooksAlike(t *testing.T) {
	t.Parallel()

	env := failuresEnv(t)
	env.clients.clients["spa"] = &oauth2.DefaultClient{
		IDValue: "spa", TypeValue: oauth2.ClientPublic, GrantTypeValues: []string{oauth2.GrantTypeAuthorizationCode},
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader("token=ghost&client_id=spa"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := serve(env.srv.IntrospectHandler(), req)
	requireConstantInvalidClient(t, env, rec, errPublicCaller.Error(), nil)
}
