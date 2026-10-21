// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenRequest checks RFC 6749 §4.1.3 and RFC 7636 §4.5.
func TestTokenRequest(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)

	op.set(func(op *fakeOP) {
		require.Len(t, op.tokenRequests, 1)
		req := op.tokenRequests[0]

		assert.Equal(t, http.MethodPost, req.method)
		assert.Equal(t, "application/x-www-form-urlencoded", req.contentType)
		assert.Equal(t, "application/json", req.accept)
		assert.Equal(t, "authorization_code", req.form.Get("grant_type"))
		assert.Equal(t, testRedirectURL, req.form.Get("redirect_uri"))
		assert.Regexp(t, b64url43, req.form.Get("code_verifier"))
		assert.ElementsMatch(t, []string{"grant_type", "code", "redirect_uri", "code_verifier"}, keys(req.form))
	})
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	return out
}

// TestTokenClientAuthentication checks the three methods of OpenID Connect
// Core §9, client_secret_basic form-urlencoding the identifier and the
// secret before Base64 (RFC 6749 §2.3.1, Appendix B).
func TestTokenClientAuthentication(t *testing.T) {
	t.Parallel()

	t.Run("client_secret_basic with special characters", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) {
			op.clientID = "client:1"
			op.clientSecret = "a b:c%d+é"
		})
		c := op.client(t, func(cfg *oidcclient.Config) {
			cfg.ClientID = "client:1"
			cfg.ClientSecret = oidcclient.NewSecret("a b:c%d+é")
		})

		_, err := op.login(t, c)
		require.NoError(t, err)

		op.set(func(op *fakeOP) {
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("client%3A1:a+b%3Ac%25d%2B%C3%A9"))
			assert.Equal(t, want, op.tokenRequests[0].authorization)
			assert.False(t, op.tokenRequests[0].form.Has("client_id"), "one authentication method per request")
			assert.False(t, op.tokenRequests[0].form.Has("client_secret"))
		})
	})

	t.Run("client_secret_post", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) { op.authMethod = oidcclient.AuthMethodClientSecretPost })
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.AuthMethod = oidcclient.AuthMethodClientSecretPost })

		_, err := op.login(t, c)
		require.NoError(t, err)

		op.set(func(op *fakeOP) {
			assert.Empty(t, op.tokenRequests[0].authorization)
			assert.Equal(t, testClientID, op.tokenRequests[0].form.Get("client_id"))
			assert.Equal(t, testClientSecret, op.tokenRequests[0].form.Get("client_secret"))
		})
	})

	t.Run("none", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) { op.authMethod = oidcclient.AuthMethodNone })
		c := op.client(t, func(cfg *oidcclient.Config) {
			cfg.AuthMethod = oidcclient.AuthMethodNone
			cfg.ClientSecret = oidcclient.Secret{}
		})

		_, err := op.login(t, c)
		require.NoError(t, err)

		op.set(func(op *fakeOP) {
			assert.Empty(t, op.tokenRequests[0].authorization)
			assert.Equal(t, testClientID, op.tokenRequests[0].form.Get("client_id"))
			assert.False(t, op.tokenRequests[0].form.Has("client_secret"))
		})
	})
}

// TestTokenRedirectNotFollowed checks that a redirect of the token request
// — which carries the code, the verifier and the client credentials — is
// never followed, whatever the outbound policy allows.
func TestTokenRedirectNotFollowed(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(elsewhere.Close)

	op := newFakeOP(t)
	op.set(func(op *fakeOP) {
		op.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+"/token", http.StatusTemporaryRedirect)
		}
	})
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.Outbound.MaxRedirects = 5 })

	id, err := op.login(t, c)
	require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint)
	assert.Nil(t, id)
	assert.Zero(t, hits.Load())

	t.Run("on the same origin", func(t *testing.T) {
		t.Parallel()

		// Discovery and JWK Set requests may follow such a redirect; the
		// token request, which carries the client's credentials, may not.
		op := newFakeOP(t)
		op.set(func(op *fakeOP) { op.redirects = map[string]string{"/token": "/token-v2"} })

		id, err := op.login(t, op.client(t, maxRedirects(5)))
		require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint)
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
		assert.Nil(t, id)
		assert.Zero(t, op.hitCount("/token-v2"), "the code, the verifier and the secret are never re-sent")
	})
}

// TestTokenResponse checks the successful response of RFC 6749 §5.1 and
// OpenID Connect Core §3.1.3.3, parsed strictly.
func TestTokenResponse(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		hook  func(body map[string]any)
		check func(t *testing.T, id *oidcclient.Identity)
		ok    bool
	}{
		"lower-case bearer":      {hook: func(b map[string]any) { b["token_type"] = "bearer" }, ok: true},
		"expires_in as a string": {hook: func(b map[string]any) { b["expires_in"] = "3599" }, ok: true, check: expiry(3599)},
		"expires_in absent":      {hook: func(b map[string]any) { delete(b, "expires_in") }, ok: true, check: noExpiry},
		"expires_in zero":        {hook: func(b map[string]any) { b["expires_in"] = 0 }, ok: true, check: expiry(0)},
		"expires_in maximal":     {hook: func(b map[string]any) { b["expires_in"] = 1<<31 - 1 }, ok: true, check: expiry(1<<31 - 1)},
		"scope not a string":     {hook: func(b map[string]any) { b["scope"] = []string{"openid"} }, ok: true, check: noScope},
		"refresh token absent":   {hook: func(b map[string]any) { delete(b, "refresh_token") }, ok: true},
		"unknown member":         {hook: func(b map[string]any) { b["foo"] = map[string]any{"bar": 1} }, ok: true},
		"no access token":        {hook: func(b map[string]any) { delete(b, "access_token") }},
		"empty access token":     {hook: func(b map[string]any) { b["access_token"] = "" }},
		"access token control":   {hook: func(b map[string]any) { b["access_token"] = "a\nb" }},
		"access token number":    {hook: func(b map[string]any) { b["access_token"] = 1 }},
		"no token type":          {hook: func(b map[string]any) { delete(b, "token_type") }},
		"dpop token type":        {hook: func(b map[string]any) { b["token_type"] = "DPoP" }},
		"no id token":            {hook: func(b map[string]any) { delete(b, "id_token") }},
		"id token number":        {hook: func(b map[string]any) { b["id_token"] = 1 }},
		"id token too large":     {hook: func(b map[string]any) { b["id_token"] = strings.Repeat("a", 64<<10+1) }},
		"negative expires_in":    {hook: func(b map[string]any) { b["expires_in"] = -1 }},
		"fractional expires_in":  {hook: func(b map[string]any) { b["expires_in"] = 1.5 }},
		"huge expires_in":        {hook: func(b map[string]any) { b["expires_in"] = 1 << 31 }},
		"expires_in bad string":  {hook: func(b map[string]any) { b["expires_in"] = "1h" }},
		"expires_in boolean":     {hook: func(b map[string]any) { b["expires_in"] = true }},
		"refresh token number":   {hook: func(b map[string]any) { b["refresh_token"] = 42 }},
		"refresh token control":  {hook: func(b map[string]any) { b["refresh_token"] = "r\tt" }},
		"token type with space":  {hook: func(b map[string]any) { b["token_type"] = "Bearer x" }},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.tokenHook = func(_ *grant, body map[string]any) { tc.hook(body) } })
			c := op.client(t)

			id, err := op.login(t, c)
			if !tc.ok {
				require.ErrorIs(t, err, oidcclient.ErrInvalidTokenResponse)
				assert.Nil(t, id)

				return
			}

			require.NoError(t, err)

			if tc.check != nil {
				tc.check(t, id)
			}
		})
	}
}

func expiry(seconds int64) func(*testing.T, *oidcclient.Identity) {
	return func(t *testing.T, id *oidcclient.Identity) {
		t.Helper()
		assert.Equal(t, testNow.Add(time.Duration(seconds)*time.Second), id.Tokens.Expiry)
	}
}

func noExpiry(t *testing.T, id *oidcclient.Identity) {
	t.Helper()
	assert.True(t, id.Tokens.Expiry.IsZero())
}

func noScope(t *testing.T, id *oidcclient.Identity) {
	t.Helper()
	assert.Empty(t, id.Tokens.Scope)
}

// TestTokenResponseRaw checks responses a map cannot express.
func TestTokenResponseRaw(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		contentType string
		status      int
		body        string
		err         error
		tokenErr    *oidcclient.TokenError
	}{
		"duplicate access_token": {
			contentType: "application/json", status: 200, err: oidcclient.ErrInvalidTokenResponse,
			body: `{"access_token":"a","access_token":"b","token_type":"Bearer","id_token":"x.y.z"}`,
		},
		"case-variant member": {
			contentType: "application/json", status: 200, err: oidcclient.ErrInvalidTokenResponse,
			body: `{"access_token":"a","Access_Token":"b","token_type":"Bearer","id_token":"x.y.z"}`,
		},
		"not json": {contentType: "text/plain", status: 200, body: `access_token=a`, err: oidcclient.ErrInvalidTokenResponse},
		"json body, text content type": {
			contentType: "text/plain", status: 200, err: oidcclient.ErrInvalidTokenResponse,
			body: `{"access_token":"a","token_type":"Bearer","id_token":"x.y.z"}`,
		},
		"invalid grant": {
			contentType: "application/json", status: 400, err: oidcclient.ErrTokenEndpoint,
			body:     `{"error":"invalid_grant","error_description":"code expired"}`,
			tokenErr: &oidcclient.TokenError{StatusCode: 400, Code: "invalid_grant", Description: "code expired"},
		},
		"invalid client": {
			contentType: "application/json", status: 401, err: oidcclient.ErrTokenEndpoint,
			body:     `{"error":"invalid_client","error_uri":"https://op.example.com/e"}`,
			tokenErr: &oidcclient.TokenError{StatusCode: 401, Code: "invalid_client", URI: "https://op.example.com/e"},
		},
		"description outside charset dropped": {
			contentType: "application/json", status: 400, err: oidcclient.ErrTokenEndpoint,
			body:     `{"error":"invalid_grant","error_description":"say \"no\""}`,
			tokenErr: &oidcclient.TokenError{StatusCode: 400, Code: "invalid_grant"},
		},
		"error code outside charset": {contentType: "application/json", status: 400, body: `{"error":"bad\"code"}`, err: oidcclient.ErrTokenEndpoint},
		"error without code":         {contentType: "application/json", status: 400, body: `{}`, err: oidcclient.ErrTokenEndpoint},
		"html error":                 {contentType: "text/html", status: 400, body: `<html>`, err: oidcclient.ErrTokenEndpoint},
		"server error":               {contentType: "application/json", status: 500, body: `{"error":"server_error"}`, err: oidcclient.ErrTokenEndpoint},
		"created":                    {contentType: "application/json", status: 201, body: `{}`, err: oidcclient.ErrTokenEndpoint},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) {
				op.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", tc.contentType)
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
				}
			})
			c := op.client(t)

			id, err := op.login(t, c)
			require.ErrorIs(t, err, tc.err)
			assert.Nil(t, id)

			var tokenErr *oidcclient.TokenError
			if tc.tokenErr == nil {
				assert.NotErrorAs(t, err, &tokenErr)

				return
			}

			require.ErrorAs(t, err, &tokenErr)
			assert.Equal(t, *tc.tokenErr, *tokenErr)
			assert.NotContains(t, err.Error(), tc.tokenErr.Description+"x", "description stays out of Error()")
		})
	}

	t.Run("token endpoint down", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		down := httptest.NewTLSServer(http.NotFoundHandler())
		down.Close()
		op.set(func(op *fakeOP) { op.metadata["token_endpoint"] = down.URL + "/token" })
		c := op.client(t)

		_, err := op.login(t, c)
		require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint)
	})

	t.Run("oversized response", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) {
			op.tokenHook = func(_ *grant, body map[string]any) { body["padding"] = strings.Repeat("p", 4096) }
		})
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.Outbound.MaxResponseBytes = 4096 })

		_, err := op.login(t, c)
		require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint)
	})
}
