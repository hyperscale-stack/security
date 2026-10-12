// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const userInfoPath = "/oauth2/userinfo"

// bearerGET is the canonical UserInfo request: GET, the access token in the
// Authorization header (RFC 6750 §2.1).
func bearerGET(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, userInfoPath, nil)
	r.Header.Set("Authorization", "Bearer "+token)

	return r
}

// formPOST posts body form-encoded to /userinfo (RFC 6750 §2.2).
func formPOST(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, userInfoPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return r
}

// userinfo serves r through the provider's UserInfo handler.
func (e *env) userinfo(r *http.Request) *httptest.ResponseRecorder {
	return serve(e.op.UserInfoHandler(), r)
}

// userInfoClaims decodes a successful UserInfo response.
func userInfoClaims(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var claims map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &claims))

	return claims
}

var challengeParam = regexp.MustCompile(`([a-z_]+)="((?:[^"\\]|\\.)*)"`)

// challenge parses the Bearer challenge of a response (RFC 6750 §3).
func challenge(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	values := rec.Header().Values("WWW-Authenticate")
	require.Len(t, values, 1, "exactly one challenge")
	require.True(t, strings.HasPrefix(values[0], "Bearer "), values[0])

	params := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(values[0], -1) {
		params[m[1]] = m[2]
	}

	return params
}

// revoke revokes token at the revocation endpoint (RFC 7009) as the web
// client.
func (e *env) revoke(token string) {
	e.t.Helper()

	r := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(url.Values{"token": {token}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(webClientID), url.QueryEscape(webClientSecret))

	require.Equal(e.t, http.StatusOK, serve(e.op.Server().RevokeHandler(), r).Code)
}

// flakyStore is a memory store whose access-token lookups can be made to
// fail.
type flakyStore struct {
	*memory.Store

	failing atomic.Bool
	// silent makes lookups return neither a record nor an error.
	silent atomic.Bool
}

func (s *flakyStore) LookupAccessToken(ctx context.Context, hash string) (*oauth2.AccessToken, error) {
	if s.failing.Load() {
		return nil, errors.New("database unavailable")
	}

	if s.silent.Load() {
		return nil, nil
	}

	return s.Store.LookupAccessToken(ctx, hash) //nolint:wrapcheck // test double
}

func withFlaky(s *flakyStore) envOption {
	return func(sc *oauth2.ServerConfig, g *grant.Config, _ *oidcprovider.Config) {
		s.Store = sc.Storage.(*memory.Store) //nolint:forcetypeassert // the env's own store
		sc.Storage, g.Storage = s, s
	}
}

// TestUserInfoMethods pins OIDC Core §5.3.1 and RFC 6750 §2: GET or POST,
// the token in the Authorization header or, on POST, in the form body; the
// URI query is not a supported method.
func TestUserInfoMethods(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	at := e.flow(authorizeQuery()).AccessToken

	assert.Equal(t, "alice", userInfoClaims(t, e.userinfo(bearerGET(at)))["sub"])

	post := httptest.NewRequest(http.MethodPost, userInfoPath, strings.NewReader(`{"x":1}`))
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Authorization", "Bearer "+at)
	assert.Equal(t, "alice", userInfoClaims(t, e.userinfo(post))["sub"], "a non-form body is not a token method")

	assert.Equal(t, "alice", userInfoClaims(t, e.userinfo(formPOST("access_token="+at)))["sub"])

	other := formPOST("schema=openid")
	other.Header.Set("Authorization", "Bearer "+at)
	assert.Equal(t, "alice", userInfoClaims(t, e.userinfo(other))["sub"], "a form body without access_token is no method")

	lower := httptest.NewRequest(http.MethodGet, userInfoPath, nil)
	lower.Header.Set("Authorization", "bearer "+at)
	assert.Equal(t, "alice", userInfoClaims(t, e.userinfo(lower))["sub"], "the scheme is case-insensitive")

	spaces := httptest.NewRequest(http.MethodGet, userInfoPath, nil)
	spaces.Header.Set("Authorization", "Bearer   "+at)
	assert.Equal(t, "alice", userInfoClaims(t, e.userinfo(spaces))["sub"], `"Bearer" 1*SP b64token`)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodPatch} {
		r := bearerGET(at)
		r.Method = method
		rec := e.userinfo(r)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, method)
		assert.Equal(t, "GET, POST", rec.Header().Get("Allow"), method)
	}

	t.Run("query token alone is ignored", func(t *testing.T) {
		t.Parallel()

		rec := e.userinfo(httptest.NewRequest(http.MethodGet, userInfoPath+"?access_token="+at, nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, map[string]string{"realm": testIssuer}, challenge(t, rec))
	})

	t.Run("token in a body that is not form-encoded", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodPost, userInfoPath, strings.NewReader("access_token="+at))
		r.Header.Set("Content-Type", "text/plain")
		rec := e.userinfo(r)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, map[string]string{"realm": testIssuer}, challenge(t, rec))
	})

	t.Run("form POST without a body", func(t *testing.T) {
		t.Parallel()

		r := formPOST("")
		r.Body = nil
		rec := e.userinfo(r)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, map[string]string{"realm": testIssuer}, challenge(t, rec))
	})

	t.Run("form body on GET is ignored", func(t *testing.T) {
		t.Parallel()

		r := formPOST("access_token=" + at)
		r.Method = http.MethodGet
		rec := e.userinfo(r)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, map[string]string{"realm": testIssuer}, challenge(t, rec))
	})
}

// TestUserInfoTokenMethods pins RFC 6750 §2 and §3.1: more than one method,
// or a malformed one, is invalid_request (400) — in a Bearer challenge too.
func TestUserInfoTokenMethods(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	at := e.flow(authorizeQuery()).AccessToken

	withHeader := func(r *http.Request, values ...string) *http.Request {
		for _, v := range values {
			r.Header.Add("Authorization", v)
		}

		return r
	}

	cases := map[string]*http.Request{
		"header and body": withHeader(formPOST("access_token="+at), "Bearer "+at),
		"two headers": withHeader(httptest.NewRequest(http.MethodGet, userInfoPath, nil),
			"Bearer "+at, "Bearer "+at),
		"bearer and basic headers": withHeader(httptest.NewRequest(http.MethodGet, userInfoPath, nil),
			"Bearer "+at, "Basic d2ViOnNlY3JldA=="),
		"duplicated body parameter": formPOST("access_token=" + at + "&access_token=" + at),
		"empty body parameter":      formPOST("access_token="),
		"query and header": withHeader(httptest.NewRequest(http.MethodGet, userInfoPath+"?access_token="+at, nil),
			"Bearer "+at),
		"query and body": func() *http.Request {
			r := formPOST("access_token=" + at)
			r.URL.RawQuery = "access_token=" + at

			return r
		}(),
		"bearer without token":  withHeader(httptest.NewRequest(http.MethodGet, userInfoPath, nil), "Bearer"),
		"bearer and spaces":     withHeader(httptest.NewRequest(http.MethodGet, userInfoPath, nil), "Bearer   "),
		"oversized body":        formPOST("access_token=" + at + "&pad=" + strings.Repeat("p", 16<<10)),
		"malformed body":        formPOST("access_token=%zz"),
		"malformed body anyway": withHeader(formPOST("a=%zz"), "Bearer "+at),
	}

	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := e.userinfo(r)
			assert.Equal(t, http.StatusBadRequest, rec.Code)

			params := challenge(t, rec)
			assert.Equal(t, testIssuer, params["realm"])
			assert.Equal(t, "invalid_request", params["error"])
			assert.NotEmpty(t, params["error_description"])
			assert.NotContains(t, rec.Header().Get("WWW-Authenticate"), at)
		})
	}
}

// TestUserInfoErrors pins RFC 6750 §3 and §3.1 and OIDC Core §5.3.3: the
// status and challenge of every failure; storage, claims source and issuer
// failures are server errors without a challenge.
func TestUserInfoErrors(t *testing.T) {
	t.Parallel()

	type outcome struct {
		status int
		code   string // "" for a challenge without error, "-" for no challenge
		realm  string // the test issuer when empty
	}

	invalidToken := outcome{http.StatusUnauthorized, "invalid_token", ""}
	internal := outcome{http.StatusInternalServerError, "-", ""}

	cases := []struct {
		name string
		opts []envOption
		// request returns the request to send, given the environment and an
		// access token of a fresh OpenID code flow.
		request func(t *testing.T, e *env, at string) *http.Request
		want    outcome
	}{
		{"no credentials", nil, func(*testing.T, *env, string) *http.Request {
			return httptest.NewRequest(http.MethodGet, userInfoPath, nil)
		}, outcome{http.StatusUnauthorized, "", ""}},
		{"another scheme", nil, func(*testing.T, *env, string) *http.Request {
			r := httptest.NewRequest(http.MethodGet, userInfoPath, nil)
			r.SetBasicAuth(webClientID, webClientSecret)

			return r
		}, outcome{http.StatusUnauthorized, "", ""}},
		{"token outside the b64token syntax", nil, func(_ *testing.T, _ *env, at string) *http.Request {
			return bearerGET(at + "@")
		}, invalidToken},
		{"padding inside the token", nil, func(_ *testing.T, _ *env, at string) *http.Request {
			return bearerGET("a=b" + at)
		}, invalidToken},
		{"padding only", nil, func(*testing.T, *env, string) *http.Request {
			return bearerGET("===")
		}, invalidToken},
		{"unknown token", nil, func(*testing.T, *env, string) *http.Request {
			return bearerGET("unknown-token")
		}, invalidToken},
		{"expired token", nil, func(_ *testing.T, e *env, at string) *http.Request {
			e.clock.Advance(time.Hour + time.Second)

			return bearerGET(at)
		}, invalidToken},
		{"revoked token", nil, func(_ *testing.T, e *env, at string) *http.Request {
			e.revoke(at)

			return bearerGET(at)
		}, invalidToken},
		{"token of another issuer", nil, func(_ *testing.T, _ *env, at string) *http.Request {
			r := bearerGET(at)
			r.Host = "other.example"

			return r
		}, outcome{http.StatusUnauthorized, "invalid_token", "https://other.example"}},
		{"an ID Token", nil, func(t *testing.T, e *env, _ string) *http.Request {
			return bearerGET(e.flow(authorizeQuery()).IDToken)
		}, invalidToken},
		{"client_credentials token", nil, func(t *testing.T, e *env, _ string) *http.Request {
			// Even with a source answering for the client ID: its sub is no
			// end-user.
			e.claims.users[webClientID] = map[string]any{"name": "Web App"}
			resp := tokens(t, e.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"openid profile"}}, webClientID))

			return bearerGET(resp.AccessToken)
		}, invalidToken},
		{"plain OAuth 2.0 token", nil, func(_ *testing.T, e *env, _ string) *http.Request {
			return bearerGET(e.flow(with(authorizeQuery(), "scope", "profile email", "nonce", "")).AccessToken)
		}, invalidToken},
		{"unknown subject", nil, func(_ *testing.T, e *env, at string) *http.Request {
			e.claims.removeUser("alice")

			return bearerGET(at)
		}, invalidToken},
		{"claims source failure", nil, func(_ *testing.T, e *env, at string) *http.Request {
			e.claims.fail(errors.New("directory down"))

			return bearerGET(at)
		}, internal},
		{"claim value JSON cannot encode", nil, func(_ *testing.T, e *env, at string) *http.Request {
			e.claims.users["alice"]["name"] = math.Inf(1)

			return bearerGET(at)
		}, internal},
		{"resolver failure", []envOption{withResolver(&switchIssuer{})}, func(_ *testing.T, e *env, at string) *http.Request {
			r := bearerGET(at)
			r.Host = switchFail

			return r
		}, internal},
		{"invalid issuer", []envOption{withResolver(&switchIssuer{})}, func(_ *testing.T, e *env, at string) *http.Request {
			r := bearerGET(at)
			r.Host = switchInsecure

			return r
		}, internal},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t, tc.opts...)
			at := e.flow(authorizeQuery()).AccessToken

			rec := e.userinfo(tc.request(t, e, at))
			assert.Equal(t, tc.want.status, rec.Code, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "alice")

			if tc.want.code == "-" {
				assert.Empty(t, rec.Header().Values("WWW-Authenticate"), "no challenge for a server error")

				return
			}

			realm := tc.want.realm
			if realm == "" {
				realm = testIssuer
			}

			params := challenge(t, rec)
			assert.Equal(t, realm, params["realm"])
			assert.Equal(t, tc.want.code, params["error"])

			if tc.want.code == "" {
				assert.Equal(t, map[string]string{"realm": realm}, params, "no error information without credentials")
			} else {
				assert.NotEmpty(t, params["error_description"])
			}
		})
	}

	t.Run("expiry boundary", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		at := e.flow(authorizeQuery()).AccessToken

		e.clock.Advance(time.Hour)
		assert.Equal(t, http.StatusOK, e.userinfo(bearerGET(at)).Code, "valid until ExpiresAt included")
	})

	t.Run("family revoked by a code replay", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		code := e.code(authorizeQuery())
		at := tokens(t, e.exchange(code)).AccessToken
		require.Equal(t, http.StatusOK, e.userinfo(bearerGET(at)).Code)

		assert.Equal(t, oauth2.CodeInvalidGrant, oauthError(t, e.exchange(code)))
		assert.Equal(t, "invalid_token", challenge(t, e.userinfo(bearerGET(at)))["error"])
	})

	t.Run("storage failure", func(t *testing.T) {
		t.Parallel()

		store := &flakyStore{}
		e := newEnv(t, withFlaky(store))
		at := e.flow(authorizeQuery()).AccessToken

		store.failing.Store(true)

		rec := e.userinfo(bearerGET(at))
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Empty(t, rec.Header().Values("WWW-Authenticate"))

		// A token outside the b64token syntax never reaches the store.
		for _, malformed := range []string{at + "@", "===", "=" + at, "a=b"} {
			assert.Equal(t, "invalid_token", challenge(t, e.userinfo(bearerGET(malformed)))["error"], malformed)
		}

		store.failing.Store(false)
		store.silent.Store(true)
		assert.Equal(t, http.StatusInternalServerError, e.userinfo(bearerGET(at)).Code, "a store breaking its contract")
	})

	t.Run("unreadable body", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		r := formPOST("")
		r.Body = io.NopCloser(iotest.ErrReader(errors.New("connection reset")))

		rec := e.userinfo(r)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "invalid_request", challenge(t, rec)["error"])
	})

	t.Run("token without openid", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		e.consentOffline()

		resp := e.flow(offlineQuery())
		narrowed := tokens(t, e.refresh(resp.RefreshToken, "profile")).AccessToken

		rec := e.userinfo(bearerGET(narrowed))
		assert.Equal(t, http.StatusForbidden, rec.Code)

		params := challenge(t, rec)
		assert.Equal(t, "insufficient_scope", params["error"])
		assert.Equal(t, "openid", params["scope"])
		assert.Equal(t, testIssuer, params["realm"])
	})
}

// TestUserInfoRefusesUnusableRecords: a record the provider cannot trust —
// written before issuers were recorded, or with a context it cannot read —
// is an invalid token.
func TestUserInfoRefusesUnusableRecords(t *testing.T) {
	t.Parallel()

	cases := map[string]oauth2.AccessToken{
		"record without issuer": {ExtensionData: `{"v":1,"auth_time":1760000000}`},
		"unreadable context":    {Issuer: testIssuer, ExtensionData: `{"v":2,"auth_time":1760000000}`},
	}

	for name, record := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			record.TokenHash = oauth2.HashToken(nil, "stored-token")
			record.ClientID, record.Subject, record.Scope = webClientID, "alice", "openid profile"
			record.IssuedAt, record.ExpiresAt = e.clock.Now(), e.clock.Now().Add(time.Hour)
			require.NoError(t, e.store.SaveTokenPair(t.Context(), &oauth2.TokenPair{Access: record}))

			rec := e.userinfo(bearerGET("stored-token"))
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, "invalid_token", challenge(t, rec)["error"])
		})
	}
}

// switchIssuer resolves the test issuer, except for two magic hosts: one
// whose resolution fails, one resolving to an http issuer.
type switchIssuer struct{}

const (
	switchFail     = "fail.example"
	switchInsecure = "insecure.example"
)

func (*switchIssuer) Resolve(_ context.Context, r *http.Request) (string, string, error) {
	switch r.Host {
	case switchFail:
		return "", "", errors.New("tenant directory down")
	case switchInsecure:
		return "http://op.example", "api", nil
	default:
		return testIssuer, "api", nil
	}
}

// TestUserInfoErrorsReachTheHook: every RFC 6750 error reaches the
// ErrorHook as an *oauth2.Error carrying its code, never the token.
func TestUserInfoErrorsReachTheHook(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	resp := e.flow(authorizeQuery())

	e.userinfo(bearerGET("unknown-token"))
	e.userinfo(formPOST("access_token=" + resp.AccessToken + "&access_token=x"))

	var codes []string

	for _, err := range e.sink.all() {
		var oe *oauth2.Error
		if errors.As(err, &oe) {
			codes = append(codes, oe.Code)
		}

		assert.NotContains(t, err.Error(), resp.AccessToken)
		assert.NotContains(t, err.Error(), "unknown-token")
	}

	assert.Contains(t, codes, "invalid_token")
	assert.Contains(t, codes, "invalid_request")
}

// TestUserInfoScopeClaims pins OIDC Core §5.4 and §5.3.2: the claims of the
// access token's scopes, language-tagged variants included, null and empty
// values omitted; a refreshed, narrower token gets fewer.
func TestUserInfoScopeClaims(t *testing.T) {
	t.Parallel()

	cases := map[string]map[string]any{
		"openid": {"sub": "alice"},
		"openid profile": {
			"sub": "alice", "name": "Alice Liddell", "name#fr": "Alice Liddell (fr)", "given_name": "Alice",
			"family_name": "Liddell", "updated_at": float64(1760000000),
		},
		"openid email":   {"sub": "alice", "email": "alice@example.com", "email_verified": true},
		"openid address": {"sub": "alice", "address": map[string]any{"country": "FR"}},
		"openid phone":   {"sub": "alice", "phone_number": "+33 1 23 45 67 89", "phone_number#x#y": "+0"},
	}

	for scope, want := range cases {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			at := e.flow(with(authorizeQuery(), "scope", scope)).AccessToken
			assert.Equal(t, want, userInfoClaims(t, e.userinfo(bearerGET(at))))
		})
	}

	t.Run("refreshed narrower scope", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		e.consentOffline()

		resp := e.flow(with(offlineQuery(), "scope", "openid profile email offline_access"))
		assert.Contains(t, userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken))), "email")

		narrowed := tokens(t, e.refresh(resp.RefreshToken, "openid profile")).AccessToken
		claims := userInfoClaims(t, e.userinfo(bearerGET(narrowed)))
		assert.Contains(t, claims, "name")
		assert.NotContains(t, claims, "email")
	})
}

// TestUserInfoClaimsParameter pins OIDC Core §5.5: the userinfo member
// releases the claims the end-user agreed to, value constraints applied;
// the id_token member does not reach UserInfo.
func TestUserInfoClaimsParameter(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	request := `{
		"userinfo": {"groups": null, "phone_number": {"value": "+33 1 23 45 67 89"}, "address": {"value": "x"},
			"nickname": null, "email": {"essential": true}},
		"id_token": {"given_name": null}
	}`
	e.approveWith(func(req *oidcprovider.Request) *oidcprovider.Decision {
		d := &oidcprovider.Decision{Authentication: e.event(req), Claims: []string{"groups", "phone_number", "address", "given_name"}}

		return d
	})

	at := e.flow(with(authorizeQuery(), "scope", "openid", "claims", request)).AccessToken
	claims := userInfoClaims(t, e.userinfo(bearerGET(at)))

	assert.Equal(t, map[string]any{
		"sub": "alice", "groups": []any{"admins"}, "phone_number": "+33 1 23 45 67 89",
	}, claims, "address fails its value, email was not released, given_name is an ID Token claim")
}

// TestUserInfoQueriesTheClaimsSource pins the ClaimsQuery of a UserInfo
// request: the realm, the token's subject and client, the userinfo target
// and exactly the names the response may release.
func TestUserInfoQueriesTheClaimsSource(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	at := e.flow(with(authorizeQuery(), "scope", "openid email",
		"claims", `{"userinfo": {"groups": null, "iss": null, "sub#x": null}}`)).AccessToken
	before := len(e.claims.recorded())

	userInfoClaims(t, e.userinfo(bearerGET(at)))

	queries := e.claims.recorded()[before:]
	require.Len(t, queries, 1)
	assert.Equal(t, oidcprovider.ClaimsQuery{
		Issuer: testIssuer, Subject: "alice", ClientID: webClientID, Target: oidcprovider.ClaimsForUserInfo,
		Names: []string{"email", "email_verified", "groups"},
	}, queries[0])
}

// TestUserInfoSubMatchesIDToken pins OIDC Core §5.3.2: the sub of the
// UserInfo response is the ID Token's — never the source's.
func TestUserInfoSubMatchesIDToken(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	resp := e.flow(authorizeQuery())

	_, idClaims := e.idToken(resp.IDToken)
	claims := userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken)))
	assert.Equal(t, idClaims["sub"], claims["sub"])
	assert.Equal(t, "alice", claims["sub"], "the source's sub is ignored")
}

// TestUserInfoReservedClaimsIgnored: protocol claims never come from the
// source, even when requested.
func TestUserInfoReservedClaimsIgnored(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	at := e.flow(with(authorizeQuery(), "scope", "openid",
		"claims", `{"userinfo": {"iss": null, "aud": null, "sub#x": null, "acr": null, "amr": null, "exp": null}}`)).AccessToken

	assert.Equal(t, map[string]any{"sub": "alice"}, userInfoClaims(t, e.userinfo(bearerGET(at))))
}

// TestUserInfoHeaders pins OIDC Core §5.3.2 and §16.17: a JSON response
// that is never cached.
func TestUserInfoHeaders(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	rec := e.userinfo(bearerGET(e.flow(authorizeQuery()).AccessToken))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}

// TestUserInfoRealmIsThePathIssuer: the challenge realm is the request's
// issuer, path included.
func TestUserInfoRealmIsThePathIssuer(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withResolver(fixedIssuer{issuer: "https://op.example/tenant-a"}))
	rec := e.userinfo(httptest.NewRequest(http.MethodGet, userInfoPath, nil))

	assert.Equal(t, map[string]string{"realm": "https://op.example/tenant-a"}, challenge(t, rec))
}
