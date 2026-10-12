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

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The clients of the repeated-parameter tests.
func repeatedParamsEnv(t *testing.T) *policyEnv {
	t.Helper()

	grants := []string{
		oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken, oauth2.GrantTypeClientCredentials,
	}

	return newPolicyEnv(t, oauth2.Profile20BCP,
		confidentialClient(grants, []string{"read", "write"}),
		&oauth2.DefaultClient{
			IDValue: "spa", TypeValue: oauth2.ClientPublic, RedirectURIValues: []string{redirectURI},
			GrantTypeValues: grants[:2], ScopeValues: []string{"read", "write"},
		},
	)
}

// authorizeRaw runs GET /authorize?rawQuery on env, recording whether the
// ConsentFunc ran.
func authorizeRaw(env *policyEnv, rawQuery string) (*httptest.ResponseRecorder, bool) {
	consented := false
	consent := func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		consented = true

		return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
	}

	rec := httptest.NewRecorder()
	env.srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, consent).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+rawQuery, nil))

	return rec, consented
}

// TestAuthorizeRefusesRepeatedParameters pins RFC 6749 §3.1 ("Request and
// response parameters MUST NOT be included more than once") at /authorize.
// A repeated client_id, redirect_uri or response_mode leaves the client, the
// target or the encoding of the answer ambiguous: a bare 400, never
// redirected (§4.1.2.1). Any other repeated parameter the server reads is a
// redirected invalid_request ("includes a parameter more than once") — a
// repeated state is not echoed. Nothing is issued either way.
func TestAuthorizeRefusesRepeatedParameters(t *testing.T) {
	t.Parallel()

	base := machineQuery().Encode()
	evil := url.QueryEscape("https://evil.example/cb")

	cases := []struct {
		name     string
		raw      string
		redirect bool
	}{
		{"redirect_uri, registered first", base + "&redirect_uri=" + evil, false},
		{"redirect_uri, evil first", strings.Replace(base, "redirect_uri=", "redirect_uri="+evil+"&redirect_uri=", 1), false},
		{"client_id", base + "&client_id=spa", false},
		{"response_mode", base + "&response_mode=query&response_mode=query", false},
		{"state", base + "&state=other", true},
		{"response_type", base + "&response_type=token", true},
		{"scope", base + "&scope=write", true},
		{"code_challenge", base + "&code_challenge=" + pkceChallenge, true},
		{"code_challenge_method", base + "&code_challenge_method=S256", true},
		{"nonce", base + "&nonce=a&nonce=b", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := repeatedParamsEnv(t)
			rec, consented := authorizeRaw(env, tc.raw)
			assert.False(t, consented, "the ConsentFunc never runs")
			assert.Zero(t, env.store.writes.Load(), "nothing issued")
			assert.Equal(t, []string{oauth2.CodeInvalidRequest}, env.sink.codes(), "OnError gets invalid_request")

			if !tc.redirect {
				require.Equal(t, http.StatusBadRequest, rec.Code)
				assert.Empty(t, rec.Header().Get("Location"), "never redirected")

				return
			}

			require.Equal(t, http.StatusFound, rec.Code)

			params := mustLocation(t, rec).Query()
			assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))
			assert.Equal(t, "https://auth.example", params.Get("iss"))
			assert.Empty(t, params.Get("code"))

			if tc.name == "state" {
				assert.False(t, params.Has("state"), "an ambiguous state is not echoed")
			} else {
				assert.Equal(t, "xyz-state", params.Get("state"))
			}
		})
	}
}

// TestAuthorizeRepeatedUnredirectableParameterWins: a repeated client_id,
// redirect_uri or response_mode is a bare 400 even when the request repeats
// another parameter too — whichever comes first in the request: the
// redirect is never taken to a target, or in an encoding, the request left
// ambiguous (RFC 6749 §4.1.2.1).
func TestAuthorizeRepeatedUnredirectableParameterWins(t *testing.T) {
	t.Parallel()

	unredirectable := map[string]string{
		"client_id":     "&client_id=spa",
		"redirect_uri":  "&redirect_uri=" + url.QueryEscape("https://evil.example/cb"),
		"response_mode": "&response_mode=query&response_mode=fragment",
	}
	redirectable := map[string]string{
		"response_type":         "&response_type=token",
		"scope":                 "&scope=write",
		"state":                 "&state=other",
		"code_challenge":        "&code_challenge=" + pkceChallenge,
		"code_challenge_method": "&code_challenge_method=S256",
		"nonce":                 "&nonce=a&nonce=b",
	}

	for u, uRaw := range unredirectable {
		for r, rRaw := range redirectable {
			for _, order := range []string{"before", "after"} {
				t.Run(u+"/"+r+"/"+order, func(t *testing.T) {
					t.Parallel()

					raw := machineQuery().Encode() + rRaw + uRaw
					if order == "before" {
						raw = machineQuery().Encode() + uRaw + rRaw
					}

					env := repeatedParamsEnv(t)
					rec, consented := authorizeRaw(env, raw)
					require.Equal(t, http.StatusBadRequest, rec.Code, rec.Header().Get("Location"))
					assert.Empty(t, rec.Header().Get("Location"), "never redirected")
					assert.False(t, consented)
					assert.Zero(t, env.store.writes.Load())

					errs := env.sink.collected()
					require.Len(t, errs, 1)

					var oe *oauth2.Error
					require.ErrorAs(t, errs[0], &oe)
					assert.Equal(t, "repeated "+u, oe.Description)
				})
			}
		}
	}
}

// TestAuthorizeParameterInQueryAndBody: on a POST, the query and the body
// form one request — a parameter in both is included twice.
func TestAuthorizeParameterInQueryAndBody(t *testing.T) {
	t.Parallel()

	env := repeatedParamsEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize?"+machineQuery().Encode(), strings.NewReader("scope=write"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	env.srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, approve).ServeHTTP(rec, req)
	require.Equal(t, http.StatusSeeOther, rec.Code, "a redirect answering a POST (RFC 9700 §4.12)")
	assert.Equal(t, oauth2.CodeInvalidRequest, mustLocation(t, rec).Query().Get("error"))
	assert.Zero(t, env.store.writes.Load())
}

// TestAuthorizeEmptyRepetitionIsNoRepetition pins RFC 6749 §3.1:
// "Parameters sent without a value MUST be treated as if they were omitted
// from the request" — an empty occurrence repeats nothing, and never hides
// the value that follows it from the server: a redirect_uri after an empty
// occurrence was included, so the token request must carry it (§4.1.3).
func TestAuthorizeEmptyRepetitionIsNoRepetition(t *testing.T) {
	t.Parallel()

	env := repeatedParamsEnv(t)

	var seen *oauth2.AuthorizeRequest

	consent := func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		seen = ar

		return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
	}

	q := machineQuery()
	q.Del("scope")
	q.Del("state")
	q.Del("redirect_uri")

	raw := "scope=&scope=write&state=&state=later&redirect_uri=&redirect_uri=" + url.QueryEscape(redirectURI) + "&" + q.Encode()

	rec := httptest.NewRecorder()
	env.srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, consent).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+raw, nil))
	require.Equal(t, http.StatusFound, rec.Code)

	params := mustLocation(t, rec).Query()
	require.NotEmpty(t, params.Get("code"), rec.Header().Get("Location"))
	assert.Equal(t, "later", params.Get("state"))
	require.NotNil(t, seen)
	assert.Equal(t, "write", seen.Scope)
	assert.Equal(t, "later", seen.State)

	form := codeExchangeForm(params.Get("code"))
	form.Del("redirect_uri")

	rec = env.token(form, "machine", "machine-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, oauth2.CodeInvalidGrant, jsonBody(t, rec)["error"])
}

// TestAuthorizeEmptyOccurrenceHidesNoGuardedValue: the checks made before
// the redirect URI is trusted read the value after an empty occurrence too
// (RFC 6749 §3.1) — the client, the redirect URI among several registered
// ones, the response mode.
func TestAuthorizeEmptyOccurrenceHidesNoGuardedValue(t *testing.T) {
	t.Parallel()

	const other = "https://app.example/other"

	client := confidentialClient([]string{oauth2.GrantTypeAuthorizationCode}, []string{"read"})
	client.RedirectURIValues = []string{redirectURI, other}

	t.Run("client_id and redirect_uri", func(t *testing.T) {
		t.Parallel()

		q := machineQuery()
		q.Del("client_id")
		q.Del("redirect_uri")

		env := newPolicyEnv(t, oauth2.Profile20BCP, client)
		rec, consented := authorizeRaw(env, "client_id=&client_id=machine&redirect_uri=&redirect_uri="+url.QueryEscape(other)+"&"+q.Encode())
		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
		assert.True(t, consented)

		loc := mustLocation(t, rec)
		assert.Equal(t, other, loc.Scheme+"://"+loc.Host+loc.Path)
		assert.NotEmpty(t, loc.Query().Get("code"))
	})

	t.Run("response_mode", func(t *testing.T) {
		t.Parallel()

		env := newPolicyEnv(t, oauth2.Profile20BCP, client)
		rec, consented := authorizeRaw(env, "response_mode=&response_mode=fragment&"+machineQuery().Encode())
		require.Equal(t, http.StatusBadRequest, rec.Code, "the code flow is not answered in the fragment")
		assert.Empty(t, rec.Header().Get("Location"))
		assert.False(t, consented)
	})
}

// TestAuthorizeIgnoresRepeatedUnknownParameters pins RFC 6749 §3.1: "The
// authorization server MUST ignore unrecognized request parameters".
func TestAuthorizeIgnoresRepeatedUnknownParameters(t *testing.T) {
	t.Parallel()

	env := repeatedParamsEnv(t)
	rec, consented := authorizeRaw(env, machineQuery().Encode()+"&foo=a&foo=b")
	require.Equal(t, http.StatusFound, rec.Code)
	assert.NotEmpty(t, mustLocation(t, rec).Query().Get("code"))
	assert.True(t, consented)
}

// issueMachineCode runs /authorize for the client "machine" and returns the
// code.
func issueMachineCode(t *testing.T, env *policyEnv) string {
	t.Helper()

	rec := runAuthorize(env.srv, machineQuery(), approve)
	require.Equal(t, http.StatusFound, rec.Code)

	code := mustLocation(t, rec).Query().Get("code")
	require.NotEmpty(t, code)

	return code
}

// TestTokenRefusesRepeatedParameters pins RFC 6749 §3.2 at /token: a
// repeated parameter is invalid_request (§5.2 "repeats a parameter"),
// answered before the grant runs — so a code presented in such a request is
// not consumed, and redeems afterwards.
func TestTokenRefusesRepeatedParameters(t *testing.T) {
	t.Parallel()

	cases := map[string]func(code string) string{
		"grant_type": func(string) string {
			return "grant_type=client_credentials&grant_type=authorization_code&scope=read"
		},
		"code": func(code string) string {
			return codeExchangeForm(code).Encode() + "&code=bogus"
		},
		"redirect_uri": func(code string) string {
			return codeExchangeForm(code).Encode() + "&redirect_uri=" + url.QueryEscape("https://evil.example/cb")
		},
		"code_verifier": func(code string) string {
			return codeExchangeForm(code).Encode() + "&code_verifier=" + strings.Repeat("v", 43)
		},
		"scope":         func(string) string { return "grant_type=client_credentials&scope=read&scope=write" },
		"refresh_token": func(string) string { return "grant_type=refresh_token&refresh_token=a&refresh_token=b" },
		"username":      func(string) string { return "grant_type=password&username=a&username=b&password=p" },
		"password":      func(string) string { return "grant_type=password&username=a&password=p&password=q" },
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := repeatedParamsEnv(t)
			code := issueMachineCode(t, env)
			writes := env.store.writes.Load()

			rec := env.postRaw(env.srv.TokenHandler(), body(code), "machine", "machine-secret")
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, oauth2.CodeInvalidRequest, jsonBody(t, rec)["error"])
			assert.Equal(t, "repeated "+name, jsonBody(t, rec)["error_description"])
			assert.Equal(t, writes, env.store.writes.Load(), "nothing issued")

			rec = env.token(codeExchangeForm(code), "machine", "machine-secret")
			assert.Equal(t, http.StatusOK, rec.Code, "the code was not consumed: %s", rec.Body.String())
		})
	}
}

// TestTokenEmptyRepetitionIsNoRepetition: at /token too, an empty
// occurrence is omitted — the grant and the client authentication read the
// value that follows it.
func TestTokenEmptyRepetitionIsNoRepetition(t *testing.T) {
	t.Parallel()

	env := repeatedParamsEnv(t)

	rec := env.postRaw(env.srv.TokenHandler(), "grant_type=&grant_type=client_credentials&scope=&scope=read", "machine", "machine-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "read", jsonBody(t, rec)["scope"])

	q := machineQuery()
	q.Set("client_id", "spa")

	rec = runAuthorize(env.srv, q, approve)
	require.Equal(t, http.StatusFound, rec.Code)

	body := "client_id=&client_id=spa&code=&" + codeExchangeForm(mustLocation(t, rec).Query().Get("code")).Encode()

	rec = env.postRaw(env.srv.TokenHandler(), body, "", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

// TestClientCredentialParametersRepeated: a repeated client_id or
// client_secret "includes multiple credentials" (RFC 6749 §5.2) at every
// endpoint authenticating clients — invalid_request, not invalid_client:
// the request is malformed whatever the credentials.
func TestClientCredentialParametersRepeated(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"token", "revoke", "introspect"} {
		for name, body := range map[string]string{
			"client_id":     "client_id=spa&client_id=machine&client_secret=machine-secret",
			"client_secret": "client_id=machine&client_secret=machine-secret&client_secret=other",
		} {
			t.Run(endpoint+"/"+name, func(t *testing.T) {
				t.Parallel()

				env := repeatedParamsEnv(t)
				handler := map[string]http.Handler{
					"token": env.srv.TokenHandler(), "revoke": env.srv.RevokeHandler(), "introspect": env.srv.IntrospectHandler(),
				}[endpoint]

				rec := env.postRaw(handler, body+"&grant_type=client_credentials&token=t", "", "")
				require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
				assert.Equal(t, oauth2.CodeInvalidRequest, jsonBody(t, rec)["error"])
			})
		}
	}
}

// TestTokenLookupParametersRepeated pins the same rule at /revoke (RFC 7009
// §2.1) and /introspect (RFC 7662 §2.1): which token a request carrying two
// would revoke or describe is ambiguous — invalid_request.
func TestTokenLookupParametersRepeated(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"revoke", "introspect"} {
		for name, body := range map[string]string{
			"token":           "token=a&token=b",
			"token_type_hint": "token=a&token_type_hint=access_token&token_type_hint=refresh_token",
		} {
			t.Run(endpoint+"/"+name, func(t *testing.T) {
				t.Parallel()

				env := repeatedParamsEnv(t)
				handler := env.srv.RevokeHandler()
				if endpoint == "introspect" {
					handler = env.srv.IntrospectHandler()
				}

				rec := env.postRaw(handler, body, "machine", "machine-secret")
				require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
				assert.Equal(t, oauth2.CodeInvalidRequest, jsonBody(t, rec)["error"])
				assert.Equal(t, "repeated "+name, jsonBody(t, rec)["error_description"])
			})
		}
	}
}

// TestTokenLookupEmptyRepetitionIsNoRepetition: at /introspect and /revoke
// too, an empty occurrence is omitted — the token that follows it is the
// one described, then revoked.
func TestTokenLookupEmptyRepetitionIsNoRepetition(t *testing.T) {
	t.Parallel()

	env := repeatedParamsEnv(t)

	rec := env.token(url.Values{"grant_type": {oauth2.GrantTypeClientCredentials}, "scope": {"read"}}, "machine", "machine-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	accessToken, _ := jsonBody(t, rec)["access_token"].(string)
	require.NotEmpty(t, accessToken)

	body := "token=&token=" + url.QueryEscape(accessToken) + "&token_type_hint=&token_type_hint=access_token"

	rec = env.postRaw(env.srv.IntrospectHandler(), body, "machine", "machine-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, true, jsonBody(t, rec)["active"])

	rec = env.postRaw(env.srv.RevokeHandler(), body, "machine", "machine-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = env.postRaw(env.srv.IntrospectHandler(), "token="+url.QueryEscape(accessToken), "machine", "machine-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, false, jsonBody(t, rec)["active"], "the token after the empty occurrence was revoked")
}

// TestUnsupportedGrantTypeDoesNotEchoTheRequest: the unsupported_grant_type
// description is a fixed text — it used to reflect the grant_type sent.
func TestUnsupportedGrantTypeDoesNotEchoTheRequest(t *testing.T) {
	t.Parallel()

	env := repeatedParamsEnv(t)

	rec := env.token(url.Values{"grant_type": {"urn:example:reflected"}}, "machine", "machine-secret")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, oauth2.CodeUnsupportedGrantType, jsonBody(t, rec)["error"])
	assert.NotContains(t, rec.Body.String(), "reflected")
}
