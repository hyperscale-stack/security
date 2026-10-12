// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/token"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lastRequest returns the request the interaction saw last.
func (e *env) lastRequest() oidcprovider.Request {
	e.t.Helper()

	interactive, silent := e.interaction.calls()
	all := append(interactive, silent...)
	require.NotEmpty(e.t, all, "the interaction was called")

	return all[len(all)-1]
}

// TestOpenIDRequestWithoutRedirectURIIsNotRedirected pins OIDC Core
// §3.1.2.1 (redirect_uri REQUIRED) and §3.1.2.6: the core accepts the
// omission for a client with one registered URI, the provider refuses it
// with a bare 400, before any interaction.
func TestOpenIDRequestWithoutRedirectURIIsNotRedirected(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	rec := e.authorize(with(authorizeQuery(), "redirect_uri", ""))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, rec.Header().Get("Location"))
	assert.True(t, e.sink.contains(oauth2.ErrUnredirectableRequest))

	interactive, silent := e.interaction.calls()
	assert.Empty(t, interactive)
	assert.Empty(t, silent)
}

// TestDuplicatedParameters pins RFC 6749 §3.1 ("MUST NOT be included more
// than once") for OpenID requests: a repeated client_id, redirect_uri or
// response_mode leaves the target or encoding of the answer ambiguous and
// gets a bare 400; any other repeated parameter is a redirected
// invalid_request (§4.1.2.1) — the core's repetitions refused by the core
// itself, an unredirectable one with a bare 400 whatever else is repeated.
// An empty repetition is no duplicate (§3.1: empty = omitted), except as
// the first occurrence of a core parameter, which the provider refuses.
func TestDuplicatedParameters(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		raw    string // appended to the canonical query
		status int
		code   string
	}{
		{"client_id", "&client_id=" + webClientID, http.StatusBadRequest, ""},
		{"redirect_uri", "&redirect_uri=" + url.QueryEscape(webRedirectURI), http.StatusBadRequest, ""},
		{"response_mode", "&response_mode=query&response_mode=query", http.StatusBadRequest, ""},
		{"redirect_uri with another repeated parameter", "&response_type=code&redirect_uri=" + url.QueryEscape("https://evil.example/cb"),
			http.StatusBadRequest, ""},
		{"response_mode with another repeated parameter", "&scope=openid&response_mode=query&response_mode=fragment",
			http.StatusBadRequest, ""},
		{"nonce", "&nonce=other", http.StatusFound, oauth2.CodeInvalidRequest},
		{"state", "&state=other", http.StatusFound, oauth2.CodeInvalidRequest},
		{"scope", "&scope=openid", http.StatusFound, oauth2.CodeInvalidRequest},
		{"code_challenge", "&code_challenge=" + pkceChallenge, http.StatusFound, oauth2.CodeInvalidRequest},
		{"prompt", "&prompt=login&prompt=consent", http.StatusFound, oauth2.CodeInvalidRequest},
		{"max_age", "&max_age=10&max_age=10", http.StatusFound, oauth2.CodeInvalidRequest},
		{"claims", "&claims={}&claims={}", http.StatusFound, oauth2.CodeInvalidRequest},
		{"login_hint", "&login_hint=a&login_hint=b", http.StatusFound, oauth2.CodeInvalidRequest},
		{"acr_values", "&acr_values=a&acr_values=b", http.StatusFound, oauth2.CodeInvalidRequest},
		{"display", "&display=page&display=popup", http.StatusFound, oauth2.CodeInvalidRequest},
		{"ui_locales", "&ui_locales=fr&ui_locales=en", http.StatusFound, oauth2.CodeInvalidRequest},
		{"id_token_hint", "&id_token_hint=a&id_token_hint=b", http.StatusFound, oauth2.CodeInvalidRequest},
		{"empty repetition of a provider parameter", "&prompt=&prompt=login", http.StatusFound, ""},
		{"empty repetition after a core parameter", "&nonce=", http.StatusFound, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			rec := serve(e.op.AuthorizeHandler(oauth2.AuthorizeConfig{}),
				get("/oauth2/authorize?"+authorizeQuery().Encode()+tc.raw))

			require.Equal(t, tc.status, rec.Code, rec.Body.String())

			if tc.status == http.StatusBadRequest {
				assert.Empty(t, rec.Header().Get("Location"))

				return
			}

			params := redirect(t, rec)
			assert.Equal(t, tc.code, params.Get("error"))
			assert.Equal(t, testIssuer, params.Get("iss"))
		})
	}

	t.Run("empty first occurrence of a core parameter", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		q := with(authorizeQuery(), "nonce", "")
		rec := serve(e.op.AuthorizeHandler(oauth2.AuthorizeConfig{}),
			get("/oauth2/authorize?nonce=&"+q.Encode()+"&nonce=late"))

		assert.Equal(t, oauth2.CodeInvalidRequest, redirect(t, rec).Get("error"),
			"the provider refuses an empty first occurrence of a core parameter")
	})

	t.Run("empty first occurrence of redirect_uri", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		rec := serve(e.op.AuthorizeHandler(oauth2.AuthorizeConfig{}),
			get("/oauth2/authorize?redirect_uri=&"+authorizeQuery().Encode()))

		assert.Equal(t, http.StatusBadRequest, rec.Code, "the core accepts it, the provider refuses it unredirected")
		assert.Empty(t, rec.Header().Get("Location"))
		assert.True(t, e.sink.contains(oauth2.ErrUnredirectableRequest))
	})
}

// TestOpenIDImplicitRefused pins OIDC Core §3: OpenID Connect does not use
// response_type=token, which returns no ID Token.
func TestOpenIDImplicitRefused(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withProfile(oauth2.Profile20))
	cfg := oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)}}

	params := redirect(t, e.authorizeWith(cfg, with(authorizeQuery(), "response_type", "token")))
	assert.Equal(t, oauth2.CodeUnsupportedResponseType, params.Get("error"))

	plain := redirect(t, e.authorizeWith(cfg, with(authorizeQuery(), "response_type", "token", "scope", "read", "nonce", "")))
	assert.NotEmpty(t, plain.Get("access_token"), "the OAuth 2.0 implicit flow is unaffected")
}

// TestRequestObjectParametersRefused pins OIDC Core §3.1.2.6, §6, §7.2.1.
func TestRequestObjectParametersRefused(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"request":      oauth2.CodeRequestNotSupported,
		"request_uri":  oauth2.CodeRequestURINotSupported,
		"registration": oauth2.CodeRegistrationNotSupported,
	}

	for param, code := range cases {
		t.Run(param, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			params := redirect(t, e.authorize(with(authorizeQuery(), param, "eyJhbGciOiJub25lIn0.e30.")))
			assert.Equal(t, code, params.Get("error"))

			// Empty, the parameter is omitted (RFC 6749 §3.1).
			rec := serve(e.op.AuthorizeHandler(oauth2.AuthorizeConfig{}),
				get("/oauth2/authorize?"+authorizeQuery().Encode()+"&"+param+"="))
			assert.NotEmpty(t, redirect(t, rec).Get("code"))
		})
	}
}

// TestPromptParsing pins OIDC Core §3.1.2.1: space-delimited values,
// unknown ones ignored, none combined with any other value refused.
func TestPromptParsing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		prompt string
		want   oidcprovider.Prompt
		err    bool
	}{
		{"login", oidcprovider.Prompt{Login: true}, false},
		{"consent select_account", oidcprovider.Prompt{Consent: true, SelectAccount: true}, false},
		{"login  consent", oidcprovider.Prompt{Login: true, Consent: true}, false},
		{"create", oidcprovider.Prompt{}, false},
		{"none", oidcprovider.Prompt{None: true}, false},
		{"none login", oidcprovider.Prompt{}, true},
		{"none create", oidcprovider.Prompt{}, true},
		{"LOGIN", oidcprovider.Prompt{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.prompt, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			params := redirect(t, e.authorize(with(authorizeQuery(), "prompt", tc.prompt)))

			if tc.err {
				assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))

				interactive, silent := e.interaction.calls()
				assert.Empty(t, interactive)
				assert.Empty(t, silent)

				return
			}

			assert.NotEmpty(t, params.Get("code"))
			assert.Equal(t, tc.want, e.lastRequest().Prompt)
		})
	}
}

// TestMaxAgeParsing pins OIDC Core §3.1.2.1: a non-negative number of
// seconds; very long values are accepted and clamped.
func TestMaxAgeParsing(t *testing.T) {
	t.Parallel()

	maxClamp := time.Duration(1<<31-1) * time.Second

	cases := []struct {
		raw  string
		want *time.Duration
		err  bool
	}{
		{"3600", durationPtr(time.Hour), false},
		{"007", durationPtr(7 * time.Second), false},
		{"000000000000060", durationPtr(time.Minute), false},
		{"0", durationPtr(0), false},
		{"9223372036854775807", durationPtr(maxClamp), false},
		{"9999999999", durationPtr(maxClamp), false},
		{"2147483647", durationPtr(maxClamp), false},
		{"2147483646", durationPtr(maxClamp - time.Second), false},
		{"99999999999999999999999999999999999999", durationPtr(maxClamp), false},
		{"-1", nil, true},
		{"1e3", nil, true},
		{" 60", nil, true},
		{"60s", nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			params := redirect(t, e.authorize(with(authorizeQuery(), "max_age", tc.raw)))

			if tc.err {
				assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))

				return
			}

			assert.NotEmpty(t, params.Get("code"))
			require.NotNil(t, e.lastRequest().MaxAge)
			assert.Equal(t, *tc.want, *e.lastRequest().MaxAge)
		})
	}
}

func durationPtr(d time.Duration) *time.Duration { return &d }

// TestNonceBounds pins the provider's nonce bound: at most 512 bytes of
// valid UTF-8 without NUL (storage cannot keep NUL nor invalid UTF-8);
// other control characters are kept verbatim (Core §2: no other
// processing).
func TestNonceBounds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, nonce string
		ok          bool
	}{
		{"512 bytes", strings.Repeat("n", 512), true},
		{"control characters", "a\tb\x01c\x7f", true},
		{"non-ASCII", "nonce-é-🔑", true},
		{"513 bytes", strings.Repeat("n", 513), false},
		{"NUL", "a\x00b", false},
		{"invalid UTF-8", "a\xffb", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			params := redirect(t, e.authorize(with(authorizeQuery(), "nonce", tc.nonce)))

			if !tc.ok {
				assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))

				return
			}

			resp := tokens(t, e.exchange(params.Get("code")))
			_, claims := e.idToken(resp.IDToken)
			assert.Equal(t, tc.nonce, claims["nonce"], "echoed unmodified")
		})
	}
}

// TestPassthroughParameters pins OIDC Core §15.1: display, ui_locales,
// claims_locales, acr_values and login_hint never fail a request.
func TestPassthroughParameters(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	longHint := strings.Repeat("h", 1025)
	manyLocales := strings.TrimSpace(strings.Repeat("fr ", 40))

	q := with(authorizeQuery(),
		"display", "hologram", "ui_locales", "fr-CA fr en", "claims_locales", "de",
		"acr_values", "urn:example:loa:2 urn:example:loa:1", "login_hint", "alice@example.com")
	require.NotEmpty(t, redirect(t, e.authorize(q)).Get("code"))

	req := e.lastRequest()
	assert.Equal(t, "hologram", req.Display)
	assert.Equal(t, []string{"fr-CA", "fr", "en"}, req.UILocales)
	assert.Equal(t, []string{"de"}, req.ClaimsLocales)
	assert.Equal(t, []string{"urn:example:loa:2", "urn:example:loa:1"}, req.ACRValues)
	assert.Equal(t, "alice@example.com", req.LoginHint)

	require.NotEmpty(t, redirect(t, e.authorize(with(authorizeQuery(), "login_hint", longHint, "ui_locales", manyLocales,
		"claims_locales", "fr\xffde", "display", "pop\xffup"))).Get("code"))

	req = e.lastRequest()
	assert.Empty(t, req.LoginHint, "an oversized hint is ignored")
	assert.Empty(t, req.Display, "an invalid UTF-8 display is ignored")
	assert.Len(t, req.UILocales, 32, "locales are capped, never refused")
	assert.Empty(t, req.ClaimsLocales, "invalid UTF-8 is ignored")
}

// TestOversizedListParametersAreIgnored: ui_locales, claims_locales and
// acr_values of at most 2048 bytes keep their first 32 values; a longer
// value is ignored — never refused (Core §3.1.2.1, §15.1) — like an
// oversized display or login_hint.
func TestOversizedListParametersAreIgnored(t *testing.T) {
	t.Parallel()

	atBound := strings.Repeat("fr ", 682) + "fr" // 2048 bytes, 683 values
	overBound := atBound + " "                   // 2049 bytes
	require.Len(t, atBound, 2048)

	e := newEnv(t)

	for _, value := range []string{atBound, overBound} {
		q := with(authorizeQuery(), "ui_locales", value, "claims_locales", value, "acr_values", value)
		require.NotEmpty(t, redirect(t, e.authorize(q)).Get("code"))

		req := e.lastRequest()
		if value == atBound {
			assert.Len(t, req.UILocales, 32)
			assert.Len(t, req.ClaimsLocales, 32)
			assert.Len(t, req.ACRValues, 32)

			continue
		}

		assert.Nil(t, req.UILocales, "an oversized ui_locales is ignored")
		assert.Nil(t, req.ClaimsLocales, "an oversized claims_locales is ignored")
		assert.Nil(t, req.ACRValues, "an oversized acr_values is ignored")
	}
}

// TestPromptIsReadWhole: prompt has no length bound — truncating or
// ignoring it could turn "none … login" into a valid prompt=none, or skip a
// required re-authentication — and is read whole, without allocating per
// separator.
func TestPromptIsReadWhole(t *testing.T) {
	t.Parallel()

	spaces := strings.Repeat(" ", 1<<20)

	e := newEnv(t)
	require.NotEmpty(t, redirect(t, e.authorize(with(authorizeQuery(), "prompt", spaces+"login"))).Get("code"))
	assert.Equal(t, oidcprovider.Prompt{Login: true}, e.lastRequest().Prompt)

	refused := newEnv(t)
	params := redirect(t, refused.authorize(with(authorizeQuery(), "prompt", "none"+spaces+"login")))
	assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"), "none with another value, however far")

	interactive, silent := refused.interaction.calls()
	assert.Empty(t, interactive)
	assert.Empty(t, silent)
}

// TestRequestView pins what the interaction learns about an OpenID request.
func TestRequestView(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	require.NotEmpty(t, redirect(t, e.authorize(with(authorizeQuery(), "scope", "openid email offline_access"))).Get("code"))

	req := e.lastRequest()
	assert.True(t, req.OpenID)
	assert.Equal(t, testIssuer, req.Issuer)
	assert.Equal(t, webClientID, req.Client.ID())
	assert.Equal(t, webRedirectURI, req.RedirectURI)
	assert.Equal(t, []string{"openid", "email", "offline_access"}, req.Scopes)
	assert.True(t, req.OfflineAccess)
	assert.Equal(t, e.clock.Now(), req.ReceivedAt)
	assert.Nil(t, req.MaxAge)
}

// TestRequestReportsOfflineAccessForEveryRequest: the interaction learns
// that offline_access is requested — an OpenID request or a plain OAuth 2.0
// one — so that it can ask the end-user.
func TestRequestReportsOfflineAccessForEveryRequest(t *testing.T) {
	t.Parallel()

	for scope, openID := range map[string]bool{"read offline_access": false, "openid offline_access": true} {
		e := newEnv(t)
		require.NotEmpty(t, redirect(t, e.authorize(with(authorizeQuery(), "scope", scope))).Get("code"))

		req := e.lastRequest()
		assert.Equal(t, openID, req.OpenID, scope)
		assert.True(t, req.OfflineAccess, scope)
	}
}

// TestPlainOAuth2RequestKeepsOAuth2Semantics: without openid the request
// is an OAuth 2.0 one: OpenID parameters are not parsed, the interaction
// is always interactive, and the token response carries no id_token.
func TestPlainOAuth2RequestKeepsOAuth2Semantics(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	q := with(authorizeQuery(), "scope", "read", "prompt", "none login", "nonce", strings.Repeat("n", 600), "request", "x")

	resp := e.flow(q)
	assert.Empty(t, resp.IDToken)
	assert.Equal(t, "read", resp.Scope)

	interactive, silent := e.interaction.calls()
	require.Len(t, interactive, 1)
	assert.Empty(t, silent)
	assert.False(t, interactive[0].OpenID)
	assert.Equal(t, oidcprovider.Prompt{}, interactive[0].Prompt)
}
