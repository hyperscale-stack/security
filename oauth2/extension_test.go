// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtensionCarriesTrustedContextToTheIDToken runs the toy OpenID
// Connect provider end to end. The authentication the application attests
// at /authorize reaches the id_token of the code exchange — bound to the
// issuer, the subject and the client, with the request's nonce and the
// at_hash of the access token actually returned (OIDC Core §2, §3.1.3.6) —
// and every refresh keeps the original authentication: same iss, sub, aud,
// auth_time, no nonce, a fresh iat (OIDC Core §12.2).
func TestExtensionCarriesTrustedContextToTheIDToken(t *testing.T) {
	t.Parallel()

	env := newExtensionEnv(t, toyOIDC{})
	authTime := env.clock.Now().Add(-time.Minute)

	q := oidcQuery()
	q.Set("max_age", "600")

	var seen any

	code := env.code(t, q, func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		seen = ar.ExtensionRequest

		return authenticated(authTime)(w, r, ar)
	})
	assert.Equal(t, &toyRequest{MaxAge: 10 * time.Minute}, seen, "the ConsentFunc sees the extension's view")

	rec := env.exchange(code)
	require.Equal(t, http.StatusOK, rec.Code)

	body := jsonBody(t, rec)
	assert.Equal(t, []string{"access_token", "expires_in", "id_token", "refresh_token", "scope", "token_type"}, keys(body))

	idt := decodeToyIDToken(t, body["id_token"].(string))
	assert.Equal(t, toyIDToken{
		Iss: "https://auth.example", Sub: "alice", Aud: testClientID, Nonce: "n-0S6_WzA2Mj",
		AuthTime: authTime.Unix(), ACR: "urn:example:loa:2", Iat: env.clock.Now().Unix(),
		AtHash: atHash(body["access_token"].(string)),
	}, idt)

	rt := body["refresh_token"].(string)

	for range 3 {
		env.clock.Advance(time.Hour)

		rec = env.refresh(rt)
		require.Equal(t, http.StatusOK, rec.Code)

		body = jsonBody(t, rec)
		refreshed := decodeToyIDToken(t, body["id_token"].(string))
		assert.Equal(t, toyIDToken{
			Iss: "https://auth.example", Sub: "alice", Aud: testClientID,
			AuthTime: authTime.Unix(), ACR: "urn:example:loa:2", Iat: env.clock.Now().Unix(),
			AtHash: atHash(body["access_token"].(string)),
		}, refreshed, "a refresh keeps the original authentication, without nonce")

		rt = body["refresh_token"].(string)
	}
}

// TestExtensionRefusesAStaleAuthentication: the toy provider answers an
// authentication older than max_age with login_required (OIDC Core
// §3.1.2.1, §3.1.2.6), redirected with the state; no code is issued.
func TestExtensionRefusesAStaleAuthentication(t *testing.T) {
	t.Parallel()

	env := newExtensionEnv(t, toyOIDC{})

	q := oidcQuery()
	q.Set("max_age", "60")

	rec := env.authorize(q, authenticated(env.clock.Now().Add(-2*time.Minute)))
	require.Equal(t, http.StatusFound, rec.Code)

	params := mustLocation(t, rec).Query()
	assert.Equal(t, oauth2.CodeLoginRequired, params.Get("error"))
	assert.Equal(t, "xyz-state", params.Get("state"))
	assert.False(t, params.Has("code"))
}

// TestPlainOAuth2RequestsPassThroughTheExtension: with the toy provider
// configured, a request without openid is served exactly as without it —
// same response members, no id_token.
func TestPlainOAuth2RequestsPassThroughTheExtension(t *testing.T) {
	t.Parallel()

	env := newExtensionEnv(t, toyOIDC{})

	rec := env.exchange(env.code(t, authorizeQuery(), approve))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"access_token", "expires_in", "refresh_token", "scope", "token_type"}, keys(jsonBody(t, rec)))
}

// coreFailures are /authorize requests the core refuses: redirected or not,
// the extension never sees them.
func coreFailures() map[string]url.Values {
	cases := map[string]url.Values{}

	for name, mutate := range map[string]func(url.Values){
		"unknown client":          func(q url.Values) { q.Set("client_id", "ghost") },
		"unregistered redirect":   func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"unsupported mode":        func(q url.Values) { q.Set("response_mode", "form_post") },
		"unsupported type":        func(q url.Values) { q.Set("response_type", "code id_token") },
		"scope not allowed":       func(q url.Values) { q.Set("scope", "openid admin") },
		"missing PKCE":            func(q url.Values) { q.Del("code_challenge") },
		"malformed PKCE":          func(q url.Values) { q.Set("code_challenge", "short") },
		"plain PKCE under BCP":    func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"unknown PKCE method":     func(q url.Values) { q.Set("code_challenge_method", "S512") },
		"implicit not configured": func(q url.Values) { q.Set("response_type", "token") },
	} {
		q := oidcQuery()
		mutate(q)
		cases[name] = q
	}

	return cases
}

// TestExtensionRunsAfterTheCoreValidation: every request the core refuses
// is refused before the extension runs.
func TestExtensionRunsAfterTheCoreValidation(t *testing.T) {
	t.Parallel()

	for name, q := range coreFailures() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ext := &fakeExtension{}
			env := newExtensionEnv(t, ext)

			rec := env.authorize(q, approve)
			assert.NotContains(t, rec.Header().Get("Location"), "code=")

			validated, completed, _ := ext.calls()
			assert.Zero(t, validated)
			assert.Zero(t, completed)
		})
	}
}

// TestExtensionHooksReceiveTheValidatedRequest: ValidateAuthorizeRequest
// gets the validated request, issuer resolved; its result reaches the
// ConsentFunc; CompleteAuthorization gets a pristine copy of the request —
// whatever the ConsentFunc did to its own — the consent with the granted
// scope, its trusted result, and the server clock. The code records the
// pristine request.
func TestExtensionHooksReceiveTheValidatedRequest(t *testing.T) {
	t.Parallel()

	type view struct{ Prompt string }

	ext := &fakeExtension{
		validate: func(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error) {
			return &view{Prompt: "login"}, nil
		},
	}
	env := newExtensionEnv(t, ext)
	result := &toyAuthentication{AuthTime: env.clock.Now()}

	q := oidcQuery()
	q.Set("scope", "openid read write")

	var consentView any

	code := env.code(t, q, func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		consentView = ar.ExtensionRequest
		ar.Scope, ar.RedirectURI, ar.State, ar.ExtensionRequest = "openid", "https://evil.example/cb", "forged", nil

		return &oauth2.Consent{Approved: true, Subject: "alice", Scope: "openid read", ExtensionResult: result}, nil
	})

	require.Len(t, ext.validated, 1)
	assert.Equal(t, "https://auth.example", ext.validated[0].Issuer)
	assert.Equal(t, "openid read write", ext.validated[0].Scope)
	assert.Nil(t, ext.validated[0].ExtensionRequest, "nothing to see before the extension ran")
	assert.Equal(t, &view{Prompt: "login"}, consentView, "the ConsentFunc sees the extension's view")

	require.Len(t, ext.completed, 1)
	c := ext.completed[0]
	assert.Equal(t, "openid read write", c.ar.Scope, "CompleteAuthorization sees the validated request")
	assert.Equal(t, redirectURI, c.ar.RedirectURI)
	assert.Equal(t, "xyz-state", c.ar.State)
	assert.Equal(t, &view{Prompt: "login"}, c.ar.ExtensionRequest)
	assert.Equal(t, "openid read", c.consent.Scope, "the granted scope")
	assert.Same(t, result, c.consent.ExtensionResult)
	assert.Equal(t, "alice", c.consent.Subject)
	assert.Equal(t, env.clock.Now(), c.now)

	record, err := env.store.ConsumeAuthorizationCode(t.Context(), oauth2.HashToken(nil, code))
	require.NoError(t, err)
	assert.Equal(t, "openid read", record.Scope)
	assert.Equal(t, redirectURI, record.RedirectURI)
}

// TestExtensionAuthorizeErrors: an error from either authorization hook is
// answered like a refusal — a protocol *Error with an authorization-endpoint
// code redirected as is, ErrUnredirectableRequest as a bare 400, anything
// else as server_error — and issues nothing.
func TestExtensionAuthorizeErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		err      error
		wantCode string // "" for the bare 400
		wantHook string
	}{
		{"protocol error", oauth2.ErrRequestNotSupported, oauth2.CodeRequestNotSupported, oauth2.CodeRequestNotSupported},
		{"wrapped protocol error", errors.Join(errors.New("context"), oauth2.ErrLoginRequired), oauth2.CodeLoginRequired, oauth2.CodeLoginRequired},
		{"token-endpoint code", oauth2.ErrInvalidGrant, oauth2.CodeServerError, oauth2.CodeServerError},
		{"failure", errors.New("claims backend down"), oauth2.CodeServerError, oauth2.CodeServerError},
		{"unredirectable", oauth2.ErrUnredirectableRequest, "", oauth2.CodeInvalidRequest},
	}

	for _, tc := range cases {
		for _, hook := range []string{"validate", "complete"} {
			t.Run(hook+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				ext := &fakeExtension{}
				if hook == "validate" {
					ext.validate = func(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error) {
						return nil, tc.err
					}
				} else {
					ext.complete = func(context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time) (oauth2.ExtensionGrant, error) {
						return oauth2.ExtensionGrant{}, tc.err
					}
				}

				store := &writeCountingStore{Store: memory.New()}
				env := newExtensionEnv(t, ext, withStore(store))

				consented := false
				rec := env.authorize(oidcQuery(), func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
					consented = true

					return approve(w, r, ar)
				})

				assert.Equal(t, hook == "complete", consented, "the ConsentFunc runs only once the request is validated")
				assert.Zero(t, store.writes.Load())
				assert.Equal(t, []string{tc.wantHook}, env.sink.codes())

				if tc.wantCode == "" {
					require.Equal(t, http.StatusBadRequest, rec.Code)
					assert.Empty(t, rec.Header().Get("Location"))

					return
				}

				require.Equal(t, http.StatusFound, rec.Code)
				params := mustLocation(t, rec).Query()
				assert.Equal(t, tc.wantCode, params.Get("error"))
				assert.Equal(t, "xyz-state", params.Get("state"))
			})
		}
	}
}

// grantingExtension is a fake extension whose CompleteAuthorization
// returns g.
func grantingExtension(g oauth2.ExtensionGrant) *fakeExtension {
	return &fakeExtension{
		complete: func(context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time) (oauth2.ExtensionGrant, error) {
			return g, nil
		},
	}
}

// TestExtensionGrantDataIsBounded: the extension data is recorded when it
// is at most oauth2.MaxExtensionDataLength bytes of valid UTF-8 without
// NUL; anything else fails the request with server_error, nothing issued.
func TestExtensionGrantDataIsBounded(t *testing.T) {
	t.Parallel()

	longest := strings.Repeat("x", oauth2.MaxExtensionDataLength-len("é")) + "é"

	cases := []struct {
		name, data string
		ok         bool
	}{
		{"empty", "", true},
		{"longest", longest, true},
		{"one byte too long", longest + "x", false},
		{"invalid UTF-8", "ctx\xff", false},
		{"NUL", "ctx\x00", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &writeCountingStore{Store: memory.New()}
			env := newExtensionEnv(t, grantingExtension(oauth2.ExtensionGrant{Data: tc.data}), withStore(store))

			rec := env.authorize(oidcQuery(), approve)
			require.Equal(t, http.StatusFound, rec.Code)

			params := mustLocation(t, rec).Query()
			if !tc.ok {
				assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
				assert.Zero(t, store.writes.Load())
				assert.Equal(t, []string{oauth2.CodeServerError}, env.sink.codes())

				return
			}

			record, err := store.ConsumeAuthorizationCode(t.Context(), oauth2.HashToken(nil, params.Get("code")))
			require.NoError(t, err)
			assert.Equal(t, tc.data, record.ExtensionData)
		})
	}
}

// TestExtensionGrantScopeOnlyNarrows: the extension may narrow the granted
// scope — read in its whitespace-split, de-duplicated form, recorded on the
// code, on the tokens and in the response — and never broaden it; a blank
// scope leaves the consented one.
func TestExtensionGrantScopeOnlyNarrows(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, scope, want string
		ok                bool
	}{
		{"unset", "", "openid read write", true},
		{"blank", " \t ", "openid read write", true},
		{"narrowed", "openid read", "openid read", true},
		{"reordered with duplicates", " read  openid read ", "read openid", true},
		{"broadened", "openid admin", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &writeCountingStore{Store: memory.New()}
			env := newExtensionEnv(t, grantingExtension(oauth2.ExtensionGrant{Scope: tc.scope}), withStore(store))

			q := oidcQuery()
			q.Set("scope", "openid read write")

			rec := env.authorize(q, approve)
			require.Equal(t, http.StatusFound, rec.Code)

			params := mustLocation(t, rec).Query()
			if !tc.ok {
				assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
				assert.Zero(t, store.writes.Load())

				return
			}

			rec = env.exchange(params.Get("code"))
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, tc.want, jsonBody(t, rec)["scope"])
		})
	}
}

// TestImplicitTokenRecordsTheExtensionData: the implicit flow runs the
// authorization hooks and records the extension data on its access token;
// its response members are fixed (RFC 6749 §4.2.2): no token-response hook.
func TestImplicitTokenRecordsTheExtensionData(t *testing.T) {
	t.Parallel()

	ext := grantingExtension(oauth2.ExtensionGrant{Data: "implicit-ctx"})
	env := newExtensionEnv(t, ext, withProfile(oauth2.Profile20))

	q := implicitQuery()
	rec := runAuthorizeCfg(env.srv, oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}, q, approve)
	require.Equal(t, http.StatusFound, rec.Code)

	fragment, err := url.ParseQuery(mustLocation(t, rec).Fragment)
	require.NoError(t, err)
	assert.False(t, fragment.Has("id_token"))

	at, err := env.store.LookupAccessToken(t.Context(), oauth2.HashToken(nil, fragment.Get("access_token")))
	require.NoError(t, err)
	assert.Equal(t, "implicit-ctx", at.ExtensionData)
	assert.Equal(t, "https://auth.example", at.Issuer)

	validated, completed, extended := ext.calls()
	assert.Equal(t, 1, validated)
	assert.Equal(t, 1, completed)
	assert.Zero(t, extended)
}
