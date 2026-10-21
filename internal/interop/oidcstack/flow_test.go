// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCodeFlowAgainstOurProvider runs the Authorization Code flow with PKCE
// S256 and a nonce, our relying party against our provider, for every
// client authentication method — client_secret_basic with a client ID and
// secret holding every character RFC 6749 §2.3.1 form-encodes — and for a
// root issuer, a path issuer and a path issuer ending with a slash
// (Discovery §4.1, §4.3: both sides strip one slash to build the discovery
// URL, the issuer stays verbatim). The provider names its issuer in the
// response (RFC 9207), which the client then requires; the ID Token's
// at_hash and nonce are checked; UserInfo answers for the same subject.
func TestCodeFlowAgainstOurProvider(t *testing.T) {
	t.Parallel()

	o := newOP(t)

	cases := []struct {
		name string
		c    connection
	}{
		{"client_secret_basic, encoded credentials", o.basic()},
		{"client_secret_post", conn("post", o.base, postID, postSecret, oidcclient.AuthMethodClientSecretPost)},
		{"public client", conn("public", o.base, publicID, "", oidcclient.AuthMethodNone)},
		{"path issuer", o.tenant(tenantA, tenantAID)},
		{"path issuer with a trailing slash", o.tenant(tenantC, tenantCID)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := o.rp(t, tc.c)
			ar, loc := o.begin(t, c, oidcclient.AuthOptions{})
			assert.Equal(t, tc.c.issuer, loc.Query().Get("iss"), "RFC 9207 iss")

			id, err := c.Complete(t.Context(), callbackOf(loc, ar.Binding))
			require.NoError(t, err)
			assert.Equal(t, tc.c.name, id.ConnectionID)
			assert.Equal(t, tc.c.issuer, id.Issuer)
			assert.Equal(t, alice, id.Subject)
			assert.Equal(t, []string{tc.c.clientID}, id.Audience)
			assert.Equal(t, []string{"pwd"}, id.AMR)
			assert.WithinDuration(t, o.clock.now(), id.AuthTime, 2*time.Second)

			_, claims := jwsParts(t, id.Tokens.IDToken.Reveal())
			assert.Contains(t, claims, "at_hash", "the client verified at_hash")
			assert.Contains(t, claims, "nonce")

			info, err := c.UserInfo(t.Context(), id)
			require.NoError(t, err)
			assert.Equal(t, id.Subject, info.Subject)

			var profile struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			}

			require.NoError(t, info.Decode(&profile))
			assert.Equal(t, "Alice Liddell", profile.Name)
			assert.Equal(t, "alice@example.com", profile.Email)
		})
	}
}

// TestCodeFlowSigningAlgorithms checks every ID Token algorithm a client
// may register (Registration §2 id_token_signed_response_alg): our provider
// signs with the issuer's key of that algorithm, our client — configured
// with that algorithm (Config.Algorithms, Core §3.1.3.7 step 7) — verifies
// the signature and the at_hash computed with the algorithm's hash (Core
// §3.1.3.6).
func TestCodeFlowSigningAlgorithms(t *testing.T) {
	t.Parallel()

	o := newOP(t)

	for _, alg := range []jwtsec.Algorithm{
		jwtsec.RS256, jwtsec.RS384, jwtsec.RS512, jwtsec.PS256, jwtsec.PS384, jwtsec.PS512,
		jwtsec.ES256, jwtsec.ES384, jwtsec.ES512,
	} {
		t.Run(string(alg), func(t *testing.T) {
			t.Parallel()

			name := strings.ToLower(string(alg))
			c := o.rp(t, conn(name, o.base, "rp-"+name, secret, oidcclient.AuthMethodClientSecretBasic),
				func(cfg *oidcclient.Config) { cfg.Algorithms = []oidcclient.Algorithm{oidcclient.Algorithm(alg)} })

			id, err := o.login(t, c, oidcclient.AuthOptions{})
			require.NoError(t, err)

			header, _ := jwsParts(t, id.Tokens.IDToken.Reveal())
			assert.Equal(t, string(alg), header["alg"])
			assert.Equal(t, "root-"+name, header["kid"])
		})
	}
}

// TestFormPostRefusedAgainstAQueryOnlyProvider: the provider advertises the
// query response mode only, so a connection configured for form_post is
// refused when it is built, before any login.
func TestFormPostRefusedAgainstAQueryOnlyProvider(t *testing.T) {
	t.Parallel()

	o := newOP(t)

	_, err := oidcclient.New(t.Context(), o.config(o.basic(), func(cfg *oidcclient.Config) {
		cfg.ResponseMode = oidcclient.ResponseModeFormPost
	}))
	require.ErrorIs(t, err, oidcclient.ErrInvalidMetadata)
}

// TestPromptNoneThroughTheClient: without a session, prompt=none comes back
// as login_required — matched to its login by the client, with the
// provider's iss — and never reaches the token endpoint; with a session it
// logs in silently (Core §3.1.2.1, §3.1.2.6).
func TestPromptNoneThroughTheClient(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())
	silent := oidcclient.AuthOptions{Prompt: []string{"none"}}

	o.enduser.set(func(s *script) { s.signedOut = true })

	ar, loc := o.begin(t, c, silent)
	assert.Equal(t, o.base, loc.Query().Get("iss"))

	id, err := c.Complete(t.Context(), callbackOf(loc, ar.Binding))
	requireAuthorizationError(t, err, "login_required")
	assert.Nil(t, id)
	assert.Zero(t, o.hits(o.paths(o.base).Token))

	o.enduser.set(func(s *script) { s.signedOut = false })

	id, err = o.login(t, c, silent)
	require.NoError(t, err)
	assert.Equal(t, alice, id.Subject)
}

// requireAuthorizationError requires err to be the provider's error
// response code.
func requireAuthorizationError(t *testing.T, err error, code string) {
	t.Helper()

	var authErr *oidcclient.AuthorizationError
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, code, authErr.Code)
	require.ErrorIs(t, err, oidcclient.ErrAuthorizationFailed)
}

// TestReauthenticationThroughTheClient: max_age and prompt=login are
// enforced by the provider — an application approving a stale session is
// refused login_required — and the client checks the auth_time it gets
// against the max_age it sent (Core §3.1.2.1, §3.1.3.7).
func TestReauthenticationThroughTheClient(t *testing.T) {
	t.Parallel()

	zero, minute, hour := time.Duration(0), time.Minute, time.Hour

	cases := []struct {
		name    string
		opts    oidcclient.AuthOptions
		authAge time.Duration
		refused bool
	}{
		{"max_age=0, fresh authentication", oidcclient.AuthOptions{MaxAge: &zero}, 0, false},
		{"prompt=login, fresh authentication", oidcclient.AuthOptions{Prompt: []string{"login"}}, 0, false},
		{"max_age=1h, 30-minute-old session", oidcclient.AuthOptions{MaxAge: &hour}, 30 * time.Minute, false},
		{"max_age=60, 2-hour-old session", oidcclient.AuthOptions{MaxAge: &minute}, 2 * time.Hour, true},
		{"max_age=0, 1-minute-old session", oidcclient.AuthOptions{MaxAge: &zero}, time.Minute, true},
		{"prompt=login, 1-minute-old session", oidcclient.AuthOptions{Prompt: []string{"login"}}, time.Minute, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			o := newOP(t)
			o.enduser.set(func(s *script) { s.authAge = tc.authAge })
			c := o.rp(t, o.basic())

			id, err := o.login(t, c, tc.opts)
			if tc.refused {
				requireAuthorizationError(t, err, "login_required")
				assert.Zero(t, o.hits(o.paths(o.base).Token))

				return
			}

			require.NoError(t, err)
			assert.WithinDuration(t, o.clock.now().Add(-tc.authAge), id.AuthTime, 2*time.Second)
		})
	}
}

// TestACRValuesThroughTheClient: the provider passes acr_values through to
// the application (voluntary, Core §3.1.2.1) and puts the application's acr
// in the ID Token; the client requires it to be one of the values it sent.
func TestACRValuesThroughTheClient(t *testing.T) {
	t.Parallel()

	requested := []string{"urn:acr:gold", "urn:acr:silver"}

	cases := []struct {
		acr  string
		want error
	}{
		{"urn:acr:silver", nil},
		{"urn:acr:bronze", oidcclient.ErrIDTokenACR},
		{"", oidcclient.ErrIDTokenACR},
	}

	for _, tc := range cases {
		t.Run("acr="+tc.acr, func(t *testing.T) {
			t.Parallel()

			o := newOP(t)
			o.enduser.set(func(s *script) { s.acr = tc.acr })
			c := o.rp(t, o.basic())

			id, err := o.login(t, c, oidcclient.AuthOptions{ACRValues: requested})
			assert.Equal(t, requested, o.enduser.lastRequest(t).ACRValues)

			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				assert.Nil(t, id)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.acr, id.ACR)
		})
	}
}

// TestHintsReachTheProvider: login_hint, ui_locales and display reach the
// application; an id_token_hint designates the end-user (Core §3.1.2.1) —
// another end-user's session answers login_required.
func TestHintsReachTheProvider(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())

	first, err := o.login(t, c, oidcclient.AuthOptions{LoginHint: "alice@example.com", UILocales: []string{"fr", "en"}, Display: "page"})
	require.NoError(t, err)

	req := o.enduser.lastRequest(t)
	assert.Equal(t, "alice@example.com", req.LoginHint)
	assert.Equal(t, []string{"fr", "en"}, req.UILocales)
	assert.Equal(t, "page", req.Display)

	hinted := oidcclient.AuthOptions{IDTokenHint: first.Tokens.IDToken, Prompt: []string{"none"}}

	id, err := o.login(t, c, hinted)
	require.NoError(t, err, "the same end-user")
	assert.Equal(t, alice, id.Subject)
	assert.Equal(t, []string{alice}, o.enduser.lastRequest(t).Subjects)

	o.enduser.set(func(s *script) { s.subject = bob })

	_, err = o.login(t, c, hinted)
	requireAuthorizationError(t, err, "login_required")
}

// TestConsentDeniedThroughTheClient: a denial comes back as access_denied
// and never reaches the token endpoint (Core §3.1.2.6).
func TestConsentDeniedThroughTheClient(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	o.enduser.set(func(s *script) { s.deny = true })

	_, err := o.login(t, o.rp(t, o.basic()), oidcclient.AuthOptions{})
	requireAuthorizationError(t, err, "access_denied")
	assert.Zero(t, o.hits(o.paths(o.base).Token))
}

// TestGrantedScopeDrivesUserInfo: UserInfo releases the claims of the
// granted scopes only (Core §5.4) — a client asking for less, or an
// end-user granting less, gets no email.
func TestGrantedScopeDrivesUserInfo(t *testing.T) {
	t.Parallel()

	userinfo := func(t *testing.T, o *op, c *oidcclient.Client) (map[string]any, *oidcclient.Identity) {
		t.Helper()

		id, err := o.login(t, c, oidcclient.AuthOptions{})
		require.NoError(t, err)

		info, err := c.UserInfo(t.Context(), id)
		require.NoError(t, err)

		var claims map[string]any
		require.NoError(t, json.Unmarshal(info.Claims, &claims))

		return claims, id
	}

	t.Run("client requests profile only", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		claims, _ := userinfo(t, o, o.rp(t, o.basic(), func(cfg *oidcclient.Config) { cfg.Scopes = []string{"profile"} }))
		assert.Equal(t, "Alice Liddell", claims["name"])
		assert.NotContains(t, claims, "email")
	})

	t.Run("end-user grants profile only", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		o.enduser.set(func(s *script) { s.scope = "openid profile" })
		claims, id := userinfo(t, o, o.rp(t, o.basic()))
		assert.Equal(t, "openid profile", id.Tokens.Scope)
		assert.Contains(t, claims, "name")
		assert.NotContains(t, claims, "email")
	})
}

// TestRefreshOfAClientLogin: offline_access consented in the consent
// dialog yields a refresh token (Core §11), which the application redeems
// itself — the client has no refresh helper — and the ID Token of the
// refresh keeps iss, sub, aud and the original authentication, with a new
// iat and no nonce (Core §12.2). Without the consent dialog, no refresh
// token.
func TestRefreshOfAClientLogin(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic(), func(cfg *oidcclient.Config) { cfg.Scopes = []string{"profile", "offline_access"} })

	id, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)
	assert.Empty(t, id.Tokens.RefreshToken.Reveal(), "no consent dialog, no offline access")

	id, err = o.login(t, c, oidcclient.AuthOptions{Prompt: []string{"consent"}})
	require.NoError(t, err)
	require.NotEmpty(t, id.Tokens.RefreshToken.Reveal())

	o.clock.advance(time.Minute)

	refreshed := o.refresh(t, basicID, basicSecret, id.Tokens.RefreshToken.Reveal())
	require.Equal(t, http.StatusOK, refreshed.status, refreshed.body)

	raw, ok := refreshed.json["id_token"].(string)
	require.True(t, ok, "an ID Token at the refresh")

	verified, err := jwtsec.VerifySignature(t.Context(), raw, publicKeys(t, rootRing().Signing...))
	require.NoError(t, err)

	var before, after map[string]any
	_, before = jwsParts(t, id.Tokens.IDToken.Reveal())
	require.NoError(t, json.Unmarshal(verified.Payload, &after))

	for _, claim := range []string{"iss", "sub", "aud", "auth_time", "amr"} {
		assert.Equal(t, before[claim], after[claim], claim)
	}

	assert.NotContains(t, after, "nonce")
	assert.Greater(t, after["iat"], before["iat"], "iat is the time of the refresh")
}

// tokenResponse is a raw /token answer.
type tokenResponse struct {
	status int
	body   string
	json   map[string]any
}

// refresh redeems a refresh token at the root issuer as the client id with
// client_secret_basic (credentials form-encoded, RFC 6749 §2.3.1).
func (o *op) refresh(t *testing.T, id, sec, refreshToken string) tokenResponse {
	t.Helper()

	return o.tokenRequest(t, o.base, id, sec, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

// tokenRequest posts form to the token endpoint of issuer as the client
// id, authenticated with client_secret_basic.
func (o *op) tokenRequest(t *testing.T, issuer, id, sec string, form url.Values) tokenResponse {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, o.base+o.paths(issuer).Token, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(sec))

	resp, err := o.srv.Client().Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	out := tokenResponse{status: resp.StatusCode, body: string(body)}
	_ = json.Unmarshal([]byte(out.body), &out.json)

	return out
}

// isCode reports whether a raw /token answer is the RFC 6749 §5.2 error
// code.
func (r tokenResponse) isCode(code string) bool {
	return r.status >= http.StatusBadRequest && r.json["error"] == code
}
