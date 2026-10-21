// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireTokenError requires err to be the token endpoint's error code.
func requireTokenError(t *testing.T, err error, code string) {
	t.Helper()

	var tokErr *oidcclient.TokenError
	require.ErrorAs(t, err, &tokErr)
	assert.Equal(t, code, tokErr.Code)
	require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint)
}

// withState returns loc with its state replaced.
func withState(loc *url.URL, state string) *url.URL {
	out := *loc
	q := out.Query()
	q.Set("state", state)
	out.RawQuery = q.Encode()

	return &out
}

// TestCodeInjectionIsDefeated models code injection (RFC 9700 §4.5): an
// attacker logs in with the client in its own browser and injects its
// authorization response into the victim's. With its own state, the
// victim's browser binding does not match — the attacker's login stays
// usable by the attacker, not by the victim. With the victim's state
// (leaked), the client redeems the attacker's code with the victim's PKCE
// verifier, which our provider refuses (RFC 7636 §4.6): no login.
func TestCodeInjectionIsDefeated(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())
	token := o.paths(o.base).Token

	victim, err := c.Begin(t.Context(), oidcclient.AuthOptions{})
	require.NoError(t, err)

	attacker, attackerLoc := o.begin(t, c, oidcclient.AuthOptions{})

	_, err = c.Complete(t.Context(), callbackOf(attackerLoc, victim.Binding))
	require.ErrorIs(t, err, oidcclient.ErrBindingMismatch)
	assert.Zero(t, o.hits(token))

	_, err = c.Complete(t.Context(), callbackOf(attackerLoc, attacker.Binding))
	require.NoError(t, err, "the attacker's own login was left intact")

	_, secondLoc := o.begin(t, c, oidcclient.AuthOptions{})

	id, err := c.Complete(t.Context(), callbackOf(withState(secondLoc, victim.State), victim.Binding))
	requireTokenError(t, err, "invalid_grant")
	assert.Nil(t, id)
}

// TestPKCEDowngradeIsRefused models RFC 9700 §4.8.1: the attacker strips
// code_challenge from its own authorization request and injects the code
// into the session of a victim whose client sends its code_verifier. Under
// Profile20, where PKCE is optional, the provider issues such a code but
// refuses the verifier at the token endpoint (§4.8.2); under the default
// profile, the stripped request — or a plain challenge — is refused
// outright.
func TestPKCEDowngradeIsRefused(t *testing.T) {
	t.Parallel()

	strip := func(t *testing.T, raw string, edit func(url.Values)) string {
		t.Helper()

		u, err := url.Parse(raw)
		require.NoError(t, err)

		q := u.Query()
		edit(q)
		u.RawQuery = q.Encode()

		return u.String()
	}

	t.Run("Profile20: the verifier of a code issued without challenge", func(t *testing.T) {
		t.Parallel()

		o := newOP(t, func(cfg *opConfig) { cfg.profile = oauth2.Profile20 })
		c := o.rp(t, o.basic())

		attacker, err := c.Begin(t.Context(), oidcclient.AuthOptions{})
		require.NoError(t, err)

		loc := redirected(t, o.authorize(t, strip(t, attacker.URL, func(q url.Values) {
			q.Del("code_challenge")
			q.Del("code_challenge_method")
		})))
		require.NotEmpty(t, loc.Query().Get("code"), "Profile20 issues a code without PKCE")

		victim, err := c.Begin(t.Context(), oidcclient.AuthOptions{})
		require.NoError(t, err)

		id, err := c.Complete(t.Context(), callbackOf(withState(loc, victim.State), victim.Binding))
		requireTokenError(t, err, "invalid_grant")
		assert.Nil(t, id)
	})

	for name, edit := range map[string]func(url.Values){
		"Profile20BCP: no code_challenge": func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") },
		"Profile20BCP: plain":             func(q url.Values) { q.Set("code_challenge_method", "plain") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o := newOP(t)
			c := o.rp(t, o.basic())

			ar, err := c.Begin(t.Context(), oidcclient.AuthOptions{})
			require.NoError(t, err)

			loc := redirected(t, o.authorize(t, strip(t, ar.URL, edit)))
			assert.Equal(t, "invalid_request", loc.Query().Get("error"))
			assert.Empty(t, loc.Query().Get("code"))
		})
	}
}

// TestCallbackReplay: a callback delivered twice redeems the code once.
func TestCallbackReplay(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())
	ar, loc := o.begin(t, c, oidcclient.AuthOptions{})

	_, err := c.Complete(t.Context(), callbackOf(loc, ar.Binding))
	require.NoError(t, err)

	id, err := c.Complete(t.Context(), callbackOf(loc, ar.Binding))
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	assert.Nil(t, id)
	assert.Equal(t, 1, o.hits(o.paths(o.base).Token), "the replay never reaches the token endpoint")
}

// replayRecorded sends again the index-th request path received — its
// form and its Authorization header — and returns the answer.
func (o *op) replayRecorded(t *testing.T, path string, index int) rawResponse {
	t.Helper()

	recs := o.faults.recordedAt(path)
	require.Greater(t, len(recs), index)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, o.base+path, strings.NewReader(recs[index].form.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", recs[index].header.Get("Authorization"))

	resp, err := o.srv.Client().Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return rawResponse{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

// TestProvenCodeReplayRevokesTheClientsTokens: the token request of a
// completed login replayed as is — the code, its PKCE verifier and the
// client's credentials, stolen together — is refused and revokes every
// token the code issued (RFC 6749 §4.1.2): the client's UserInfo calls
// fail from then on.
func TestProvenCodeReplayRevokesTheClientsTokens(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())

	id, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	_, err = c.UserInfo(t.Context(), id)
	require.NoError(t, err)

	replay := o.replayRecorded(t, o.paths(o.base).Token, 0)
	assert.Equal(t, http.StatusBadRequest, replay.status)
	assert.Contains(t, replay.body, `"invalid_grant"`)

	info, err := c.UserInfo(t.Context(), id)
	require.ErrorIs(t, err, oidcclient.ErrUserInfo)
	assert.Nil(t, info)
}

// TestRefreshReuseRevokesTheClientsTokens: reusing a refresh token the
// provider rotated revokes its whole family (RFC 9700 §4.14.2): the newest
// access token stops working at UserInfo too.
func TestRefreshReuseRevokesTheClientsTokens(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic(), func(cfg *oidcclient.Config) { cfg.Scopes = []string{"profile", "offline_access"} })

	id, err := o.login(t, c, oidcclient.AuthOptions{Prompt: []string{"consent"}})
	require.NoError(t, err)
	require.NotEmpty(t, id.Tokens.RefreshToken.Reveal())

	o.clock.advance(time.Second)

	rotated := o.refresh(t, basicID, basicSecret, id.Tokens.RefreshToken.Reveal())
	require.Equal(t, http.StatusOK, rotated.status, rotated.body)

	newest := *id
	accessToken, _ := rotated.json["access_token"].(string)
	newest.Tokens.AccessToken = oidcclient.NewSecret(accessToken)

	_, err = c.UserInfo(t.Context(), &newest)
	require.NoError(t, err, "the rotated access token works")

	reuse := o.refresh(t, basicID, basicSecret, id.Tokens.RefreshToken.Reveal())
	assert.True(t, reuse.isCode("invalid_grant"), reuse.body)

	_, err = c.UserInfo(t.Context(), &newest)
	require.ErrorIs(t, err, oidcclient.ErrUserInfo, "the family is revoked")
}
