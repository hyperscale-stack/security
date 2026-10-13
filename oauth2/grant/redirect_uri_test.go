// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redirectCodeRequest saves the code raw — S256 PKCE, delivered to the
// test client's redirect URI, the authorization request having omitted
// redirect_uri when omitted — and returns the /token request redeeming it
// with sent as redirect_uri ("" omits it).
func redirectCodeRequest(t *testing.T, store oauth2.Storage, raw string, omitted bool, sent string) grant.Request {
	t.Helper()

	now := time.Now()

	require.NoError(t, store.SaveAuthorizationCode(t.Context(), &oauth2.AuthorizationCode{
		Code: raw, CodeHash: oauth2.HashToken(nil, raw),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, RedirectURIOmitted: omitted, Scope: "read:mail",
		CodeChallenge: codeChallenge, CodeChallengeMethod: string(pkce.MethodS256),
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Issuer: "https://auth.example",
	}))

	form := url.Values{"code": {raw}, "code_verifier": {codeVerifier}}
	if sent != "" {
		form.Set("redirect_uri", sent)
	}

	return grant.Request{
		Client: newClient(), Form: form, Issuer: "https://auth.example", Audience: "api",
		Now: now, Profile: oauth2.Profile20BCP,
	}
}

// TestAuthorizationCodeRedirectURIRule pins RFC 6749 §4.1.3: redirect_uri
// is "REQUIRED, if the redirect_uri parameter was included in the
// authorization request", and whenever present it must be identical to the
// redirect URI the code was delivered to.
func TestAuthorizationCodeRedirectURIRule(t *testing.T) {
	t.Parallel()

	const other = "https://app.example/other"

	cases := []struct {
		name    string
		omitted bool
		sent    string
		ok      bool
	}{
		{"omitted at /authorize, omitted at /token", true, "", true},
		{"omitted at /authorize, the registered URI at /token", true, redirectURI, true},
		{"omitted at /authorize, another URI at /token", true, other, false},
		{"sent at /authorize, omitted at /token", false, "", false},
		{"sent at /authorize, the same at /token", false, redirectURI, true},
		{"sent at /authorize, another at /token", false, other, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: memory.New()}
			req := redirectCodeRequest(t, store, "redirect-code", tc.omitted, tc.sent)

			resp, err := grant.NewAuthorizationCode(rotatingConfig(store, &hookRecorder{})).Handle(t.Context(), req)
			if tc.ok {
				require.NoError(t, err)
				assert.NotEmpty(t, resp.Pair.Access.Token)

				return
			}

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
			assert.ErrorContains(t, err, "redirect_uri mismatch")
			assert.Empty(t, store.savedPairs())
		})
	}
}

// TestRedirectURIRuleAppliesToReplays: a replay proves possession of the
// code exactly when it would have redeemed it — so a replay without
// redirect_uri revokes the family of a code whose authorization request
// omitted it, and revokes nothing when the request included it.
func TestRedirectURIRuleAppliesToReplays(t *testing.T) {
	t.Parallel()

	for name, omitted := range map[string]bool{"omitted": true, "included": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: memory.New()}
			g := grant.NewAuthorizationCode(rotatingConfig(store, &hookRecorder{}))

			sent := ""
			if !omitted {
				sent = redirectURI
			}

			req := redirectCodeRequest(t, store, "replayed-redirect-code", omitted, sent)

			first, err := g.Handle(t.Context(), req)
			require.NoError(t, err)

			replay := withForm(func(f url.Values) { f.Del("redirect_uri") })(req)

			_, err = g.Handle(t.Context(), replay)
			require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)

			if omitted {
				requirePairRevoked(t, store, first.Pair)
			} else {
				requirePairUsable(t, store, first.Pair)
			}
		})
	}
}
