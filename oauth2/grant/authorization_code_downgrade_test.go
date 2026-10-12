// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// downgradeDescription is the refusal of a code_verifier presented for a
// code issued without code_challenge.
const downgradeDescription = "code_verifier sent for a code issued without code_challenge"

// TestAuthorizationCodeRefusesAVerifierWithoutAChallenge pins RFC 9700
// §4.8.2: "if there was no code_challenge in the authorization request, a
// request to the token endpoint containing a code_verifier is rejected" —
// the PKCE downgrade attack, where an attacker strips code_challenge from
// its own authorization request and injects the resulting code into a
// victim's session. Under every profile; the code is burned and nothing is
// issued.
func TestAuthorizationCodeRefusesAVerifierWithoutAChallenge(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		profile  oauth2.Profile
		verifier string
	}{
		{"Profile20, well-formed verifier", oauth2.Profile20, codeVerifier},
		{"Profile20, malformed verifier", oauth2.Profile20, "x"},
		{"Profile20BCP, stored challenge-less code", oauth2.Profile20BCP, codeVerifier},
		{"Profile21Draft, stored challenge-less code", oauth2.Profile21Draft, codeVerifier},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: memory.New()}
			req := seedPKCECode(t, store, "", "", tc.verifier, tc.profile)

			resp, err := newPKCEGrant(store).Handle(context.Background(), req)
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
			assert.Empty(t, store.savedPairs(), "nothing is issued")

			if tc.profile == oauth2.Profile20 {
				assert.ErrorContains(t, err, downgradeDescription)
			}

			// The code is burned: even without a verifier it no longer
			// redeems.
			req.Form.Del("code_verifier")

			resp, err = newPKCEGrant(store).Handle(context.Background(), req)
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Empty(t, store.savedPairs())
		})
	}
}

// TestAuthorizationCodeVerifierRepeatedWithAnEmptyFirstValue checks that
// a repeated code_verifier whose first value is empty still counts as a
// verifier: an empty parameter is an omitted one (RFC 6749 §3.1), not a
// way to hide the second.
func TestAuthorizationCodeVerifierRepeatedWithAnEmptyFirstValue(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	req := seedPKCECode(t, store, "", "", "", oauth2.Profile20)
	req.Form["code_verifier"] = []string{"", codeVerifier}

	resp, err := newPKCEGrant(store).Handle(context.Background(), req)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, downgradeDescription)
	assert.Empty(t, store.savedPairs())
}

// TestAuthorizationCodeWithoutChallengeOrVerifier is a regression guard:
// under Profile20 a code issued without code_challenge still redeems
// without a code_verifier — absent, or present without a value, which RFC
// 6749 §3.1 treats as omitted.
func TestAuthorizationCodeWithoutChallengeOrVerifier(t *testing.T) {
	t.Parallel()

	for name, edit := range map[string]func(grant.Request){
		"verifier absent":         func(req grant.Request) { req.Form.Del("code_verifier") },
		"verifier without value":  func(req grant.Request) { req.Form.Set("code_verifier", "") },
		"verifier repeated empty": func(req grant.Request) { req.Form["code_verifier"] = []string{"", ""} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := newStore()
			req := seedPKCECode(t, store, "", "", "", oauth2.Profile20)
			edit(req)

			resp, err := newPKCEGrant(store).Handle(context.Background(), req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.Pair.Access.Token)
		})
	}
}

// TestAuthorizationCodeDowngradeRefusalKeepsReplayRevocation checks that
// the refusal applies to issuance only: a code redeemed without PKCE, then
// replayed with a code_verifier by a request that otherwise passes what its
// first exchange passed, still revokes the tokens the code issued (RFC 6749
// §4.1.2, #80) — the verifier proves nothing either way.
func TestAuthorizationCodeDowngradeRefusalKeepsReplayRevocation(t *testing.T) {
	t.Parallel()

	store := &replayStore{Store: memory.New()}
	req := seedPKCECode(t, store, "", "", "", oauth2.Profile20)
	g := newPKCEGrant(store)

	issued, err := g.Handle(context.Background(), req)
	require.NoError(t, err)

	req.Form.Set("code_verifier", codeVerifier)

	resp, err := g.Handle(context.Background(), req)
	require.ErrorIs(t, err, oauth2.ErrCodeAlreadyUsed)
	assert.Nil(t, resp)
	assert.Equal(t, int32(1), store.revokes.Load(), "the replay revoked the code's family")

	_, err = store.LookupAccessToken(context.Background(), oauth2.HashToken(nil, issued.Pair.Access.Token))
	require.Error(t, err, "the access token the code issued is revoked")
}
