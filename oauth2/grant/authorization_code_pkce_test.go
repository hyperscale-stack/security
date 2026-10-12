// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wellFormedWrongVerifier is RFC 7636 §4.1 compliant but does not match
// codeChallenge, so only the PKCE comparison can refuse it.
const wellFormedWrongVerifier = "a-well-formed-verifier-that-does-not-match-the-challenge"

// unreservedAlphabet is the RFC 3986 §2.3 unreserved set a code verifier is
// drawn from (RFC 7636 §4.1).
const unreservedAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// seedPKCECode stores an authorization code bound to challenge / method and
// returns the /token request presenting verifier under profile.
func seedPKCECode(
	t *testing.T,
	store oauth2.Storage,
	method pkce.Method,
	challenge, verifier string,
	profile oauth2.Profile,
) grant.Request {
	t.Helper()

	raw := "raw-pkce-code"
	require.NoError(t, store.SaveAuthorizationCode(context.Background(), &oauth2.AuthorizationCode{
		Code: raw, CodeHash: oauth2.HashToken(nil, raw),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, Scope: "read:mail",
		CodeChallenge: challenge, CodeChallengeMethod: string(method),
		IssuedAt:  time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 5, 20, 12, 10, 0, 0, time.UTC),
		Issuer:    "https://auth.example",
	}))

	form := url.Values{}
	form.Set("code", raw)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	return grant.Request{
		Client: newClient(), Form: form, Profile: profile,
		Issuer: "https://auth.example", Audience: "api",
		Now: time.Date(2026, 5, 20, 12, 5, 0, 0, time.UTC),
	}
}

// newPKCEGrant builds an authorization_code grant that does not force PKCE
// itself: the profile of each request decides.
func newPKCEGrant(store oauth2.Storage) *grant.AuthorizationCode {
	return grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})
}

// mustS256 derives the S256 challenge of verifier.
func mustS256(t *testing.T, verifier string) string {
	t.Helper()

	c, ok := pkce.Challenge(pkce.MethodS256, verifier)
	require.True(t, ok)

	return c
}

// TestAuthorizationCodeRejectsMalformedVerifier stores the S256 challenge of
// each malformed verifier, so the transformation matches and only the RFC
// 7636 §4.1 syntax check can refuse the exchange.
func TestAuthorizationCodeRejectsMalformedVerifier(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		verifier string
	}{
		{"one character (issue #79)", "x"},
		{"42 chars", strings.Repeat("a", 42)},
		{"129 chars", strings.Repeat("a", 129)},
		{"non-ASCII", strings.Repeat("a", 41) + "é"},
		{"trailing LF", codeVerifier + "\n"},
		{"embedded space", codeVerifier[:20] + " " + codeVerifier[20:]},
		{"standard base64 plus", strings.Repeat("a", 42) + "+"},
		{"standard base64 slash", strings.Repeat("a", 42) + "/"},
		{"base64 padding", strings.Repeat("a", 42) + "="},
		{"percent-encoded tilde", strings.Repeat("a", 40) + "%7E"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newStore()
			req := seedPKCECode(t, store, pkce.MethodS256, mustS256(t, tc.verifier), tc.verifier, oauth2.Profile20BCP)

			resp, err := newPKCEGrant(store).Handle(context.Background(), req)
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
			assert.ErrorContains(t, err, "malformed code_verifier")
		})
	}
}

// TestAuthorizationCodeAcceptsWellFormedVerifiers is a regression guard for
// the RFC 7636 §4.1 bounds and alphabet.
func TestAuthorizationCodeAcceptsWellFormedVerifiers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		verifier string
	}{
		{"43 chars (the minimum)", strings.Repeat("a", 43)},
		{"128 chars (the maximum)", strings.Repeat("a", 128)},
		{"the whole unreserved alphabet", unreservedAlphabet},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newStore()
			req := seedPKCECode(t, store, pkce.MethodS256, mustS256(t, tc.verifier), tc.verifier, oauth2.Profile20BCP)

			resp, err := newPKCEGrant(store).Handle(context.Background(), req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.Pair.Access.Token)
		})
	}
}

// TestAuthorizationCodeProfile20WithoutPKCE is a regression guard: PKCE
// stays optional under Profile20 when the grant does not require it.
func TestAuthorizationCodeProfile20WithoutPKCE(t *testing.T) {
	t.Parallel()

	store := newStore()
	req := seedPKCECode(t, store, "", "", "", oauth2.Profile20)

	resp, err := newPKCEGrant(store).Handle(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Pair.Access.Token)
}

// TestAuthorizationCodePlainRejectsMalformedVerifier covers a plain pair
// that matches verbatim but is too short to be a code verifier. The empty
// method defaults to plain (RFC 7636 §4.3), which Profile20 tolerates.
func TestAuthorizationCodePlainRejectsMalformedVerifier(t *testing.T) {
	t.Parallel()

	store := newStore()
	req := seedPKCECode(t, store, "", "shared-plain-secret", "shared-plain-secret", oauth2.Profile20)

	_, err := newPKCEGrant(store).Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
	assert.ErrorContains(t, err, "malformed code_verifier")
}

// TestAuthorizationCodeMalformedStoredChallengeNeverMatches documents codes
// stored before /authorize validated the challenge: a well-formed verifier
// can never match a malformed challenge, so the exchange fails as a plain
// mismatch.
func TestAuthorizationCodeMalformedStoredChallengeNeverMatches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		method    pkce.Method
		challenge string
		profile   oauth2.Profile
	}{
		{"padded S256 challenge", pkce.MethodS256, codeChallenge + "=", oauth2.Profile20BCP},
		{"short S256 challenge", pkce.MethodS256, "abc", oauth2.Profile20BCP},
		{"short plain challenge", pkce.MethodPlain, "shared-plain-secret", oauth2.Profile20},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newStore()
			req := seedPKCECode(t, store, tc.method, tc.challenge, codeVerifier, tc.profile)

			_, err := newPKCEGrant(store).Handle(context.Background(), req)
			require.Error(t, err)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
			assert.ErrorContains(t, err, "PKCE verification failed")
		})
	}
}
