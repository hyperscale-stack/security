// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest

import (
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// The RFC 7636 Appendix B PKCE pair the replay case redeems codes with.
const (
	replayVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	replayChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// redeemCode saves the authorization code raw — S256 PKCE, issued to the
// test client under the suite's issuer — into s, redeems it through g at
// that issuer, and returns the /token request it sent and the pair the
// exchange issued.
func redeemCode(t *testing.T, s oauth2.Storage, g *grant.AuthorizationCode, raw string) (grant.Request, *oauth2.TokenPair) {
	t.Helper()

	now := time.Now()

	mustNoError(t, s.SaveAuthorizationCode(ctx(), &oauth2.AuthorizationCode{
		Code: raw, CodeHash: oauth2.HashToken(nil, raw),
		ClientID: testClientID, Subject: testSubject, RedirectURI: testRedirectURI, Scope: testScope,
		CodeChallenge: replayChallenge, CodeChallengeMethod: string(pkce.MethodS256),
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Issuer: testIssuer,
	}), "save code "+raw)

	req := grant.Request{
		Client: &oauth2.DefaultClient{
			IDValue: testClientID, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{testRedirectURI}, ScopeValues: []string{testScope},
			GrantTypeValues: []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken},
		},
		Form:    url.Values{"code": {raw}, "redirect_uri": {testRedirectURI}, "code_verifier": {replayVerifier}},
		Issuer:  testIssuer,
		Now:     now,
		Profile: oauth2.Profile20BCP,
	}

	resp, err := g.Handle(ctx(), req)
	mustNoError(t, err, "exchange code "+raw)

	return req, &resp.Pair
}

// testCodeReplayRevokesIssuedTokens drives the real authorization_code
// grant over the store. Two codes of the same client are exchanged, then
// the first one is replayed with the same proof: the replay is refused,
// and the tokens the first exchange issued are no longer usable through
// the store (RFC 6749 §4.1.2), while those of the other code and a token
// outside any family are untouched.
func testCodeReplayRevokesIssuedTokens(t *testing.T, s oauth2.Storage) {
	g := grant.NewAuthorizationCode(grant.Config{
		Storage:       s,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
	})

	replayed, first := redeemCode(t, s, g, "replay-a")
	_, other := redeemCode(t, s, g, "replay-b")

	cc := accessOnly("replay-cc", "")
	mustSave(t, s, cc)

	requireUsable(t, s, first)

	resp, err := g.Handle(ctx(), replayed)
	mustEqual(t, resp == nil, true, "replay: no tokens issued")
	mustErrorIs(t, err, oauth2.ErrCodeAlreadyUsed, "replay")

	requireUnusable(t, s, first)
	requireUsable(t, s, other)
	requireUsable(t, s, cc)
}
