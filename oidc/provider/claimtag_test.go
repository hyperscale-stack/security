// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"

	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A language-tagged claim is a claim name, "#" and a BCP 47 language tag
// (OIDC Core §5.2, RFC 5646). lodash's and change-case's camelCase split
// words on "#": they read "email_verified#", "email#verified" and
// "email#verified-fr" as emailVerified and emailVerifiedFr — the names of
// email_verified and of its tagged variant email_verified#fr.

// tagControls are genuine language-tagged claims (Core §5.2's examples
// among them): always released with their scope.
var tagControls = map[string]any{
	"family_name#ja-Kana-JP": "イブ", "website#de": "https://eve.example/de", "name#fr": "Ève",
	"name#x-private": "Eve X", "name#i-klingon": "Eve K",
}

// TestTaggedAliasesOfKnownClaimsAreNeverReleased (Core §5.2, §5.4): a
// source name that a camelCase relying party reads as a known claim — an
// empty or malformed tag, or a tag that continues the claim's name — is
// never released, whether the genuine claim is released next to it or not.
func TestTaggedAliasesOfKnownClaimsAreNeverReleased(t *testing.T) {
	t.Parallel()

	cases := map[string]struct{ genuine, aliases map[string]any }{
		"next to the genuine claims": {
			genuine: map[string]any{"email_verified": true, "phone_number_verified": true, "given_name": "Eve"},
			aliases: map[string]any{
				"email_verified#": false, "email_verified#-": false, "email#verified": false, "email#verified-fr": false,
				"phone_number#verified": false, "given_name#": "Mallory", "name#": "Mallory",
			},
		},
		"alone": {
			genuine: map[string]any{},
			aliases: map[string]any{
				"email_verified#": true, "email#verified": true, "email#verified-fr": true, "phone_number#verified": true,
				"given_name#": "Mallory", "family_name#": "Mallory",
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want := map[string]any{"sub": "eve", "email": "eve@example.com", "phone_number": "+33 1 00 00 00 00", "name": "Eve"}
			maps.Copy(want, tagControls)
			maps.Copy(want, tc.genuine)

			user := maps.Clone(want)
			delete(user, "sub")
			maps.Copy(user, tc.aliases)

			e := newEnv(t)
			e.claims.setUser("eve", user)
			e.approveAs("eve")

			resp := e.flow(with(authorizeQuery(), "scope", "openid email profile phone"))
			assert.Equal(t, want, userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken))))
		})
	}
}

// TestTaggedAliasesOfRequestedClaimsAreNeverReleased: a tagged variant of a
// requested claim is released with it (Core §5.2) unless its name, as a
// whole, reads as a protocol or known claim or a tagged variant of one
// ("given#name-de" as given_name#de, "s#ub-fr" as sub) — in the ID Token
// and at UserInfo alike.
func TestTaggedAliasesOfRequestedClaimsAreNeverReleased(t *testing.T) {
	t.Parallel()

	genuine := map[string]any{"given": "g", "phone": "p", "s": "s", "email": "eve@example.com", "email_verified#fr": false}
	aliases := map[string]any{
		"given#name-de": "Mallory", "phone#number-fr": "+0", "s#ub": "mallory", "s#ub-fr": "mallory",
		"email#verified-fr": true, "s#ub-x-y": "mallory",
	}

	user := maps.Clone(genuine)
	maps.Copy(user, aliases)

	e := newEnv(t)
	e.claims.setUser("eve", user)
	e.approveAs("eve")

	requested := slices.Sorted(maps.Keys(genuine))
	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", claimsParameter(t, requested, requested)))

	_, claims := e.idToken(resp.IDToken)
	userInfo := userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken)))

	for target, got := range map[string]map[string]any{"ID Token": claims, "UserInfo": userInfo} {
		assert.Equal(t, "eve", got["sub"], target)

		for name, value := range genuine {
			assert.Equal(t, value, got[name], "%s: %s", target, name)
		}

		for name := range aliases {
			assert.NotContains(t, got, name, target)
		}
	}
}

// TestClaimsParameterNeverAsksForTaggedAliases (Core §5.5): a requested
// name that reads as a protocol or known claim is neither shown to the
// interaction nor asked of the source — silently, never an error.
func TestClaimsParameterNeverAsksForTaggedAliases(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	request := `{"userinfo": {"email#verified": null, "s#ub": null, "email_verified#": null, "name#": null,
		"s#ub-fr": null, "email#verified-fr": null, "phone_number#verified": null, "#sub": null, "name#fr": null}}`

	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", request))
	userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken)))

	assert.Equal(t, []string{"name#fr"}, requestNames(e.lastRequest().Claims.UserInfo))

	queries := e.claims.recorded()
	require.NotEmpty(t, queries)
	assert.Equal(t, oidcprovider.ClaimsForUserInfo, queries[len(queries)-1].Target)
	assert.Equal(t, []string{"name#fr"}, queries[len(queries)-1].Names)
}

// TestMalformedLanguageTagsAreNotTaggedVariants (Core §5.2, RFC 5646 §2.1):
// a "#" not followed by a well-formed language tag is no tag delimiter, so
// "foo#", "foo#1" or "foo#fr-" is no variant of a requested foo — an
// undeclared claim, which only this rule protects.
func TestMalformedLanguageTagsAreNotTaggedVariants(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.claims.setUser("eve", map[string]any{
		"foo": "kept", "foo#fr": "tagged", "foo#": "x", "foo#1": "x", "foo#toolongtag": "x", "foo#fr-": "x", "foo#fr#de": "x",
	})
	e.approveAs("eve")

	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", claimsParameter(t, []string{"foo"}, nil)))

	_, claims := e.idToken(resp.IDToken)
	assert.Equal(t, "kept", claims["foo"])
	assert.Equal(t, "tagged", claims["foo#fr"])

	for _, name := range []string{"foo#", "foo#1", "foo#toolongtag", "foo#fr-", "foo#fr#de"} {
		assert.NotContains(t, claims, name)
	}
}

// TestURIClaimNamesWithAFragmentAreOrdinaryNames (RFC 7519 §4.2): a "#"
// without a well-formed language tag after it is an ordinary character —
// a URI claim name with a fragment is declared, requested and released
// like any other name — and a name without a claim name before its "#" is
// no tagged name.
func TestURIClaimNamesWithAFragmentAreOrdinaryNames(t *testing.T) {
	t.Parallel()

	declared := []string{"https://example.com/claims#user_roles", "https://example.com/claims#roles", "tenant#"}
	e := newEnv(t, withConfig(func(c *oidcprovider.Config) { c.ClaimsSupported = declared }))
	e.claims.setUser("eve", map[string]any{
		"https://example.com/claims#user_roles": "admin", "https://example.com/claims#roles": "user",
		"tenant#": "eve-co", "#fr": "fr", "#sub": "mallory",
	})
	e.approveAs("eve")

	requested := []string{"https://example.com/claims#user_roles", "https://example.com/claims#roles", "tenant#", "#fr", "#sub"}
	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", claimsParameter(t, requested, nil)))

	_, claims := e.idToken(resp.IDToken)
	assert.Equal(t, "admin", claims["https://example.com/claims#user_roles"])
	assert.Equal(t, "user", claims["https://example.com/claims#roles"])
	assert.Equal(t, "eve-co", claims["tenant#"])
	assert.Equal(t, "fr", claims["#fr"])
	assert.NotContains(t, claims, "#sub", "reads as sub")
	assert.Equal(t, "eve", claims["sub"])

	var doc struct {
		Claims []string `json:"claims_supported"`
	}

	rec := serve(e.op.DiscoveryHandler(), get("/.well-known/openid-configuration"))
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	assert.Subset(t, doc.Claims, declared)
}

// TestNamesWhoseClaimNameIsAKnownClaimsVariantAreNeverReleased: a name whose
// part before its first "#" is a protocol claim or another spelling of a
// known claim is never released, even requested exactly and without a
// well-formed tag — a relying party splitting language tags leniently
// would read "sub#x" as sub and "Email#x" as email.
func TestNamesWhoseClaimNameIsAKnownClaimsVariantAreNeverReleased(t *testing.T) {
	t.Parallel()

	aliases := []string{"sub#x", "Email#x", "EMAIL_VERIFIED#1", "\u017fub#-"}
	user := map[string]any{"email#x": "kept"}

	for _, name := range aliases {
		user[name] = "mallory"
	}

	e := newEnv(t)
	e.claims.setUser("eve", user)
	e.approveAs("eve")

	requested := append([]string{"email#x"}, aliases...)
	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", claimsParameter(t, requested, requested)))

	_, claims := e.idToken(resp.IDToken)
	userInfo := userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken)))

	for target, got := range map[string]map[string]any{"ID Token": claims, "UserInfo": userInfo} {
		assert.Equal(t, "eve", got["sub"], target)
		assert.Equal(t, "kept", got["email#x"], "%s: email is spelled exactly", target)

		for _, name := range aliases {
			assert.NotContains(t, got, name, target)
		}
	}

	assert.Equal(t, []string{"email#x"}, requestNames(e.lastRequest().Claims.IDToken), "never shown to the interaction")
}
