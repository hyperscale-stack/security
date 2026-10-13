// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Claim names are case-sensitive (OIDC Core §5.1, RFC 7519 §4), but relying
// parties match them in other ways: Go's encoding/json under Unicode simple
// case folding (the last match wins), encoding/json/v2's case:ignore also
// ignoring "_" and "-", Java's equalsIgnoreCase with İ and ı, upper-casing
// with full case mappings (ß as SS). A claim an end-user names after
// another one must never be released next to it, nor in its place.

// protocolVariants spell protocol claims differently, as an end-user who
// names her own attributes (custom profile attributes, attributes passed
// through from an upstream directory) would.
var protocolVariants = []string{
	"SUB", "Sub", "\u017fub", "\u017fUB", "s_ub", "S-U-B", "SUB#fr", "\u017fub#x",
	"\u0131ss", "\u0130SS", "Iss", "i\u00df", "aUd", "AUTH_TIME", "authtime", "auth-time",
	"Nonce", "AT-HASH", "_CLAIM_NAMES", "claimnames", "JTI", "Azp", "Sid", "EXP",
}

// claimsParameter encodes a claims parameter requesting names, each with no
// constraint, for the ID Token and UserInfo.
func claimsParameter(t *testing.T, idToken, userInfo []string) string {
	t.Helper()

	member := func(names []string) map[string]any {
		m := map[string]any{}
		for _, name := range names {
			m[name] = nil
		}

		return m
	}

	doc := map[string]any{}
	if idToken != nil {
		doc["id_token"] = member(idToken)
	}

	if userInfo != nil {
		doc["userinfo"] = member(userInfo)
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	return string(b)
}

// approveAs makes subject authenticate and release every claim the
// interaction is shown.
func (e *env) approveAs(subject string) {
	e.approveWith(func(req *oidcprovider.Request) *oidcprovider.Decision {
		var names []string
		for _, c := range append(slices.Clone(req.Claims.IDToken), req.Claims.UserInfo...) {
			names = append(names, c.Name)
		}

		return &oidcprovider.Decision{
			Authentication: &oidcprovider.AuthenticationEvent{Issuer: req.Issuer, Subject: subject, AuthTime: e.clock.Now()},
			Claims:         names,
		}
	})
}

// idTokenPayload verifies the signature of raw and returns its payload as
// sent.
func (e *env) idTokenPayload(raw string) []byte {
	e.t.Helper()

	verified, err := jwtsec.VerifySignature(context.Background(), raw, e.verificationKeys())
	require.NoError(e.t, err)

	return verified.Payload
}

// memberNames returns the member names of the JSON object doc, in order,
// repetitions included.
func memberNames(t *testing.T, doc []byte) []string {
	t.Helper()

	dec := json.NewDecoder(strings.NewReader(string(doc)))

	tok, err := dec.Token()
	require.NoError(t, err)
	require.Equal(t, json.Delim('{'), tok)

	var names []string

	for dec.More() {
		tok, err := dec.Token()
		require.NoError(t, err)

		names = append(names, tok.(string)) //nolint:forcetypeassert // a member name

		var skip json.RawMessage
		require.NoError(t, dec.Decode(&skip))
	}

	return names
}

// userInfoBody returns the UserInfo response of the access token at.
func (e *env) userInfoBody(at string) []byte {
	e.t.Helper()

	rec := e.userinfo(bearerGET(at))
	require.Equal(e.t, 200, rec.Code, rec.Body.String())

	return rec.Body.Bytes()
}

// TestProtocolClaimsCannotBeAliasedByCaseVariants (OIDC Core §2, §5.3.2;
// RFC 7519 §4): an end-user's attributes named like protocol claims —
// whatever the case, "_" and "-", ſ, İ, ı or ß — are never asked of the
// source, never shown to the interaction and never released: the ID Token
// and UserInfo carry the provider's protocol claims only, and a relying
// party decoding them with encoding/json reads the authenticated sub.
func TestProtocolClaimsCannotBeAliasedByCaseVariants(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	attributes := map[string]any{"name": "Mallory"}

	for _, name := range protocolVariants {
		attributes[name] = "alice"
	}

	e.claims.setUser("mallory", attributes)
	e.approveAs("mallory")

	resp := e.flow(with(authorizeQuery(), "scope", "openid",
		"claims", claimsParameter(t, protocolVariants, protocolVariants)))

	payload := e.idTokenPayload(resp.IDToken)
	assert.Equal(t, []string{"at_hash", "aud", "auth_time", "exp", "iat", "iss", "nonce", "sub"}, memberNames(t, payload),
		"the protocol claims only, once each: %s", payload)

	var rp struct {
		Subject  string `json:"sub"`
		Issuer   string `json:"iss"`
		Audience string `json:"aud"`
		Nonce    string `json:"nonce"`
	}

	require.NoError(t, json.Unmarshal(payload, &rp))
	assert.Equal(t, "mallory", rp.Subject, "an encoding/json relying party reads the authenticated end-user")
	assert.Equal(t, testIssuer, rp.Issuer)
	assert.Equal(t, webClientID, rp.Audience)
	assert.Equal(t, testNonce, rp.Nonce)

	body := e.userInfoBody(resp.AccessToken)
	assert.Equal(t, []string{"sub"}, memberNames(t, body), "%s", body)
	require.NoError(t, json.Unmarshal(body, &rp))
	assert.Equal(t, "mallory", rp.Subject, "UserInfo sub equals the ID Token's (Core §5.3.2)")

	for _, q := range e.claims.recorded() {
		assert.Empty(t, q.Names, "never asked of the source (%s)", q.Target)
	}

	shown := e.lastRequest().Claims
	assert.Empty(t, shown.IDToken, "never shown to the interaction")
	assert.Empty(t, shown.UserInfo, "never shown to the interaction")
}

// TestKnownClaimsAreReleasedUnderTheirExactSpellingOnly: a claim the
// provider knows — the standard claims of Core §5.1, the authorization
// claims of RFC 9068 §2.2.3.1 (roles, groups, entitlements) and
// Config.ClaimsSupported — is released under its exact spelling only, its
// language-tagged variants included; any other spelling is dropped, even
// alone, so that a relying party never reads it as the known claim. The
// genuine claim requested next to a variant keeps its value.
func TestKnownClaimsAreReleasedUnderTheirExactSpellingOnly(t *testing.T) {
	t.Parallel()

	genuine := map[string]any{
		"email": "eve@example.com", "email#fr": "eve@example.fr", "nickname": "Eve",
		"profile": "https://eve.example", "address": map[string]any{"country": "FR"}, "email_verified": true,
		"roles": []any{"user"}, "groups": []any{"users"}, "entitlements": []any{"read"}, "tenant": "eve-co",
	}
	variants := map[string]any{
		"Email": "victim@example.com", "EMAIL": "victim@example.com", "ema\u0131l": "victim@example.com",
		"ema\u0130l": "victim@example.com", "e_mail": "victim@example.com", "e-mail": "victim@example.com",
		"EMAIL#fr": "victim", "Email#fr": "victim", "nic\u212aname": "Victim", "pro\ufb01le": "https://victim.example",
		"addre\u00df": map[string]any{"country": "XX"}, "email_veri\ufb01ed": false,
		"Roles": []any{"admin"}, "role\u017f": []any{"admin"}, "Groups": []any{"admins"}, "group\u017f": []any{"admins"},
		"ENTITLEMENTS": []any{"write"}, "Tenant": "victim-co", "TENANT": "victim-co", "ten_ant": "victim-co",
	}

	e := newEnv(t, withConfig(func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"tenant"} }))
	user := maps.Clone(genuine)
	maps.Copy(user, variants)
	e.claims.setUser("eve", user)
	e.approveAs("eve")

	requested := slices.Sorted(maps.Keys(variants))
	requested = append(requested, slices.Sorted(maps.Keys(genuine))...)

	_, claims := e.idToken(e.flow(with(authorizeQuery(), "claims", claimsParameter(t, requested, nil))).IDToken)

	for name, want := range genuine {
		got, err := json.Marshal(claims[name])
		require.NoError(t, err)

		expected, err := json.Marshal(want)
		require.NoError(t, err)
		assert.JSONEq(t, string(expected), string(got), "%s keeps its genuine value", name)
	}

	for name := range variants {
		assert.NotContains(t, claims, name, "another spelling of a known claim")
	}

	assert.ElementsMatch(t, slices.Sorted(maps.Keys(genuine)), requestNames(e.lastRequest().Claims.IDToken),
		"the interaction is shown the releasable requests only")
}

// TestSeparatorVariantsAreCaseVariants: relying parties that normalize claim
// names to camelCase (lodash camelCase, camelcase-keys, humps) split words
// on punctuation, white space and invisible characters, and lodash's strips
// the diacritics of Latin letters: they read "email.verified", "auth time",
// "email‐verified" (U+2010) or "émail_verified" as emailVerified or
// authTime. Such spellings of known and protocol claims are dropped like
// other case variants.
func TestSeparatorVariantsAreCaseVariants(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.claims.setUser("eve", map[string]any{
		"email_verified": true, "given_name": "Eve",
		"email.verified": false, "email verified": false, "Email~Verified": false,
		"given name": "Victim", "given.name": "Victim", "@given$name!": "Victim",
		"auth time": 1, "at~hash": "x", "s.u.b": "alice",
		"email\u2010verified": false, "email\u00b7verified": false, "email\u00adverified": false,
		"email\u200bverified": false, "email\ufeffverified": false, "auth\u2010time": 1,
		"\u00e9mail_verified": false, "e\u0301mail_verified": false, "s\u0345ub": "alice",
	})
	e.approveAs("eve")

	requested := []string{
		"email_verified", "given_name", "email.verified", "email verified", "Email~Verified",
		"given name", "given.name", "@given$name!", "auth time", "at~hash", "s.u.b",
		"email\u2010verified", "email\u00b7verified", "email\u00adverified", "email\u200bverified",
		"email\ufeffverified", "auth\u2010time", "\u00e9mail_verified", "e\u0301mail_verified", "s\u0345ub",
	}
	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", claimsParameter(t, requested, requested)))

	_, claims := e.idToken(resp.IDToken)
	userInfo := userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken)))

	for target, got := range map[string]map[string]any{"ID Token": claims, "UserInfo": userInfo} {
		assert.Equal(t, true, got["email_verified"], target)
		assert.Equal(t, "Eve", got["given_name"], target)
		assert.Equal(t, "eve", got["sub"], target)

		for _, name := range requested[2:] {
			assert.NotContains(t, got, name, "%s: a separator variant", target)
		}
	}
}

// TestClaimNamesCollidingUnderCaseFoldingAreDropped: claims the provider
// does not know whose names are case variants of one another — a
// language tag spelled twice included — are all dropped: which one a
// relying party would read is unknowable.
func TestClaimNamesCollidingUnderCaseFoldingAreDropped(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.claims.setUser("eve", map[string]any{
		"name": "Eve", "name#fr": "Ève", "name#FR": "Victim",
		"team": "red", "teaM": "blue", "colour": "red", "co_lour": "blue", "unique": "kept",
	})
	e.approveAs("eve")

	request := claimsParameter(t, []string{"name", "team", "teaM", "colour", "co_lour", "unique"},
		[]string{"name", "team", "teaM", "colour", "co_lour", "unique"})
	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", request))

	_, claims := e.idToken(resp.IDToken)
	userInfo := userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken)))

	for target, got := range map[string]map[string]any{"ID Token": claims, "UserInfo": userInfo} {
		assert.Equal(t, "Eve", got["name"], target)
		assert.Equal(t, "kept", got["unique"], target)

		for _, name := range []string{"name#fr", "name#FR", "team", "teaM", "colour", "co_lour"} {
			assert.NotContains(t, got, name, "%s: a case variant of another released claim", target)
		}
	}
}

// TestReleasedClaimNamesAreValidAndUnique (RFC 7519 §4: claim names MUST be
// unique): a language-tagged variant the source names with invalid UTF-8,
// a control character or over 255 bytes is dropped — encoding/json would
// write two invalid names as the same member twice.
func TestReleasedClaimNamesAreValidAndUnique(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.claims.setUser("eve", map[string]any{
		"name": "Eve", "name#\xff": "a", "name#\xfe": "b", "name#\x01": "c", "name#" + strings.Repeat("x", 300): "d",
	})
	e.approveAs("eve")

	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", claimsParameter(t, []string{"name"}, []string{"name"})))

	for target, doc := range map[string][]byte{
		"ID Token": e.idTokenPayload(resp.IDToken), "UserInfo": e.userInfoBody(resp.AccessToken),
	} {
		names := memberNames(t, doc)
		assert.Contains(t, names, "name", target)

		for _, name := range names {
			assert.False(t, strings.HasPrefix(name, "name#"), "%s: %q released", target, name)
		}
	}
}

// TestReleasedClaimValuesAreWellFormed: a claim whose value holds, at any
// depth, a member name with invalid UTF-8 (written as U+FFFD) or a control
// character, two member names of one object that are case variants of each
// other (exact duplicates included), invalid UTF-8, an unpaired surrogate
// escape, or more nesting than strict relying parties accept, is dropped —
// oidc/client refuses a whole token holding one, and encoding/json reads
// such members under names they never had — and so is a number beyond
// float64, for which encoding/json refuses a whole document decoded into an
// any.
func TestReleasedClaimValuesAreWellFormed(t *testing.T) {
	t.Parallel()

	nested := func(depth int) any {
		var v any = "leaf"
		for range depth {
			v = []any{v}
		}

		return v
	}

	values := map[string]any{
		"folded_members":    map[string]any{"country": "FR", "Country": "EVIL"},
		"deep_folded":       map[string]any{"a": []any{map[string]any{"role": "user", "ROLE": "admin"}}},
		"duplicate_members": json.RawMessage(`{"k": 1, "k": 2}`),
		"invalid_names":     map[string]any{"k\xff": 1, "k\xfe": 2},
		"invalid_name":      map[string]any{"k\xff": 1},
		"escaped_invalid":   json.RawMessage(`{"k\ud800": 1}`),
		"invalid_utf8":      json.RawMessage("{\"k\": \"\xff\"}"),
		"lone_surrogate":    json.RawMessage(`"\ud800"`),
		"reversed_pair":     json.RawMessage(`{"k": "\udfff\ud800"}`),
		"lone_low":          json.RawMessage(`["\udc00"]`),
		"escaped_backslash": json.RawMessage(`"\\ud800"`),
		"nul_member":        map[string]any{"country": "FR", "country\x00": "EVIL"},
		"control_member":    map[string]any{"role\x1f": "admin"},
		"too_deep":          nested(32),
		"deepest":           nested(31),
		"separate_objects":  []any{map[string]any{"k": 1}, map[string]any{"K": 2}},
		"well_formed":       map[string]any{"a": map[string]any{"b": []any{1, "two", true}}, "c": nil},
		"surrogate_pair":    json.RawMessage(`"\ud83d\ude00"`),
		"beyond_float64":    json.Number("1e400"),
		"big_integer":       new(big.Int).Exp(big.NewInt(10), big.NewInt(400), nil),
		"deep_big_number":   []any{map[string]any{"n": json.Number("-1e309")}},
		"large_integer":     json.Number("12345678901234567890"),
	}
	dropped := []string{
		"folded_members", "deep_folded", "duplicate_members", "invalid_names", "invalid_name",
		"escaped_invalid", "invalid_utf8", "lone_surrogate", "reversed_pair", "lone_low", "nul_member", "control_member", "too_deep",
		"beyond_float64", "big_integer", "deep_big_number",
	}

	e := newEnv(t)
	e.claims.setUser("eve", values)
	e.approveAs("eve")

	names := slices.Sorted(maps.Keys(values))
	resp := e.flow(with(authorizeQuery(), "scope", "openid", "claims", claimsParameter(t, names, names)))

	_, claims := e.idToken(resp.IDToken)
	userInfo := userInfoClaims(t, e.userinfo(bearerGET(resp.AccessToken)))

	for target, got := range map[string]map[string]any{"ID Token": claims, "UserInfo": userInfo} {
		for _, name := range dropped {
			assert.NotContains(t, got, name, target)
		}

		for _, name := range []string{"deepest", "separate_objects", "well_formed", "surrogate_pair", "escaped_backslash", "large_integer"} {
			assert.Contains(t, got, name, target)
		}
	}
}

// TestTheInteractionIsShownReleasableClaimRequestsOnly: the claim requests
// the provider never releases — protocol claims and their case variants,
// other spellings of known claims — are not shown to the interaction, so
// that consent is asked for what can be released; the end-user a sub
// request designates and an essential acr still apply.
func TestTheInteractionIsShownReleasableClaimRequestsOnly(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.ACR = "urn:a" }, nil)

	request := `{"id_token": {"sub": {"value": "alice"}, "acr": {"essential": true, "values": ["urn:a"]},
		"auth_time": {"essential": true}, "SUB": null, "email": null, "Email": null, "nickname": {"essential": true}},
		"userinfo": {"email": null, "EMAIL": null, "ſub": null}}`
	require.NotEmpty(t, redirect(t, e.authorize(with(authorizeQuery(), "claims", request))).Get("code"))

	req := e.lastRequest()
	assert.Equal(t, oidcprovider.ClaimsRequest{
		IDToken:  []oidcprovider.ClaimRequest{{Name: "email"}, {Name: "nickname", Essential: true}},
		UserInfo: []oidcprovider.ClaimRequest{{Name: "email"}},
	}, req.Claims)
	assert.Equal(t, []string{"alice"}, req.Subjects)
	assert.Equal(t, []string{"urn:a"}, req.EssentialACR)
}

// TestClaimRequestsRecordedEarlierAreFilteredAtUse: a grant records the
// claim requests released when it was issued; the release rules apply to
// them again at every use — here a name the provider learned since then
// (Config.ClaimsSupported), so that its other spelling is no longer
// released at UserInfo nor in a refreshed ID Token.
func TestClaimRequestsRecordedEarlierAreFilteredAtUse(t *testing.T) {
	t.Parallel()

	store := memory.New()
	user := map[string]any{"tenant": "eve-co", "Tenant": "victim-co"}

	before := newEnv(t, withStore(store))
	before.claims.setUser("eve", user)
	before.approveWith(func(req *oidcprovider.Request) *oidcprovider.Decision {
		return &oidcprovider.Decision{
			Authentication: &oidcprovider.AuthenticationEvent{Issuer: req.Issuer, Subject: "eve", AuthTime: before.clock.Now()},
			Claims:         []string{"Tenant"}, OfflineAccess: oidcprovider.OfflineAccessPrompted,
		}
	})

	resp := before.flow(with(offlineQuery(), "scope", "openid offline_access",
		"claims", claimsParameter(t, []string{"Tenant"}, []string{"Tenant"})))
	_, issued := before.idToken(resp.IDToken)
	require.Equal(t, "victim-co", issued["Tenant"], "an unknown name when the grant was issued")

	after := newEnv(t, withStore(store), withConfig(func(c *oidcprovider.Config) { c.ClaimsSupported = []string{"tenant"} }))
	after.claims.setUser("eve", user)

	assert.NotContains(t, userInfoClaims(t, after.userinfo(bearerGET(resp.AccessToken))), "Tenant")

	refreshed := tokens(t, after.refresh(resp.RefreshToken, ""))
	_, claims := after.idToken(refreshed.IDToken)
	assert.NotContains(t, claims, "Tenant")
}

// TestClaimsSupportedNamesTheOnlySpellings: Config.ClaimsSupported accepts
// application claims, standard claims and protocol claims spelled exactly
// — the latter two are published once — and an exact repetition.
func TestClaimsSupportedNamesTheOnlySpellings(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withConfig(func(c *oidcprovider.Config) {
		c.ClaimsSupported = []string{"tenant", "email", "sub", "roles", "tenant", "name#fr"}
	}))

	rec := serve(e.op.DiscoveryHandler(), get("/.well-known/openid-configuration"))

	var doc struct {
		Claims []string `json:"claims_supported"`
	}

	require.NoError(t, json.NewDecoder(io.LimitReader(rec.Body, 1<<20)).Decode(&doc))
	assert.Equal(t, 1, countOf(doc.Claims, "sub"))
	assert.Equal(t, 1, countOf(doc.Claims, "tenant"))
	assert.Contains(t, doc.Claims, "name#fr")
}

// requestNames returns the names of claim requests.
func requestNames(list []oidcprovider.ClaimRequest) []string {
	names := make([]string, 0, len(list))
	for _, c := range list {
		names = append(names, c.Name)
	}

	return names
}

func countOf(list []string, v string) int {
	n := 0

	for _, x := range list {
		if x == v {
			n++
		}
	}

	return n
}
