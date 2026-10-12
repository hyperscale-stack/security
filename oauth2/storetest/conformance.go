// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package storetest provides a black-box conformance suite that every
// [oauth2.Storage] implementation MUST pass. The in-memory, SQL and Redis
// stores all run RunConformance against a fresh instance so behavioral
// drift between backends is caught at test time.
//
// The package imports "testing" deliberately: it is a test helper in the
// spirit of net/http/httptest and testing/fstest, meant to be called from
// _test.go files of the store implementations.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// Factory builds a fresh, empty [oauth2.Storage]. RunConformance calls it
// once per sub-test so cases never share state.
type Factory func() oauth2.Storage

// RunConformance executes the full storage contract against the
// implementation produced by newStore. Call it from a Test function:
//
//	func TestMyStoreConformance(t *testing.T) {
//	    storetest.RunConformance(t, func() oauth2.Storage { return New(...) })
//	}
//
// Besides single-use codes — retained once consumed, so a replay is told
// from an unknown code — and atomic rotation, it checks the token-family
// invariants the [oauth2.Storage] godoc states — visibility, gating, atomic
// writes, reuse, idempotence, isolation — sequentially and under races,
// through the public API only, and drives the real authorization_code
// grant to check that a replayed code revokes the tokens it issued. What
// it cannot observe stays with each store's own tests: an injected backend
// failure (I6, and a reuse whose revocation fails), and family state lost
// by the backend (I8).
func RunConformance(t *testing.T, newStore Factory) {
	t.Helper()

	cases := []struct {
		name string
		run  func(*testing.T, oauth2.Storage)
	}{
		{"AuthorizationCodeSaveConsume", testCodeSaveConsume},
		{"AuthorizationCodeSingleUse", testCodeSingleUse},
		{"AuthorizationCodeUnknown", testCodeUnknown},
		{"AuthorizationCodeConcurrentConsume", testCodeConcurrentConsume},
		{"AuthorizationCodeRedirectURIOmitted", testCodeRedirectURIOmitted},
		{"AuthorizationCodeReplayRevokesIssuedTokens", testCodeReplayRevokesIssuedTokens},
		{"AccessTokenSaveLookupRevoke", testAccessLifecycle},
		{"AccessTokenLookupUnknown", testAccessUnknown},
		{"RefreshTokenSaveLookup", testRefreshSaveLookup},
		{"RefreshTokenRotation", testRefreshRotation},
		{"RefreshTokenReuseRevokesFamily", testRefreshReuse},
		{"RefreshTokenConcurrentRotation", testRefreshConcurrentRotation},
		{"RevokeRefreshFamily", testRevokeFamily},
		{"FamilyRevokeBeforeIssuance", testFamilyRevokeBeforeIssuance},
		{"FamilyRotateThenRevoke", testFamilyRotateThenRevoke},
		{"FamilyRevokeThenRotate", testFamilyRevokeThenRotate},
		{"FamilyRevokeIsIdempotent", testFamilyRevokeIsIdempotent},
		{"FamilyRevokeIsolation", testFamilyRevokeIsolation},
		{"FamilyRevokeRejectsEmptyID", testFamilyRevokeRejectsEmptyID},
		{"FamilyIDLengthLimit", testFamilyIDLengthLimit},
		{"FamilyFailedRotationPersistsNothing", testFamilyFailedRotationPersistsNothing},
		{"FamilySaveTokenPairRejectsInvalidPair", testFamilySaveTokenPairRejectsInvalidPair},
		{"FamilyAccessOnlyIssuanceIsGated", testFamilyAccessOnlyIssuanceIsGated},
		{"FamilyRevokeRacesRotationChain", testFamilyRevokeRacesRotationChain},
		{"FamilyRevokeRacesIssuance", testFamilyRevokeRacesIssuance},
		{"GrantContextRoundTrip", testGrantContextRoundTrip},
		{"GrantContextLongestData", testGrantContextLongestData},
		{"RotationKeepsGrantContext", testRotationKeepsGrantContext},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.run(t, newStore())
		})
	}
}

// testSubject is the fixed resource-owner subject used across the suite.
const testSubject = "alice"

// testClientID is the fixed client identifier used across the suite.
const testClientID = "client-1"

// testScope is the fixed scope used across the suite.
const testScope = "read"

// testRedirectURI is the fixed redirect URI of the suite's codes.
const testRedirectURI = "https://app.example/cb"

// testIssuer is the issuer the suite's codes and tokens are bound to, and
// otherIssuer the one a rotation must not re-bind them to.
const (
	testIssuer  = "https://issuer.example/realm-a"
	otherIssuer = "https://issuer.example/realm-b"
)

// trickyData is extension data that stresses every store's encoding: text
// Redis' cjson re-encodes on the replay and rotation paths (\/, U+2028,
// U+2029, an empty JSON array), characters Go escapes for HTML, control
// characters, DEL, multi-byte runes, quotes and backslashes, JSON-looking
// text and surrounding spaces. Every store must return it byte-exact.
const trickyData = " {\"auth_time\":1700000000,\"amr\":[\"pwd\",\"otp\"],\"a\":[]} \\/ <>& \"q\" é 🔑    \x7f \x01\x1f\t\n\r "

func ctx() context.Context { return context.Background() }

// The assertion helpers below hold every t.Fatalf of the suite, so the
// cases themselves stay free of branches a passing store never takes.

func mustNoError(t *testing.T, err error, msg string) {
	t.Helper()

	if err != nil {
		t.Fatalf("%s: unexpected error: %v", msg, err)
	}
}

// mustErrorIs asserts that err matches target.
func mustErrorIs(t *testing.T, err, target error, msg string) {
	t.Helper()

	if !errors.Is(err, target) {
		t.Fatalf("%s: got error %v, want one matching %v", msg, err, target)
	}
}

// mustNotErrorIs asserts that err does not match target.
func mustNotErrorIs(t *testing.T, err, target error, msg string) {
	t.Helper()

	if errors.Is(err, target) {
		t.Fatalf("%s: got error %v, must not match %v", msg, err, target)
	}
}

// mustCode asserts that err is an error carrying the OAuth2 code.
func mustCode(t *testing.T, err error, code, msg string) {
	t.Helper()

	if got := oauth2.IsCode(err); err == nil || got != code {
		t.Fatalf("%s: got error %v (code %q), want an error with code %s", msg, err, got, code)
	}
}

// mustEqual asserts that got equals want.
func mustEqual[T comparable](t *testing.T, got, want T, msg string) {
	t.Helper()

	if got != want {
		t.Fatalf("%s: got %v, want %v", msg, got, want)
	}
}

// --- authorization codes -------------------------------------------------

func sampleCode(hash string) *oauth2.AuthorizationCode {
	now := time.Now()

	return &oauth2.AuthorizationCode{
		Code:                "raw-" + hash,
		CodeHash:            hash,
		ClientID:            testClientID,
		Subject:             testSubject,
		RedirectURI:         testRedirectURI,
		RedirectURIOmitted:  true,
		Scope:               testScope,
		CodeChallenge:       "challenge-" + hash,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-" + hash,
		IssuedAt:            now,
		ExpiresAt:           now.Add(10 * time.Minute),
		Issuer:              testIssuer,
		ExtensionData:       trickyData + hash,
	}
}

// storedCode is code as a store returns it: without the raw value, with
// its timestamps at the second.
func storedCode(code oauth2.AuthorizationCode) oauth2.AuthorizationCode {
	code.Code = ""
	code.IssuedAt = time.Unix(code.IssuedAt.Unix(), 0)
	code.ExpiresAt = time.Unix(code.ExpiresAt.Unix(), 0)

	return code
}

// requireRecord asserts that got is the record of saved: every field a
// store keeps, and never the raw code.
func requireRecord(t *testing.T, got, saved *oauth2.AuthorizationCode, msg string) {
	t.Helper()

	mustEqual(t, got != nil, true, msg+": a record")
	mustEqual(t, got.Code, "", msg+": the raw code is never kept")
	mustEqual(t, storedCode(*got), storedCode(*saved), msg)
}

// requireReplay asserts that got and err report a replay of saved: no
// code to issue tokens from, and an invalid_grant matching
// oauth2.ErrCodeAlreadyUsed that carries the retained record.
func requireReplay(t *testing.T, got *oauth2.AuthorizationCode, err error, saved *oauth2.AuthorizationCode, msg string) {
	t.Helper()

	mustEqual(t, got == nil, true, msg+": no code returned")
	mustErrorIs(t, err, oauth2.ErrCodeAlreadyUsed, msg)
	mustCode(t, err, oauth2.CodeInvalidGrant, msg)

	var replay *oauth2.CodeReplayError

	mustEqual(t, errors.As(err, &replay), true, msg+": a CodeReplayError")
	requireRecord(t, replay.Record, saved, msg+": the retained record")
}

func testCodeSaveConsume(t *testing.T, s oauth2.Storage) {
	mustCode(t, s.SaveAuthorizationCode(ctx(), &oauth2.AuthorizationCode{}), oauth2.CodeInvalidRequest, "save a code without hash")

	saved := sampleCode("code-1")
	mustNoError(t, s.SaveAuthorizationCode(ctx(), saved), "save")

	got, err := s.ConsumeAuthorizationCode(ctx(), "code-1")
	mustNoError(t, err, "consume")
	requireRecord(t, got, saved, "consumed code")
}

// testCodeSingleUse replays a consumed code: every replay is refused with
// a CodeReplayError carrying the retained record, so the server can tell
// it from an unknown code and revoke what the first exchange issued.
func testCodeSingleUse(t *testing.T, s oauth2.Storage) {
	saved := sampleCode("code-2")
	mustNoError(t, s.SaveAuthorizationCode(ctx(), saved), "save")

	_, err := s.ConsumeAuthorizationCode(ctx(), "code-2")
	mustNoError(t, err, "first consume")

	for _, attempt := range []string{"second consume", "third consume"} {
		got, err := s.ConsumeAuthorizationCode(ctx(), "code-2")
		requireReplay(t, got, err, saved, attempt)
	}
}

// testCodeUnknown consumes a code never saved: an invalid_grant matching
// oauth2.ErrCodeAlreadyUsed, but no replay — there is nothing to revoke.
func testCodeUnknown(t *testing.T, s oauth2.Storage) {
	got, err := s.ConsumeAuthorizationCode(ctx(), "never-saved")
	mustEqual(t, got == nil, true, "consume an unknown code: no code returned")
	mustErrorIs(t, err, oauth2.ErrCodeAlreadyUsed, "consume an unknown code")
	mustCode(t, err, oauth2.CodeInvalidGrant, "consume an unknown code")

	var replay *oauth2.CodeReplayError

	mustEqual(t, errors.As(err, &replay), false, "an unknown code is no replay")
}

// testCodeConcurrentConsume asserts the single-use guarantee under
// concurrency: 50 goroutines race to consume one code, exactly one wins,
// and every other one sees a replay of the code.
func testCodeConcurrentConsume(t *testing.T, s oauth2.Storage) {
	saved := sampleCode("code-race")
	mustNoError(t, s.SaveAuthorizationCode(ctx(), saved), "save")

	const n = 50

	codes := make([]*oauth2.AuthorizationCode, n)
	errs := make([]error, n)

	var wg sync.WaitGroup

	start := make(chan struct{})

	for i := range n {
		wg.Go(func() {
			<-start

			codes[i], errs[i] = s.ConsumeAuthorizationCode(ctx(), "code-race")
		})
	}

	close(start)
	wg.Wait()

	wins := 0

	for i, err := range errs {
		if err == nil {
			wins++

			requireRecord(t, codes[i], saved, "winning consume")

			continue
		}

		requireReplay(t, codes[i], err, saved, "losing consume")
	}

	mustEqual(t, wins, 1, "successful consumes")
}

// testCodeRedirectURIOmitted round-trips both values of RedirectURIOmitted,
// on consumption and on the replay record — which the Redis store
// re-encodes: a store dropping the flag relaxes nothing (false requires
// redirect_uri), but one always reading true would let a token request omit
// a redirect_uri the authorization request included (RFC 6749 §4.1.3).
func testCodeRedirectURIOmitted(t *testing.T, s oauth2.Storage) {
	for _, omitted := range []bool{false, true} {
		saved := sampleCode(fmt.Sprintf("code-redirect-omitted-%t", omitted))
		saved.RedirectURIOmitted = omitted
		mustNoError(t, s.SaveAuthorizationCode(ctx(), saved), "save")

		got, err := s.ConsumeAuthorizationCode(ctx(), saved.CodeHash)
		mustNoError(t, err, "consume")
		requireRecord(t, got, saved, "consumed code")
		mustEqual(t, got.RedirectURIOmitted, omitted, "RedirectURIOmitted")

		got, err = s.ConsumeAuthorizationCode(ctx(), saved.CodeHash)
		requireReplay(t, got, err, saved, "replayed code")
	}
}

// --- access tokens -------------------------------------------------------

func testAccessLifecycle(t *testing.T, s oauth2.Storage) {
	cc := accessOnly("lifecycle", "") // a client_credentials token
	mustSave(t, s, cc)

	got, err := s.LookupAccessToken(ctx(), cc.Access.TokenHash)
	mustNoError(t, err, "lookup")
	mustEqual(t, got.Subject, testSubject, "lookup lost the subject")
	mustEqual(t, got.Audience, cc.Access.Audience, "lookup lost the audience")
	requireContext(t, s, cc)

	mustNoError(t, s.RevokeAccessToken(ctx(), cc.Access.TokenHash), "revoke")
	requireUnusable(t, s, cc)
}

func testAccessUnknown(t *testing.T, s oauth2.Storage) {
	_, err := s.LookupAccessToken(ctx(), "missing")
	mustCode(t, err, oauth2.CodeInvalidGrant, "lookup of an unknown access token")
}

// --- refresh tokens ------------------------------------------------------

func testRefreshSaveLookup(t *testing.T, s oauth2.Storage) {
	pair := newPair("save", "fam-save")
	mustSave(t, s, pair)

	requireUsable(t, s, pair)

	got, err := s.LookupRefreshToken(ctx(), pair.Refresh.TokenHash)
	mustNoError(t, err, "lookup refresh token")
	mustEqual(t, got.FamilyID, "fam-save", "lookup lost the family")
	mustEqual(t, got.Scope, testScope, "lookup lost the scope")
	requireContext(t, s, pair)
}

func testRefreshRotation(t *testing.T, s oauth2.Storage) {
	first := newPair("rot-0", "fam-rot")
	mustSave(t, s, first)

	next := newPair("rot-1", "fam-rot")
	mustRotate(t, s, first, next)

	requireConsumed(t, s, first.Refresh.TokenHash)
	requireUsable(t, s, next)
	requireContext(t, s, next)
	// The consumed token keeps its own record: the Redis rotation script
	// re-encodes it with cjson, the context must survive that byte-exact.
	requireContext(t, s, first)

	// Rotation consumes the presented refresh token only: the access token
	// issued alongside it lives on until it expires.
	_, err := s.LookupAccessToken(ctx(), first.Access.TokenHash)
	mustNoError(t, err, "lookup the previous access token")
}

// testRefreshReuse replays a rotated token: the store reports reuse — with
// the family revoked, so not as a revocation failure — and nothing of the
// family stays usable or can be issued any more.
func testRefreshReuse(t *testing.T, s oauth2.Storage) {
	first := newPair("reuse-0", "fam-reuse")
	mustSave(t, s, first)

	second := newPair("reuse-1", "fam-reuse")
	mustRotate(t, s, first, second)

	replay := newPair("reuse-2", "fam-reuse")
	err := s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, replay)
	mustErrorIs(t, err, oauth2.ErrRefreshTokenReused, "replay a rotated token")
	mustCode(t, err, oauth2.CodeInvalidGrant, "replay a rotated token")
	mustNotErrorIs(t, err, oauth2.ErrTokenFamilyRevocationFailed, "replay a rotated token")

	requireUnusable(t, s, first)
	requireUnusable(t, s, second)
	requireAbsent(t, s, replay)

	// Once the family is revoked, the revoked state decides before the
	// consumed one: the next replay is refused as a revoked family.
	again := newPair("reuse-again", "fam-reuse")
	err = s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, again)
	mustErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, "replay into the revoked family")
	requireAbsent(t, s, again)

	late := newPair("reuse-3", "fam-reuse")
	mustErrorIs(t, s.SaveTokenPair(ctx(), late), oauth2.ErrTokenFamilyRevoked, "issue into the revoked family")
	requireAbsent(t, s, late)
}

// testRefreshConcurrentRotation asserts atomic rotation: 30 goroutines race
// to rotate the same token and exactly one succeeds. Every loser runs after
// the winner, so the first of them detects the reuse and revokes the
// family: the winner's tokens end up unusable and no loser persists
// anything.
func testRefreshConcurrentRotation(t *testing.T, s oauth2.Storage) {
	first := newPair("race-0", "fam-race")
	mustSave(t, s, first)

	const n = 30

	nexts := make([]*oauth2.TokenPair, n)
	errs := make([]error, n)

	for i := range nexts {
		nexts[i] = newPair(fmt.Sprintf("race-%d", i+1), "fam-race")
	}

	var wg sync.WaitGroup

	start := make(chan struct{})

	for i := range nexts {
		wg.Go(func() {
			<-start

			errs[i] = s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, nexts[i])
		})
	}

	close(start)
	wg.Wait()

	wins := 0

	for i, err := range errs {
		if err == nil {
			wins++

			requireUnusable(t, s, nexts[i])

			continue
		}

		mustCode(t, err, oauth2.CodeInvalidGrant, "losing rotation")
		requireAbsent(t, s, nexts[i])
	}

	mustEqual(t, wins, 1, "successful rotations")
}

func testRevokeFamily(t *testing.T, s oauth2.Storage) {
	pair := newPair("revoke", "fam-revoke")
	mustSave(t, s, pair)

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-revoke"), "revoke family")

	requireUnusable(t, s, pair)
}
