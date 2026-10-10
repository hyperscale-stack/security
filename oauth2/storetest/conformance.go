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
// Besides single-use codes and atomic rotation, it checks the token-family
// invariants the [oauth2.Storage] godoc states — visibility, gating, atomic
// writes, reuse, idempotence, isolation — sequentially and under races,
// through the public API only. What it cannot observe stays with each
// store's own tests: an injected backend failure (I6, and a reuse whose
// revocation fails), and family state lost by the backend (I8).
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
		Code:        "raw-" + hash,
		CodeHash:    hash,
		ClientID:    testClientID,
		Subject:     testSubject,
		RedirectURI: "https://app.example/cb",
		Scope:       testScope,
		IssuedAt:    now,
		ExpiresAt:   now.Add(10 * time.Minute),
	}
}

func testCodeSaveConsume(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveAuthorizationCode(ctx(), sampleCode("code-1")), "save")

	got, err := s.ConsumeAuthorizationCode(ctx(), "code-1")
	mustNoError(t, err, "consume")
	mustEqual(t, got.ClientID, testClientID, "consumed code lost the client")
	mustEqual(t, got.Subject, testSubject, "consumed code lost the subject")
	mustEqual(t, got.Scope, testScope, "consumed code lost the scope")
}

func testCodeSingleUse(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveAuthorizationCode(ctx(), sampleCode("code-2")), "save")

	_, err := s.ConsumeAuthorizationCode(ctx(), "code-2")
	mustNoError(t, err, "first consume")

	_, err = s.ConsumeAuthorizationCode(ctx(), "code-2")
	mustCode(t, err, oauth2.CodeInvalidGrant, "second consume (single-use)")
}

func testCodeUnknown(t *testing.T, s oauth2.Storage) {
	_, err := s.ConsumeAuthorizationCode(ctx(), "never-saved")
	mustCode(t, err, oauth2.CodeInvalidGrant, "consume an unknown code")
}

// testCodeConcurrentConsume asserts the single-use guarantee under
// concurrency: 50 goroutines race to consume one code, exactly one wins.
func testCodeConcurrentConsume(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveAuthorizationCode(ctx(), sampleCode("code-race")), "save")

	const n = 50

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)

	for range n {
		wg.Go(func() {
			if _, err := s.ConsumeAuthorizationCode(ctx(), "code-race"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	mustEqual(t, wins, 1, "successful consumes")
}

// --- access tokens -------------------------------------------------------

func testAccessLifecycle(t *testing.T, s oauth2.Storage) {
	cc := accessOnly("lifecycle", "") // a client_credentials token
	mustSave(t, s, cc)

	got, err := s.LookupAccessToken(ctx(), cc.Access.TokenHash)
	mustNoError(t, err, "lookup")
	mustEqual(t, got.Subject, testSubject, "lookup lost the subject")
	mustEqual(t, got.Audience, cc.Access.Audience, "lookup lost the audience")

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
}

func testRefreshRotation(t *testing.T, s oauth2.Storage) {
	first := newPair("rot-0", "fam-rot")
	mustSave(t, s, first)

	next := newPair("rot-1", "fam-rot")
	mustRotate(t, s, first, next)

	requireConsumed(t, s, first.Refresh.TokenHash)
	requireUsable(t, s, next)

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
