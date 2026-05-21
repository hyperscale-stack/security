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

func mustNoError(t *testing.T, err error, msg string) {
	t.Helper()

	if err != nil {
		t.Fatalf("%s: unexpected error: %v", msg, err)
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

	if got.ClientID != testClientID || got.Subject != testSubject || got.Scope != testScope {
		t.Fatalf("consumed code lost fields: %+v", got)
	}
}

func testCodeSingleUse(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveAuthorizationCode(ctx(), sampleCode("code-2")), "save")

	if _, err := s.ConsumeAuthorizationCode(ctx(), "code-2"); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}

	_, err := s.ConsumeAuthorizationCode(ctx(), "code-2")
	if err == nil {
		t.Fatal("second consume MUST fail (single-use)")
	}

	if !errors.Is(err, oauth2.ErrCodeAlreadyUsed) &&
		oauth2.IsCode(err) != oauth2.CodeInvalidGrant {
		t.Fatalf("reuse error should be ErrCodeAlreadyUsed/invalid_grant, got %v", err)
	}
}

func testCodeUnknown(t *testing.T, s oauth2.Storage) {
	if _, err := s.ConsumeAuthorizationCode(ctx(), "never-saved"); err == nil {
		t.Fatal("consuming an unknown code MUST fail")
	}
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
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, err := s.ConsumeAuthorizationCode(ctx(), "code-race"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if wins != 1 {
		t.Fatalf("expected exactly 1 successful consume, got %d", wins)
	}
}

// --- access tokens -------------------------------------------------------

func sampleAccess(hash, family string) *oauth2.AccessToken {
	now := time.Now()

	return &oauth2.AccessToken{
		Token:     "raw-" + hash,
		TokenHash: hash,
		ClientID:  testClientID,
		Subject:   testSubject,
		Scope:     testScope,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		FamilyID:  family,
		Audience:  "api",
	}
}

func testAccessLifecycle(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveAccessToken(ctx(), sampleAccess("at-1", "")), "save")

	got, err := s.LookupAccessToken(ctx(), "at-1")
	mustNoError(t, err, "lookup")

	if got.Subject != testSubject {
		t.Fatalf("lookup lost fields: %+v", got)
	}

	mustNoError(t, s.RevokeAccessToken(ctx(), "at-1"), "revoke")

	if _, err := s.LookupAccessToken(ctx(), "at-1"); err == nil {
		t.Fatal("lookup after revoke MUST fail")
	}
}

func testAccessUnknown(t *testing.T, s oauth2.Storage) {
	if _, err := s.LookupAccessToken(ctx(), "missing"); err == nil {
		t.Fatal("lookup of unknown access token MUST fail")
	}
}

// --- refresh tokens ------------------------------------------------------

func sampleRefresh(hash, family string) *oauth2.RefreshToken {
	now := time.Now()

	return &oauth2.RefreshToken{
		Token:     "raw-" + hash,
		TokenHash: hash,
		ClientID:  testClientID,
		Subject:   testSubject,
		Scope:     testScope,
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
		FamilyID:  family,
	}
}

func testRefreshSaveLookup(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveRefreshToken(ctx(), sampleRefresh("rt-1", "fam-1")), "save")

	got, err := s.LookupRefreshToken(ctx(), "rt-1")
	mustNoError(t, err, "lookup")

	if got.Consumed {
		t.Fatal("freshly saved refresh token must not be consumed")
	}
}

func testRefreshRotation(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveRefreshToken(ctx(), sampleRefresh("rt-old", "fam-2")), "save old")

	next := sampleRefresh("rt-new", "fam-2")
	mustNoError(t, s.RotateRefreshToken(ctx(), "rt-old", next), "rotate")

	old, err := s.LookupRefreshToken(ctx(), "rt-old")
	mustNoError(t, err, "lookup old")

	if !old.Consumed {
		t.Fatal("rotated old token MUST be marked consumed")
	}

	fresh, err := s.LookupRefreshToken(ctx(), "rt-new")
	mustNoError(t, err, "lookup new")

	if fresh.Consumed {
		t.Fatal("new token must not be consumed")
	}
}

func testRefreshReuse(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveRefreshToken(ctx(), sampleRefresh("rt-r1", "fam-3")), "save")

	next1 := sampleRefresh("rt-r2", "fam-3")
	mustNoError(t, s.RotateRefreshToken(ctx(), "rt-r1", next1), "first rotate")

	// Replaying rt-r1 (already consumed) MUST fail and revoke the family.
	next2 := sampleRefresh("rt-r3", "fam-3")

	err := s.RotateRefreshToken(ctx(), "rt-r1", next2)
	if err == nil {
		t.Fatal("rotating a consumed token MUST fail")
	}

	if !errors.Is(err, oauth2.ErrRefreshTokenReused) {
		t.Fatalf("expected ErrRefreshTokenReused, got %v", err)
	}

	// The whole family must now be consumed.
	for _, h := range []string{"rt-r1", "rt-r2"} {
		rt, lookupErr := s.LookupRefreshToken(ctx(), h)
		if lookupErr != nil {
			continue // some backends delete revoked tokens — acceptable
		}

		if !rt.Consumed {
			t.Fatalf("token %s should be consumed after family revocation", h)
		}
	}
}

// testRefreshConcurrentRotation asserts atomic rotation: 30 goroutines race
// to rotate the same token; exactly one succeeds, the rest see reuse.
func testRefreshConcurrentRotation(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveRefreshToken(ctx(), sampleRefresh("rt-c0", "fam-c")), "save")

	const n = 30

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)

	for i := range n {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			next := sampleRefresh(fmt.Sprintf("rt-c%d", i+1), "fam-c")
			if err := s.RotateRefreshToken(ctx(), "rt-c0", next); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if wins != 1 {
		t.Fatalf("expected exactly 1 successful rotation, got %d", wins)
	}
}

func testRevokeFamily(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.SaveRefreshToken(ctx(), sampleRefresh("rt-f1", "fam-x")), "save rt1")
	mustNoError(t, s.SaveRefreshToken(ctx(), sampleRefresh("rt-f2", "fam-x")), "save rt2")
	mustNoError(t, s.SaveAccessToken(ctx(), sampleAccess("at-f1", "fam-x")), "save at")

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-x"), "revoke family")

	// Access tokens of the family must be gone.
	if _, err := s.LookupAccessToken(ctx(), "at-f1"); err == nil {
		t.Fatal("access token of revoked family MUST be gone")
	}

	// Refresh tokens of the family must be consumed (or gone).
	for _, h := range []string{"rt-f1", "rt-f2"} {
		rt, err := s.LookupRefreshToken(ctx(), h)
		if err != nil {
			continue
		}

		if !rt.Consumed {
			t.Fatalf("refresh token %s should be consumed after family revocation", h)
		}
	}
}
