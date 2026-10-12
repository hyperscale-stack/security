// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// The token-family cases of the suite: they check the invariants the
// [oauth2.Storage] godoc states, through the public API only.

// newPair returns a fresh pair in family: access token "at-<name>" and
// refresh token "rt-<name>", both valid for a while. Every pair of a family
// carries the family's grant context — the issuer and extension data of the
// authorization the family stems from; a pair outside any family (a
// client_credentials token) carries the issuer only.
func newPair(name, family string) *oauth2.TokenPair {
	now := time.Now()
	issuer, data := familyContext(family)

	return &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			Token:         "raw-at-" + name,
			TokenHash:     "at-" + name,
			ClientID:      testClientID,
			Subject:       testSubject,
			Scope:         testScope,
			IssuedAt:      now,
			ExpiresAt:     now.Add(time.Hour),
			FamilyID:      family,
			Audience:      "api",
			Issuer:        issuer,
			ExtensionData: data,
		},
		Refresh: &oauth2.RefreshToken{
			Token:         "raw-rt-" + name,
			TokenHash:     "rt-" + name,
			ClientID:      testClientID,
			Subject:       testSubject,
			Scope:         testScope,
			IssuedAt:      now,
			ExpiresAt:     now.Add(24 * time.Hour),
			FamilyID:      family,
			Issuer:        issuer,
			ExtensionData: data,
			// The family started before this token: a store returning the
			// token's own IssuedAt is caught.
			FamilyIssuedAt: now.Add(-time.Hour),
		},
	}
}

// familyContext is the grant context newPair gives the pairs of family.
func familyContext(family string) (issuer, data string) {
	if family == "" {
		return testIssuer, ""
	}

	return testIssuer, trickyData + family
}

// requireContext asserts that the lookups of pair's tokens return the
// issuer and extension data it was saved with, byte-exact.
func requireContext(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	at, err := s.LookupAccessToken(ctx(), pair.Access.TokenHash)
	mustNoError(t, err, "lookup access token "+pair.Access.TokenHash)
	mustEqual(t, at.Issuer, pair.Access.Issuer, "access token issuer")
	mustEqual(t, at.ExtensionData, pair.Access.ExtensionData, "access token extension data")
	mustEqual(t, at.Token, "", "the raw access token is never kept")

	if pair.Refresh == nil {
		return
	}

	rt, err := s.LookupRefreshToken(ctx(), pair.Refresh.TokenHash)
	mustNoError(t, err, "lookup refresh token "+pair.Refresh.TokenHash)
	mustEqual(t, rt.Issuer, pair.Refresh.Issuer, "refresh token issuer")
	mustEqual(t, rt.ExtensionData, pair.Refresh.ExtensionData, "refresh token extension data")
	mustEqual(t, rt.Token, "", "the raw refresh token is never kept")
	requireFamilyIssuedAt(t, rt, pair.Refresh.FamilyIssuedAt)
}

// requireFamilyIssuedAt asserts that rt carries want as FamilyIssuedAt, to
// the second — the zero time as the zero time, never as the Unix epoch.
func requireFamilyIssuedAt(t *testing.T, rt *oauth2.RefreshToken, want time.Time) {
	t.Helper()

	mustEqual(t, rt.FamilyIssuedAt.IsZero(), want.IsZero(), "refresh token FamilyIssuedAt set")
	mustEqual(t, rt.FamilyIssuedAt.Unix(), want.Unix(), "refresh token FamilyIssuedAt")
}

// accessOnly returns a pair carrying an access token alone: a
// client_credentials token when family is empty, a non-rotating Profile20
// refresh otherwise.
func accessOnly(name, family string) *oauth2.TokenPair {
	pair := newPair(name, family)
	pair.Refresh = nil

	return pair
}

func mustSave(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	mustNoError(t, s.SaveTokenPair(ctx(), pair), "save pair "+pair.Access.TokenHash)
}

func mustRotate(t *testing.T, s oauth2.Storage, from, next *oauth2.TokenPair) {
	t.Helper()

	mustNoError(t, s.RotateRefreshToken(ctx(), from.Refresh.TokenHash, next), "rotate "+from.Refresh.TokenHash)
}

// requireUsable asserts that pair can still be used: its access token is
// found, and its refresh token, if any, is found and not consumed.
func requireUsable(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(ctx(), pair.Access.TokenHash)
	mustNoError(t, err, "lookup access token "+pair.Access.TokenHash)

	if pair.Refresh == nil {
		return
	}

	rt, err := s.LookupRefreshToken(ctx(), pair.Refresh.TokenHash)
	mustNoError(t, err, "lookup refresh token "+pair.Refresh.TokenHash)
	mustEqual(t, rt.Consumed, false, "refresh token "+pair.Refresh.TokenHash+" consumed")
}

// requireUnusable asserts that no token of pair can be used any more: its
// access token lookup fails with invalid_grant, and its refresh token, if
// any, is gone or consumed.
func requireUnusable(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(ctx(), pair.Access.TokenHash)
	mustCode(t, err, oauth2.CodeInvalidGrant, "lookup access token "+pair.Access.TokenHash)

	if pair.Refresh == nil {
		return
	}

	rt, err := s.LookupRefreshToken(ctx(), pair.Refresh.TokenHash)
	if err != nil {
		mustCode(t, err, oauth2.CodeInvalidGrant, "lookup refresh token "+pair.Refresh.TokenHash)

		return
	}

	mustEqual(t, rt.Consumed, true, "refresh token "+pair.Refresh.TokenHash+" consumed")
}

// requireAbsent asserts that nothing of pair was persisted. A refresh
// token persisted into a revoked family would come back consumed, so its
// lookup must fail.
func requireAbsent(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair) {
	t.Helper()

	_, err := s.LookupAccessToken(ctx(), pair.Access.TokenHash)
	mustCode(t, err, oauth2.CodeInvalidGrant, "lookup access token "+pair.Access.TokenHash)

	if pair.Refresh == nil {
		return
	}

	_, err = s.LookupRefreshToken(ctx(), pair.Refresh.TokenHash)
	mustCode(t, err, oauth2.CodeInvalidGrant, "lookup refresh token "+pair.Refresh.TokenHash)
}

// requireConsumed asserts that the refresh token hash is found, consumed.
func requireConsumed(t *testing.T, s oauth2.Storage, hash string) {
	t.Helper()

	rt, err := s.LookupRefreshToken(ctx(), hash)
	mustNoError(t, err, "lookup refresh token "+hash)
	mustEqual(t, rt.Consumed, true, "refresh token "+hash+" consumed")
}

// testFamilyRevokeBeforeIssuance revokes a family no token belongs to yet:
// the revocation is recorded all the same and refuses the first issuance.
func testFamilyRevokeBeforeIssuance(t *testing.T, s oauth2.Storage) {
	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-early"), "revoke an unknown family")

	pair := newPair("early", "fam-early")
	err := s.SaveTokenPair(ctx(), pair)
	mustErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, "issue into a family revoked beforehand")
	mustCode(t, err, oauth2.CodeInvalidGrant, "issue into a family revoked beforehand")
	requireAbsent(t, s, pair)
}

// testFamilyRotateThenRevoke revokes a family after two rotations: every
// ancestor and descendant becomes unusable.
func testFamilyRotateThenRevoke(t *testing.T, s oauth2.Storage) {
	chain := []*oauth2.TokenPair{
		newPair("chain-0", "fam-chain"),
		newPair("chain-1", "fam-chain"),
		newPair("chain-2", "fam-chain"),
	}

	mustSave(t, s, chain[0])
	mustRotate(t, s, chain[0], chain[1])
	mustRotate(t, s, chain[1], chain[2])

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-chain"), "revoke family")

	for _, pair := range chain {
		requireUnusable(t, s, pair)
	}
}

// testFamilyRevokeThenRotate rotates a token of a revoked family: the
// rotation fails and persists nothing.
func testFamilyRevokeThenRotate(t *testing.T, s oauth2.Storage) {
	first := newPair("late-0", "fam-late")
	mustSave(t, s, first)

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-late"), "revoke family")

	next := newPair("late-1", "fam-late")
	err := s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, next)
	mustCode(t, err, oauth2.CodeInvalidGrant, "rotate in a revoked family")
	requireAbsent(t, s, next)
	requireUnusable(t, s, first)
}

// testFamilyRevokeIsIdempotent revokes a family twice: both calls succeed
// and the family stays revoked.
func testFamilyRevokeIsIdempotent(t *testing.T, s oauth2.Storage) {
	pair := newPair("twice", "fam-twice")
	mustSave(t, s, pair)

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-twice"), "first revocation")
	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-twice"), "second revocation")

	requireUnusable(t, s, pair)

	late := newPair("twice-late", "fam-twice")
	mustErrorIs(t, s.SaveTokenPair(ctx(), late), oauth2.ErrTokenFamilyRevoked, "issue into the revoked family")
	requireAbsent(t, s, late)
}

// testFamilyRevokeIsolation revokes one family: another family and a token
// outside any family stay usable.
func testFamilyRevokeIsolation(t *testing.T, s oauth2.Storage) {
	revoked := newPair("iso-a", "fam-iso-a")
	other := newPair("iso-b", "fam-iso-b")
	cc := accessOnly("iso-cc", "")

	mustSave(t, s, revoked)
	mustSave(t, s, other)
	mustSave(t, s, cc)

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-iso-a"), "revoke family")

	requireUnusable(t, s, revoked)
	requireUsable(t, s, other)
	requireUsable(t, s, cc)
}

// testFamilyRevokeRejectsEmptyID refuses to revoke the empty family ID,
// which would otherwise reach every token outside a family.
func testFamilyRevokeRejectsEmptyID(t *testing.T, s oauth2.Storage) {
	cc := accessOnly("empty-id", "")
	mustSave(t, s, cc)

	mustCode(t, s.RevokeRefreshFamily(ctx(), ""), oauth2.CodeInvalidRequest, "revoke the empty family id")
	requireUsable(t, s, cc)
}

// testFamilyIDLengthLimit accepts a family ID of exactly
// oauth2.MaxFamilyIDLength bytes everywhere and refuses a longer one with
// invalid_request everywhere, so no backend can truncate two IDs into one.
func testFamilyIDLengthLimit(t *testing.T, s oauth2.Storage) {
	longest := strings.Repeat("f", oauth2.MaxFamilyIDLength)
	tooLong := longest + "f"

	first := newPair("len-0", longest)
	mustSave(t, s, first)

	next := newPair("len-1", longest)
	mustRotate(t, s, first, next)
	requireUsable(t, s, next)

	over := newPair("len-over", tooLong)
	mustCode(t, s.SaveTokenPair(ctx(), over), oauth2.CodeInvalidRequest, "issue with an over-long family id")
	requireAbsent(t, s, over)

	overNext := newPair("len-over-next", tooLong)
	err := s.RotateRefreshToken(ctx(), next.Refresh.TokenHash, overNext)
	mustCode(t, err, oauth2.CodeInvalidRequest, "rotate into an over-long family id")
	requireAbsent(t, s, overNext)
	requireUsable(t, s, next)

	mustCode(t, s.RevokeRefreshFamily(ctx(), tooLong), oauth2.CodeInvalidRequest, "revoke an over-long family id")
	mustNoError(t, s.RevokeRefreshFamily(ctx(), longest), "revoke the longest family id")
	requireUnusable(t, s, next)
}

// testFamilyFailedRotationPersistsNothing makes rotations fail for every
// reason the contract lists and checks that none of them persisted its
// target or consumed the old token. The targets declare an existing active
// family wherever the call allows it, so a wrongly persisted token would
// be found.
func testFamilyFailedRotationPersistsNothing(t *testing.T, s oauth2.Storage) {
	mustSave(t, s, newPair("fail-active", "fam-fail-active"))

	first := newPair("fail-0", "fam-fail")
	mustSave(t, s, first)

	unknown := newPair("fail-unknown", "fam-fail-active")
	err := s.RotateRefreshToken(ctx(), "never-issued", unknown)
	mustCode(t, err, oauth2.CodeInvalidGrant, "rotate an unknown token")
	requireAbsent(t, s, unknown)

	stray := newPair("fail-stray", "fam-fail-active")
	err = s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, stray)
	mustCode(t, err, oauth2.CodeInvalidRequest, "rotate into another family")
	requireAbsent(t, s, stray)

	bare := accessOnly("fail-bare", "fam-fail")
	err = s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, bare)
	mustCode(t, err, oauth2.CodeInvalidRequest, "rotate without a refresh token")
	requireAbsent(t, s, bare)

	err = s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, nil)
	mustCode(t, err, oauth2.CodeInvalidRequest, "rotate into nothing")

	// None of these consumed the old token: it still rotates.
	requireUsable(t, s, first)

	second := newPair("fail-1", "fam-fail")
	mustRotate(t, s, first, second)

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-fail"), "revoke family")

	third := newPair("fail-2", "fam-fail")
	err = s.RotateRefreshToken(ctx(), second.Refresh.TokenHash, third)
	mustErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, "rotate in a revoked family")
	requireAbsent(t, s, third)
}

// testFamilySaveTokenPairRejectsInvalidPair refuses every pair
// oauth2.TokenPair.Validate rejects, persisting nothing of it.
func testFamilySaveTokenPairRejectsInvalidPair(t *testing.T, s oauth2.Storage) {
	mustCode(t, s.SaveTokenPair(ctx(), nil), oauth2.CodeInvalidRequest, "save a nil pair")

	split := newPair("invalid-split", "fam-invalid-a")
	split.Refresh.FamilyID = "fam-invalid-b"

	orphan := newPair("invalid-orphan", "")

	consumed := newPair("invalid-consumed", "fam-invalid-c")
	consumed.Refresh.Consumed = true

	// A refresh token must carry the grant context of its access token.
	splitIssuer := newPair("invalid-issuer", "fam-invalid-d")
	splitIssuer.Refresh.Issuer = otherIssuer

	splitData := newPair("invalid-data", "fam-invalid-e")
	splitData.Refresh.ExtensionData += "!"

	for _, pair := range []*oauth2.TokenPair{split, orphan, consumed, splitIssuer, splitData} {
		mustCode(t, s.SaveTokenPair(ctx(), pair), oauth2.CodeInvalidRequest, "save invalid pair "+pair.Access.TokenHash)
		requireAbsent(t, s, pair)
	}
}

// testFamilyAccessOnlyIssuanceIsGated covers the non-rotating Profile20
// refresh, which issues an access token alone into the family: accepted
// while the family is active, refused once it is revoked.
func testFamilyAccessOnlyIssuanceIsGated(t *testing.T, s oauth2.Storage) {
	pair := newPair("static", "fam-static")
	mustSave(t, s, pair)

	refreshed := accessOnly("static-1", "fam-static")
	mustSave(t, s, refreshed)
	requireUsable(t, s, refreshed)
	requireUsable(t, s, pair)

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-static"), "revoke family")

	late := accessOnly("static-2", "fam-static")
	mustErrorIs(t, s.SaveTokenPair(ctx(), late), oauth2.ErrTokenFamilyRevoked, "issue into the revoked family")
	requireAbsent(t, s, late)
	requireUnusable(t, s, refreshed)
	requireUnusable(t, s, pair)
}

// testFamilyRevokeRacesRotationChain rotates a chain of tokens while the
// family is revoked concurrently. Whatever the schedule, once the
// revocation returned no pair of the chain is usable, the rotation that
// lost the race persisted nothing, and a further rotation fails.
func testFamilyRevokeRacesRotationChain(t *testing.T, s oauth2.Storage) {
	const n = 20

	chain := make([]*oauth2.TokenPair, n+1)
	for i := range chain {
		chain[i] = newPair(fmt.Sprintf("racing-%d", i), "fam-racing")
	}

	mustSave(t, s, chain[0])

	var (
		wg        sync.WaitGroup
		rotated   int
		rotateErr error
		revokeErr error
	)

	start := make(chan struct{})

	wg.Go(func() {
		<-start

		for rotated < n {
			rotateErr = s.RotateRefreshToken(ctx(), chain[rotated].Refresh.TokenHash, chain[rotated+1])
			if rotateErr != nil {
				return
			}

			rotated++
		}
	})
	wg.Go(func() {
		<-start

		revokeErr = s.RevokeRefreshFamily(ctx(), "fam-racing")
	})

	close(start)
	wg.Wait()

	mustNoError(t, revokeErr, "revoke family")

	if rotated < n {
		mustCode(t, rotateErr, oauth2.CodeInvalidGrant, "rotation that lost the race")
	}

	for _, pair := range chain[:rotated+1] {
		requireUnusable(t, s, pair)
	}

	for _, pair := range chain[rotated+1:] {
		requireAbsent(t, s, pair)
	}

	extra := newPair("racing-extra", "fam-racing")
	err := s.RotateRefreshToken(ctx(), chain[rotated].Refresh.TokenHash, extra)
	mustCode(t, err, oauth2.CodeInvalidGrant, "rotate after the revocation")
	requireAbsent(t, s, extra)
}

// testFamilyRevokeRacesIssuance issues pairs into a family while it is
// revoked concurrently: once the revocation returned, an issued pair is
// unusable, and a refused one reports ErrTokenFamilyRevoked and persisted
// nothing.
func testFamilyRevokeRacesIssuance(t *testing.T, s oauth2.Storage) {
	const n = 20

	pairs := make([]*oauth2.TokenPair, n)
	errs := make([]error, n)

	for i := range pairs {
		pairs[i] = newPair(fmt.Sprintf("issuing-%d", i), "fam-issuing")
	}

	var (
		wg        sync.WaitGroup
		revokeErr error
	)

	start := make(chan struct{})

	for i := range pairs {
		wg.Go(func() {
			<-start

			errs[i] = s.SaveTokenPair(ctx(), pairs[i])
		})
	}

	wg.Go(func() {
		<-start

		revokeErr = s.RevokeRefreshFamily(ctx(), "fam-issuing")
	})

	close(start)
	wg.Wait()

	mustNoError(t, revokeErr, "revoke family")

	for i, pair := range pairs {
		if errs[i] == nil {
			requireUnusable(t, s, pair)

			continue
		}

		mustErrorIs(t, errs[i], oauth2.ErrTokenFamilyRevoked, "issuance that lost the race")
		requireAbsent(t, s, pair)
	}
}
