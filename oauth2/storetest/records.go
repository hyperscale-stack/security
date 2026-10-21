// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest

import (
	"reflect"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// The token-record cases of the suite: a lookup returns every field a
// store keeps — the client binding, the subject, the scope, the audience,
// the expiry the grants and endpoints check — exactly as saved, and a store
// keeps what the token-family contract needs for as long as it needs it.

// retentionWait is how long RetainedOverTime lets pass before checking
// again: over a second, so a store keeping a record for a second only — a
// TTL unit mistake, a clamped expiry — is caught. It needs a backend whose
// time moves on its own: miniredis expires keys only when its clock is
// moved, so there the case proves nothing.
const retentionWait = 1500 * time.Millisecond

// atSecond is t as a store keeps it: whole Unix seconds, the zero time kept
// zero — never the Unix epoch.
func atSecond(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}

	return time.Unix(t.Unix(), 0)
}

// storedAccess is at as a store returns it: without the raw token, with
// its timestamps at the second.
func storedAccess(at oauth2.AccessToken) oauth2.AccessToken {
	at.Token = ""
	at.IssuedAt = atSecond(at.IssuedAt)
	at.ExpiresAt = atSecond(at.ExpiresAt)

	return at
}

// storedRefresh is rt as a store returns it: without the raw token, with
// its timestamps at the second.
func storedRefresh(rt oauth2.RefreshToken) oauth2.RefreshToken {
	rt.Token = ""
	rt.IssuedAt = atSecond(rt.IssuedAt)
	rt.ExpiresAt = atSecond(rt.ExpiresAt)
	rt.FamilyIssuedAt = atSecond(rt.FamilyIssuedAt)

	return rt
}

// mustEqualRecord asserts that the records got and want are equal in every
// field — a field added to the model is compared too — and names the
// fields that differ.
func mustEqualRecord[T any](t *testing.T, got, want T, msg string) {
	t.Helper()

	g, w := reflect.ValueOf(got), reflect.ValueOf(want)

	var differ []string

	for i := range g.NumField() {
		if !reflect.DeepEqual(g.Field(i).Interface(), w.Field(i).Interface()) {
			differ = append(differ, g.Type().Field(i).Name)
		}
	}

	if len(differ) > 0 {
		t.Fatalf("%s: fields %v differ: got %+v, want %+v", msg, differ, got, want)
	}
}

// requireRecords asserts that the lookups of pair's tokens return their
// full records — every field a store keeps, timestamps to the second,
// never the raw token — the refresh token consumed as told.
func requireRecords(t *testing.T, s oauth2.Storage, pair *oauth2.TokenPair, consumed bool) {
	t.Helper()

	at, err := s.LookupAccessToken(ctx(), pair.Access.TokenHash)
	mustNoError(t, err, "lookup access token "+pair.Access.TokenHash)
	mustEqual(t, at.Token, "", "the raw access token is never kept")
	mustEqualRecord(t, storedAccess(*at), storedAccess(pair.Access), "record of access token "+pair.Access.TokenHash)

	if pair.Refresh == nil {
		return
	}

	rt, err := s.LookupRefreshToken(ctx(), pair.Refresh.TokenHash)
	mustNoError(t, err, "lookup refresh token "+pair.Refresh.TokenHash)
	mustEqual(t, rt.Token, "", "the raw refresh token is never kept")

	want := storedRefresh(*pair.Refresh)
	want.Consumed = consumed

	mustEqualRecord(t, storedRefresh(*rt), want, "record of refresh token "+pair.Refresh.TokenHash)
}

// distinctPair is newPair with a value of its own in every field a lookup
// returns, so that a store returning one field for another is caught.
func distinctPair(name, family string) *oauth2.TokenPair {
	pair := newPair(name, family)
	now := time.Now()

	pair.Access.ClientID, pair.Refresh.ClientID = "client-"+name, "client-"+name
	pair.Access.Subject, pair.Refresh.Subject = "subject-"+name, "subject-"+name
	pair.Access.Scope, pair.Refresh.Scope = "read", "read write offline_access"
	pair.Access.Audience = "https://api.example/" + name
	pair.Access.IssuedAt, pair.Refresh.IssuedAt = now.Add(-time.Minute), now.Add(-2*time.Minute)
	pair.Access.ExpiresAt, pair.Refresh.ExpiresAt = now.Add(15*time.Minute), now.Add(30*24*time.Hour)

	return pair
}

// testTokenRecordsRoundTrip saves, rotates and looks up token pairs whose
// fields all differ: each lookup returns the full record it was saved with
// — the consumed ancestor too, with Consumed set — and an access token
// outside any family alike.
func testTokenRecordsRoundTrip(t *testing.T, s oauth2.Storage) {
	first := distinctPair("records-0", "fam-records")
	mustSave(t, s, first)
	requireRecords(t, s, first, false)

	next := distinctPair("records-1", "fam-records")
	next.Refresh.FamilyIssuedAt = first.Refresh.FamilyIssuedAt
	mustRotate(t, s, first, next)
	requireRecords(t, s, next, false)
	requireRecords(t, s, first, true)

	cc := distinctPair("records-cc", "")
	cc.Refresh = nil
	mustSave(t, s, cc)
	requireRecords(t, s, cc, false)
}

// testRetainedOverTime checks again, retentionWait later, what a store
// must keep while it lasts — not only on the next call: a consumed code
// is still a replay (RFC 6749 §4.1.2), a rotated refresh token still a
// reuse that revokes its family (RFC 9700 §4.14.2), a family revoked
// before or after issuance still refuses new tokens (I2, I5), and a live
// pair is still found intact.
func testRetainedOverTime(t *testing.T, s oauth2.Storage) {
	code := sampleCode("retained-code")
	mustNoError(t, s.SaveAuthorizationCode(ctx(), code), "save code")

	_, err := s.ConsumeAuthorizationCode(ctx(), code.CodeHash)
	mustNoError(t, err, "consume code")

	first, second := newPair("retained-0", "fam-retained"), newPair("retained-1", "fam-retained")
	mustSave(t, s, first)
	mustRotate(t, s, first, second)

	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-retained-early"), "revoke a family before issuance")

	revoked := newPair("retained-revoked", "fam-retained-revoked")
	mustSave(t, s, revoked)
	mustNoError(t, s.RevokeRefreshFamily(ctx(), "fam-retained-revoked"), "revoke a family")

	live := newPair("retained-live", "fam-retained-live")
	mustSave(t, s, live)

	time.Sleep(retentionWait)

	got, err := s.ConsumeAuthorizationCode(ctx(), code.CodeHash)
	requireReplay(t, got, err, code, "replay the consumed code later")

	// The live pair and the rotated chain are still found intact. The live
	// pair's check doubles that of second, and requireUnusable(revoked)
	// below holds even for a store that lost the family (I8 fails its
	// lookups closed): sanity checks, which the self-test does not pin on
	// their own.
	requireRecords(t, s, live, false)
	requireRecords(t, s, second, false)
	requireRecords(t, s, first, true)

	early := newPair("retained-early", "fam-retained-early")
	mustErrorIs(t, s.SaveTokenPair(ctx(), early), oauth2.ErrTokenFamilyRevoked,
		"issue into the family revoked before issuance, later")
	requireAbsent(t, s, early)

	requireUnusable(t, s, revoked)

	late := newPair("retained-revoked-late", "fam-retained-revoked")
	mustErrorIs(t, s.SaveTokenPair(ctx(), late), oauth2.ErrTokenFamilyRevoked, "issue into the revoked family, later")
	requireAbsent(t, s, late)

	reuse := newPair("retained-2", "fam-retained")
	err = s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, reuse)
	mustErrorIs(t, err, oauth2.ErrRefreshTokenReused, "reuse the rotated refresh token later")
	mustNotErrorIs(t, err, oauth2.ErrTokenFamilyRevocationFailed, "reuse the rotated refresh token later")
	requireAbsent(t, s, reuse)
	requireUnusable(t, s, second)
}
