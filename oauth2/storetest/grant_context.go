// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package storetest

import (
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
)

// The grant-context cases of the suite: every store keeps the Issuer and
// the ExtensionData of codes and tokens byte-exact, and a rotation never
// changes them.

// longestData is ExtensionData of exactly oauth2.MaxExtensionDataLength
// bytes whose last rune takes four of them, so a store truncating by bytes
// or by characters, or mangling multi-byte runes, is caught.
func longestData() string {
	const key = "🔑"

	return strings.Repeat("x", oauth2.MaxExtensionDataLength-len(key)) + key
}

// testGrantContextRoundTrip follows one grant: its code, then its tokens
// through two rotations. Every record — the consumed ancestors included,
// which the Redis scripts re-encode — returns its context unchanged, and an
// empty context stays empty.
func testGrantContextRoundTrip(t *testing.T, s oauth2.Storage) {
	code := sampleCode("ctx-code")
	mustNoError(t, s.SaveAuthorizationCode(ctx(), code), "save code")

	got, err := s.ConsumeAuthorizationCode(ctx(), "ctx-code")
	mustNoError(t, err, "consume")
	requireRecord(t, got, code, "consumed code")

	got, err = s.ConsumeAuthorizationCode(ctx(), "ctx-code")
	requireReplay(t, got, err, code, "replayed code")

	chain := []*oauth2.TokenPair{
		newPair("ctx-0", "fam-ctx"),
		newPair("ctx-1", "fam-ctx"),
		newPair("ctx-2", "fam-ctx"),
	}

	mustSave(t, s, chain[0])
	mustRotate(t, s, chain[0], chain[1])
	mustRotate(t, s, chain[1], chain[2])

	for _, pair := range chain {
		requireContext(t, s, pair)
	}

	bare := sampleCode("ctx-bare")
	bare.Issuer, bare.ExtensionData = "", ""
	mustNoError(t, s.SaveAuthorizationCode(ctx(), bare), "save a code without context")

	got, err = s.ConsumeAuthorizationCode(ctx(), "ctx-bare")
	mustNoError(t, err, "consume a code without context")
	requireRecord(t, got, bare, "code without context")

	empty := newPair("ctx-empty", "fam-ctx-empty")
	empty.Access.Issuer, empty.Access.ExtensionData = "", ""
	empty.Refresh.Issuer, empty.Refresh.ExtensionData = "", ""
	mustSave(t, s, empty)
	requireContext(t, s, empty)
}

// testGrantContextLongestData stores the longest ExtensionData the server
// records on a code and on a rotated family.
func testGrantContextLongestData(t *testing.T, s oauth2.Storage) {
	data := longestData()

	code := sampleCode("ctx-long")
	code.ExtensionData = data
	mustNoError(t, s.SaveAuthorizationCode(ctx(), code), "save code")

	got, err := s.ConsumeAuthorizationCode(ctx(), "ctx-long")
	mustNoError(t, err, "consume")
	requireRecord(t, got, code, "consumed code")

	got, err = s.ConsumeAuthorizationCode(ctx(), "ctx-long")
	requireReplay(t, got, err, code, "replayed code")

	first, next := newPair("long-0", "fam-long"), newPair("long-1", "fam-long")
	for _, pair := range []*oauth2.TokenPair{first, next} {
		pair.Access.ExtensionData, pair.Refresh.ExtensionData = data, data
	}

	mustSave(t, s, first)
	mustRotate(t, s, first, next)
	requireContext(t, s, first)
	requireContext(t, s, next)
}

// testRotationKeepsGrantContext rotates a token into a pair carrying
// another issuer or other extension data: the store refuses it with
// invalid_request, persists nothing, and leaves the presented token
// usable — a rotation can neither re-bind a grant to another realm nor
// rewrite the authentication event it rests on.
func testRotationKeepsGrantContext(t *testing.T, s oauth2.Storage) {
	first := newPair("keep-0", "fam-keep")
	mustSave(t, s, first)

	rebound := newPair("keep-issuer", "fam-keep")
	rebound.Access.Issuer, rebound.Refresh.Issuer = otherIssuer, otherIssuer

	const rewrittenData = "rewritten"

	rewritten := newPair("keep-data", "fam-keep")
	rewritten.Access.ExtensionData, rewritten.Refresh.ExtensionData = rewrittenData, rewrittenData

	for _, next := range []*oauth2.TokenPair{rebound, rewritten} {
		err := s.RotateRefreshToken(ctx(), first.Refresh.TokenHash, next)
		mustCode(t, err, oauth2.CodeInvalidRequest, "rotate into another grant context "+next.Access.TokenHash)
		requireAbsent(t, s, next)
	}

	requireUsable(t, s, first)

	same := newPair("keep-1", "fam-keep")
	mustRotate(t, s, first, same)
	requireContext(t, s, same)
}
