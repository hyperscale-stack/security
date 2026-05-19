// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package pkce_test

import (
	"testing"

	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Test vector from RFC 7636 Appendix B:
	// verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
	// challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
	rfc7636Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestVerifyS256AcceptsRFC7636Vector(t *testing.T) {
	t.Parallel()

	assert.True(t, pkce.VerifyS256(rfc7636Verifier, rfc7636Challenge))
	assert.True(t, pkce.Verify(pkce.MethodS256, rfc7636Verifier, rfc7636Challenge))
}

func TestVerifyS256RejectsBadVerifier(t *testing.T) {
	t.Parallel()

	assert.False(t, pkce.VerifyS256("wrong-verifier", rfc7636Challenge))
}

func TestVerifyPlainAcceptsExactMatch(t *testing.T) {
	t.Parallel()

	assert.True(t, pkce.Verify(pkce.MethodPlain, "verifier", "verifier"))
	assert.False(t, pkce.Verify(pkce.MethodPlain, "verifier", "other"))
}

func TestVerifyUnknownMethodReturnsFalse(t *testing.T) {
	t.Parallel()

	assert.False(t, pkce.Verify("MD5", "verifier", "challenge"))
}

func TestChallengeMatchesVerification(t *testing.T) {
	t.Parallel()

	verifier := "my-random-verifier-with-enough-entropy-43-chars"
	got, ok := pkce.Challenge(pkce.MethodS256, verifier)
	require.True(t, ok)
	assert.True(t, pkce.VerifyS256(verifier, got),
		"Challenge / Verify round-trip MUST agree")
}

func TestChallengePlainEchoesVerifier(t *testing.T) {
	t.Parallel()

	got, ok := pkce.Challenge(pkce.MethodPlain, "foo")
	require.True(t, ok)
	assert.Equal(t, "foo", got)
}

func TestChallengeUnknownMethodReturnsFalse(t *testing.T) {
	t.Parallel()

	_, ok := pkce.Challenge("MD5", "foo")
	assert.False(t, ok)
}
