// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package pkce_test

import (
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unreservedAlphabet is the RFC 3986 §2.3 unreserved set a code verifier is
// drawn from (RFC 7636 §4.1).
const unreservedAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// base64URLAlphabet is the RFC 4648 §5 alphabet, in index order.
const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// as returns n "a" characters.
func as(n int) string { return strings.Repeat("a", n) }

// mustChallenge derives the method challenge of verifier.
func mustChallenge(t *testing.T, method pkce.Method, verifier string) string {
	t.Helper()

	c, ok := pkce.Challenge(method, verifier)
	require.True(t, ok)

	return c
}

func TestValidVerifier(t *testing.T) {
	t.Parallel()

	v := rfc7636Verifier

	cases := []struct {
		name     string
		verifier string
		want     bool
	}{
		{"RFC 7636 Appendix B vector (43 chars, the minimum)", v, true},
		{"128 chars (the maximum)", as(128), true},
		{"the whole unreserved alphabet", unreservedAlphabet, true},
		{"empty", "", false},
		{"one character (issue #79)", "x", false},
		{"42 chars", as(42), false},
		{"129 chars", as(129), false},
		{"43 bytes but 42 runes", as(41) + "é", false},
		{"43 runes", as(42) + "é", false},
		{"43 bytes with a 3-byte rune", as(40) + "～", false},
		{"leading space", " " + v, false},
		{"trailing LF", v + "\n", false},
		{"embedded tab", v[:20] + "\t" + v[20:], false},
		{"trailing CRLF", v + "\r\n", false},
		{"embedded space", v[:20] + " " + v[20:], false},
		{"standard base64 plus", as(42) + "+", false},
		{"standard base64 slash", as(42) + "/", false},
		{"base64 padding", as(42) + "=", false},
		{"percent-encoded tilde", as(40) + "%7E", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, pkce.ValidVerifier(tc.verifier))
		})
	}
}

// TestValidVerifierRejectsEveryNonUnreservedByte checks each of the 256
// byte values in an otherwise valid 43-byte verifier: whitespace, control
// characters, every forbidden ASCII character and every non-ASCII byte are
// refused, the 66 unreserved characters are accepted.
func TestValidVerifierRejectsEveryNonUnreservedByte(t *testing.T) {
	t.Parallel()

	require.Len(t, unreservedAlphabet, 66)

	accepted := 0

	for b := range 256 {
		c := byte(b)
		got := pkce.ValidVerifier(as(42) + string([]byte{c}))

		assert.Equal(t, strings.IndexByte(unreservedAlphabet, c) >= 0, got, "byte 0x%02X", c)

		if got {
			accepted++
		}
	}

	assert.Equal(t, len(unreservedAlphabet), accepted)
}

func TestValidChallenge(t *testing.T) {
	t.Parallel()

	c := rfc7636Challenge

	cases := []struct {
		name      string
		method    pkce.Method
		challenge string
		want      bool
	}{
		{"S256: RFC 7636 Appendix B challenge", pkce.MethodS256, c, true},
		{"S256: challenge of a one-character verifier", pkce.MethodS256, mustChallenge(t, pkce.MethodS256, "x"), true},
		{"S256: 42 chars", pkce.MethodS256, c[:42], false},
		{"S256: 44 chars", pkce.MethodS256, c + "A", false},
		{"S256: padded", pkce.MethodS256, c + "=", false},
		{"S256: standard alphabet plus", pkce.MethodS256, strings.Replace(c, "-", "+", 1), false},
		{"S256: standard alphabet slash", pkce.MethodS256, c[:10] + "/" + c[11:], false},
		{"S256: LF in place of a character", pkce.MethodS256, c[:20] + "\n" + c[21:], false},
		{"S256: trailing CRLF in place of a character", pkce.MethodS256, c[:41] + "\r\n", false},
		{"S256: trailing LF", pkce.MethodS256, c + "\n", false},
		{"S256: tilde", pkce.MethodS256, c[:10] + "~" + c[11:], false},
		{"S256: dot", pkce.MethodS256, c[:10] + "." + c[11:], false},
		{"S256: non-canonical trailing bits", pkce.MethodS256, c[:42] + "N", false},
		{"S256: non-ASCII", pkce.MethodS256, c[:41] + "é", false},
		{"S256: 64 chars", pkce.MethodS256, as(64), false},
		{"S256: empty", pkce.MethodS256, "", false},
		{"plain: RFC 7636 Appendix B verifier", pkce.MethodPlain, rfc7636Verifier, true},
		{"plain: 43 chars", pkce.MethodPlain, as(43), true},
		{"plain: 128 chars", pkce.MethodPlain, as(128), true},
		{"plain: the whole unreserved alphabet", pkce.MethodPlain, unreservedAlphabet, true},
		{"plain: an S256-shaped string", pkce.MethodPlain, c, true},
		{"plain: 42 chars", pkce.MethodPlain, as(42), false},
		{"plain: 129 chars", pkce.MethodPlain, as(129), false},
		{"plain: plus", pkce.MethodPlain, as(42) + "+", false},
		{"plain: trailing space", pkce.MethodPlain, rfc7636Verifier + " ", false},
		{"plain: non-ASCII", pkce.MethodPlain, as(41) + "é", false},
		{"empty method", "", rfc7636Verifier, false},
		{"unknown method", "S512", c, false},
		{"methods are case-sensitive", "s256", c, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, pkce.ValidChallenge(tc.method, tc.challenge))
		})
	}
}

// TestValidChallengeS256RequiresCanonicalTrailingBits varies the last of the
// 43 characters: it carries 4 bits of the digest and 2 zero bits, so only
// the 16 characters whose index is a multiple of 4 are canonical. The others
// decode to the same digest but are not what BASE64URL-ENCODE produces.
func TestValidChallengeS256RequiresCanonicalTrailingBits(t *testing.T) {
	t.Parallel()

	var accepted []byte

	for i := range len(base64URLAlphabet) {
		ch := base64URLAlphabet[i]
		got := pkce.ValidChallenge(pkce.MethodS256, rfc7636Challenge[:42]+string(ch))

		assert.Equal(t, i%4 == 0, got, "final character %q", ch)

		if got {
			accepted = append(accepted, ch)
		}
	}

	assert.Equal(t, "AEIMQUYcgkosw048", string(accepted))
}

// TestVerifyRejectsMalformedVerifierEvenWhenTransformMatches pins the
// issue #79 fix at the primitive level: the challenge is derived from the
// malformed verifier itself, so only the syntax check can refuse it.
func TestVerifyRejectsMalformedVerifierEvenWhenTransformMatches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		verifier string
	}{
		{"one character (issue #79)", "x"},
		{"42 chars", as(42)},
		{"129 chars", as(129)},
		{"non-ASCII", as(41) + "é"},
		{"leading space", " " + rfc7636Verifier},
		{"trailing LF", rfc7636Verifier + "\n"},
		{"standard base64 plus", as(42) + "+"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			challenge := mustChallenge(t, pkce.MethodS256, tc.verifier)

			assert.False(t, pkce.Verify(pkce.MethodS256, tc.verifier, challenge))
			assert.False(t, pkce.VerifyS256(tc.verifier, challenge))
			assert.False(t, pkce.Verify(pkce.MethodPlain, tc.verifier, tc.verifier))
		})
	}
}

// TestVerifyAcceptsEveryLegalVerifierLength is a regression guard: every
// length RFC 7636 §4.1 allows round-trips through both methods.
func TestVerifyAcceptsEveryLegalVerifierLength(t *testing.T) {
	t.Parallel()

	source := strings.Repeat(unreservedAlphabet, 2)

	for n := 43; n <= 128; n++ {
		v := source[:n]
		challenge := mustChallenge(t, pkce.MethodS256, v)

		assert.True(t, pkce.ValidVerifier(v), "length %d", n)
		assert.True(t, pkce.ValidChallenge(pkce.MethodS256, challenge), "length %d", n)
		assert.True(t, pkce.Verify(pkce.MethodS256, v, challenge), "length %d", n)
		assert.True(t, pkce.ValidChallenge(pkce.MethodPlain, v), "length %d", n)
		assert.True(t, pkce.Verify(pkce.MethodPlain, v, v), "length %d", n)
	}
}
