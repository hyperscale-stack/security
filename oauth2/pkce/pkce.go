// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package pkce ships the RFC 7636 verifier helpers used by the OAuth2
// server's authorization-code grant.
//
// PKCE is mandatory for public clients and recommended for confidential
// clients (OAuth 2.0 BCP §2.1.1 / OAuth 2.1 draft §1.7). The "plain"
// method is supported for backwards compatibility but its use is refused
// when the server profile is OAuth 2.0 BCP or OAuth 2.1 draft.
//
// Both ends enforce the RFC 7636 syntax, not just the transformation:
// [ValidChallenge] checks a code_challenge at the authorization endpoint,
// and [Verify] refuses at the token endpoint a code_verifier that
// [ValidVerifier] rejects.
package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// RFC 7636 §4.1 bounds on the code_verifier length, in characters.
const (
	minVerifierLength = 43
	maxVerifierLength = 128
)

// Method identifies the PKCE transformation used to derive the challenge
// from the verifier (RFC 7636 §4.2).
type Method string

const (
	// MethodS256 is the SHA-256 + base64url challenge transformation.
	MethodS256 Method = "S256"
	// MethodPlain echoes the verifier verbatim. RFC 7636 allows it for
	// transition; the server profile must opt-in.
	MethodPlain Method = "plain"
)

// String makes Method satisfy fmt.Stringer.
func (m Method) String() string { return string(m) }

// ValidVerifier reports whether verifier is a well-formed RFC 7636 §4.1
// code_verifier: 43 to 128 characters from the unreserved set
// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~". Any other byte, including
// whitespace and every non-ASCII byte, makes it malformed.
func ValidVerifier(verifier string) bool {
	if len(verifier) < minVerifierLength || len(verifier) > maxVerifierLength {
		return false
	}

	for i := range len(verifier) {
		if !isUnreserved(verifier[i]) {
			return false
		}
	}

	return true
}

// ValidChallenge reports whether challenge is well-formed for method, as the
// authorization endpoint checks it (RFC 7636 §4.2): a plain challenge is the
// verifier itself (see [ValidVerifier]); an S256 challenge is exactly the
// unpadded base64url encoding of a SHA-256 digest (43 characters, Appendix
// A). Any other method — including the empty one, which callers resolve to
// [MethodPlain] first (§4.3) — is never valid.
func ValidChallenge(method Method, challenge string) bool {
	switch method {
	case MethodS256:
		return validS256Challenge(challenge)
	case MethodPlain:
		return ValidVerifier(challenge)
	default:
		return false
	}
}

// Verify reports whether verifier matches the expected challenge under
// method (RFC 7636 §4.6). It returns false for a malformed verifier (see
// [ValidVerifier]), an unsupported method or a mismatch, so a malformed
// stored challenge never matches either. The syntax check reads only the
// verifier; a well-formed verifier is then compared with expected in
// constant time.
func Verify(method Method, verifier, expected string) bool {
	if !ValidVerifier(verifier) {
		return false
	}

	switch method {
	case MethodS256:
		return s256Equal(verifier, expected)
	case MethodPlain:
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(expected)) == 1
	default:
		return false
	}
}

// VerifyS256 is [Verify] with the recommended S256 method.
func VerifyS256(verifier, expected string) bool { return Verify(MethodS256, verifier, expected) }

func s256Equal(verifier, expected string) bool {
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// Challenge derives the challenge for a given verifier and method. Useful
// in test helpers and client-side libraries; not used by the server during
// verification (the server only consumes the challenge stored alongside
// the code). Challenge does not validate verifier; check untrusted input
// with [ValidVerifier] first.
func Challenge(method Method, verifier string) (string, bool) {
	switch method {
	case MethodS256:
		sum := sha256.Sum256([]byte(verifier))

		return base64.RawURLEncoding.EncodeToString(sum[:]), true
	case MethodPlain:
		return verifier, true
	default:
		return "", false
	}
}

// validS256Challenge reports whether challenge is exactly what
// BASE64URL-ENCODE (RFC 7636 Appendix A) yields for a SHA-256 digest.
// Re-encoding the decoded bytes also refuses what a decode alone lets
// through: the CR and LF encoding/base64 skips, even in strict mode, and
// non-zero trailing bits.
func validS256Challenge(challenge string) bool {
	if len(challenge) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return false
	}

	digest, err := base64.RawURLEncoding.DecodeString(challenge)

	return err == nil && base64.RawURLEncoding.EncodeToString(digest) == challenge
}

// isUnreserved reports whether c is an RFC 3986 §2.3 unreserved character.
// It inspects bytes, not runes, so any multi-byte UTF-8 sequence is refused.
func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
