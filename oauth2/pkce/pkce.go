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
package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

// Verify computes the challenge from verifier per method and compares it
// constant-time against expected. Returns false on length mismatch, on
// unsupported method, or on plain-vs-S256 mismatch.
func Verify(method Method, verifier, expected string) bool {
	switch method {
	case MethodS256:
		return s256Equal(verifier, expected)
	case MethodPlain:
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(expected)) == 1
	default:
		return false
	}
}

// VerifyS256 is a convenience for the recommended S256 method.
func VerifyS256(verifier, expected string) bool { return s256Equal(verifier, expected) }

func s256Equal(verifier, expected string) bool {
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// Challenge derives the challenge for a given verifier and method. Useful
// in test helpers and client-side libraries; not used by the server during
// verification (the server only consumes the challenge stored alongside
// the code).
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
