// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import jose "github.com/go-jose/go-jose/v4"

// Algorithm is a typed alias around the JOSE algorithm identifier so the
// security API stays self-contained: callers do not need to import go-jose
// for the common case (configuring an allowlist).
type Algorithm string

// Supported signature algorithms. The list is deliberately curated: every
// algorithm here is either an RSA-PSS / ECDSA / EdDSA scheme (asymmetric)
// or HS256 (symmetric, hidden by default).
//
// "none" is not exported: rejecting it unconditionally defeats the canonical
// JWT family of "alg=none" attacks.
const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	EdDSA Algorithm = "EdDSA"
	// HS256 is symmetric. It is enabled only when [WithAllowedAlgorithms]
	// includes it explicitly — the default allowlist excludes it to prevent
	// the well-known "RSA public key used as HMAC secret" key-confusion
	// attack.
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
)

// String makes Algorithm implement fmt.Stringer; identical to the underlying
// alg identifier so logs match JOSE conventions.
func (a Algorithm) String() string { return string(a) }

// joseAlg converts Algorithm to the JOSE library's typed identifier.
func (a Algorithm) joseAlg() jose.SignatureAlgorithm {
	return jose.SignatureAlgorithm(a)
}

// defaultAllowedAlgorithms is the strict baseline applied when the user does
// not call WithAllowedAlgorithms. It deliberately excludes HMAC algorithms.
var defaultAllowedAlgorithms = []Algorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}
