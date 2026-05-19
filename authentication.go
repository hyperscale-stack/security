// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

// Authentication is an immutable snapshot of a security context: who is acting
// (the [Principal]), what proof was presented (the credentials), what
// authorities the system has granted them, and whether the proof has been
// verified.
//
// Authentication values flow through three logical stages during a request:
//
//  1. An [Extractor] reads raw credentials from a [Carrier] and constructs an
//     unauthenticated value (IsAuthenticated() == false).
//  2. A matching [Authenticator] validates the credentials and returns a NEW
//     authenticated value (IsAuthenticated() == true). The original value
//     MUST NOT be mutated.
//  3. Authorisation [Voter]s inspect the value to grant or deny access.
//
// Implementations MUST be safe for concurrent reads. Because every state
// change goes through a fresh value, no synchronization is required for
// callers.
type Authentication interface {
	// Principal returns the identity carried by this authentication.
	// MUST return [AnonymousPrincipal] for unauthenticated values and
	// MUST NOT return nil.
	Principal() Principal

	// Credentials returns the raw credentials presented by the principal.
	// For a token-based authentication this is typically the token string;
	// for username/password it is the cleartext password. Implementations
	// SHOULD zero or omit secret material once authentication has succeeded
	// to limit accidental leakage through logging or panics.
	//
	// The return type is intentionally any: typed accessors are provided by
	// each scheme module (basic.Password(), bearer.Token(), ...).
	Credentials() any

	// Authorities returns the authorities (roles, scopes, permissions) the
	// system has granted to this principal. The slice is read-only;
	// implementations SHOULD return the same backing slice across calls.
	Authorities() []string

	// IsAuthenticated reports whether the credentials have been validated by
	// an [Authenticator]. Voters use this to short-circuit denials before
	// inspecting authorities.
	IsAuthenticated() bool

	// Name returns a stable, log-friendly identifier for this authentication.
	// It is typically the principal subject; for client_credentials flows it
	// can be the client ID. It MUST be safe to include in structured logs
	// (no secrets, no high-cardinality values that are not the subject).
	Name() string
}
