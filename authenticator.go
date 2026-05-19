// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import "context"

// Authenticator validates an [Authentication] produced by an [Extractor] and
// returns a NEW authenticated value. It MUST NOT mutate its input — the
// Authentication is treated as immutable everywhere in the core.
//
// Two-step contract:
//
//   - Supports reports whether the authenticator recognizes the credential
//     type. Implementations MUST be cheap (a type switch); they MUST NOT
//     perform I/O.
//   - Authenticate validates the credential and either returns the new,
//     authenticated value or an error wrapping a security sentinel
//     ([ErrInvalidCredentials], [ErrTokenExpired], ...). Returning
//     ([ErrUnsupportedCredential]) is the canonical way to bail out at
//     runtime when Supports returned true but the value was nonetheless
//     out of scope.
//
// Implementations MUST be safe for concurrent use.
type Authenticator interface {
	Supports(auth Authentication) bool
	Authenticate(ctx context.Context, auth Authentication) (Authentication, error)
}

// AuthenticatorFunc adapts a function to the Authenticator interface. It
// reports Supports == true for every input; callers wanting selectivity
// should write a concrete type instead.
type AuthenticatorFunc func(ctx context.Context, auth Authentication) (Authentication, error)

// Supports implements [Authenticator].
func (AuthenticatorFunc) Supports(Authentication) bool { return true }

// Authenticate implements [Authenticator].
func (f AuthenticatorFunc) Authenticate(ctx context.Context, auth Authentication) (Authentication, error) {
	return f(ctx, auth)
}

// NamedAuthenticator is an optional capability: when an Authenticator
// implements it, the [Manager] records the name in the OTel span so
// observability backends can attribute decisions per provider.
type NamedAuthenticator interface {
	AuthenticatorName() string
}
