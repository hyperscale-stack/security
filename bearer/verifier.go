// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer

import (
	"context"

	"github.com/hyperscale-stack/security"
)

// TokenVerifier validates an opaque bearer token and returns the
// [security.Authentication] it represents. Implementations come from other
// modules:
//
//   - github.com/hyperscale-stack/security/jwt — local JWT verifier
//   - introspection-backed verifiers calling RFC 7662 endpoints
//   - custom verifiers calling an internal auth service
//
// On success Verify returns an authenticated value whose authorities name
// roles as [security.RolePrefix] + role ("ROLE_ADMIN") and scopes as one
// [security.ScopePrefix] + scope authority each ("scope:read") — what
// voter.HasRole and voter.HasScope match. On failure its error MUST wrap a
// security sentinel, which tells the transports how to answer:
//
//   - a refused token wraps [security.ErrTokenExpired],
//     [security.ErrTokenNotFound] or [security.ErrInvalidCredentials]
//     (401, invalid_token);
//   - a token that could not be checked — key set, introspection endpoint
//     or auth service temporarily down — wraps [security.ErrUnavailable]
//     (503 / Unavailable, retryable), never a credential sentinel;
//   - an error wrapping no sentinel is an internal error (500 / Internal).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (security.Authentication, error)
}

// VerifierFunc adapts a function to [TokenVerifier].
type VerifierFunc func(ctx context.Context, token string) (security.Authentication, error)

// Verify implements [TokenVerifier].
func (f VerifierFunc) Verify(ctx context.Context, token string) (security.Authentication, error) {
	return f(ctx, token)
}
