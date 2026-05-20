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
// Errors MUST wrap one of [security.ErrTokenExpired], [security.ErrTokenNotFound]
// or [security.ErrInvalidCredentials] so the default HTTP / gRPC error mappers
// translate them to the right status / code.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (security.Authentication, error)
}

// VerifierFunc adapts a function to [TokenVerifier].
type VerifierFunc func(ctx context.Context, token string) (security.Authentication, error)

// Verify implements [TokenVerifier].
func (f VerifierFunc) Verify(ctx context.Context, token string) (security.Authentication, error) {
	return f(ctx, token)
}
