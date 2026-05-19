// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security"
)

// Authenticator implements [security.Authenticator] for the Bearer scheme.
// It delegates token validation to a pluggable [TokenVerifier]; the bearer
// module ships no concrete verifier so it stays format-agnostic.
type Authenticator struct {
	verifier TokenVerifier
}

// NewAuthenticator returns an [Authenticator] backed by verifier.
// A nil verifier triggers a panic at construction time — the configuration
// would be silently insecure otherwise.
func NewAuthenticator(verifier TokenVerifier) *Authenticator {
	if verifier == nil {
		panic("bearer: NewAuthenticator: nil TokenVerifier")
	}

	return &Authenticator{verifier: verifier}
}

// AuthenticatorName implements [security.NamedAuthenticator].
func (a *Authenticator) AuthenticatorName() string { return schemeName }

// Supports reports whether auth is a [bearer.Authentication].
func (a *Authenticator) Supports(auth security.Authentication) bool {
	_, ok := auth.(Authentication)

	return ok
}

// Authenticate implements [security.Authenticator]. The returned
// authentication is whatever the verifier produced; on verifier error the
// error is propagated as-is (the verifier is expected to wrap one of the
// security sentinels for the error mapper to route).
func (a *Authenticator) Authenticate(ctx context.Context, auth security.Authentication) (security.Authentication, error) {
	in, ok := auth.(Authentication)
	if !ok {
		return auth, security.ErrUnsupportedCredential
	}

	out, err := a.verifier.Verify(ctx, in.Token())
	if err != nil {
		return auth, fmt.Errorf("bearer: verify token: %w", err)
	}

	if out == nil {
		return auth, fmt.Errorf("bearer: verifier returned nil authentication: %w", security.ErrInvalidCredentials)
	}

	return out, nil
}

// Compile-time interface check.
var _ security.Authenticator = (*Authenticator)(nil)
