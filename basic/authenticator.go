// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/password"
)

// AuthorityResolver maps a [PasswordUser] to the authorities (roles, scopes,
// claims) attached to the resulting [security.Authentication]. The default
// resolver returns nil; applications that ship role-based authorization
// provide one that reads the authorities from the user record.
type AuthorityResolver func(PasswordUser) []string

// Authenticator implements [security.Authenticator] for the HTTP Basic
// scheme. It loads the user via a [UserLoader], runs lifecycle checks,
// verifies the password with a [password.Hasher], then returns the
// authenticated [Authentication].
//
// Errors are always wrapped in [security.ErrInvalidCredentials] to avoid
// account-enumeration via response-time / response-code analysis. Detailed
// causes remain reachable through errors.As / errors.Is for server-side
// telemetry only — do NOT mirror them in the client response.
type Authenticator struct {
	loader     UserLoader
	hasher     password.Hasher
	authResolv AuthorityResolver
}

// NewAuthenticator returns an Authenticator using the supplied loader and
// hasher. Authorities default to nil (use [WithAuthorityResolver] to
// populate them from the user record).
func NewAuthenticator(loader UserLoader, hasher password.Hasher, opts ...Option) *Authenticator {
	a := &Authenticator{loader: loader, hasher: hasher}

	for _, o := range opts {
		o(a)
	}

	return a
}

// Option configures an Authenticator.
type Option func(*Authenticator)

// WithAuthorityResolver overrides the resolver mapping a [PasswordUser] to
// the authorities materialized on the [Authentication].
func WithAuthorityResolver(r AuthorityResolver) Option {
	return func(a *Authenticator) { a.authResolv = r }
}

// AuthenticatorName implements [security.NamedAuthenticator] so the core
// Manager can attribute spans to "basic".
func (a *Authenticator) AuthenticatorName() string { return "basic" }

// Supports reports whether auth is a [basic.Authentication]. Returns false
// for everything else, which lets the [security.Manager] delegate to the
// next authenticator in line.
func (a *Authenticator) Supports(auth security.Authentication) bool {
	_, ok := auth.(Authentication)

	return ok
}

// Authenticate implements [security.Authenticator].
func (a *Authenticator) Authenticate(ctx context.Context, auth security.Authentication) (security.Authentication, error) {
	in, ok := auth.(Authentication)
	if !ok {
		return auth, security.ErrUnsupportedCredential
	}

	user, err := a.loader.LoadByUsername(ctx, in.Username())
	if err != nil {
		// Loader-level errors (db down, unknown user, ...) collapse to a
		// single ErrInvalidCredentials at the client boundary. The original
		// error stays in the chain for observability.
		return auth, fmt.Errorf("basic: load user %q: %w (%w)", in.Username(), err, security.ErrInvalidCredentials)
	}

	if user == nil {
		return auth, fmt.Errorf("basic: user not found: %w", security.ErrInvalidCredentials)
	}

	if !user.IsEnabled() || user.IsLocked() || user.IsExpired() || user.IsCredentialsExpired() {
		return auth, fmt.Errorf("basic: account ineligible: %w", security.ErrInvalidCredentials)
	}

	ok, err = a.hasher.Verify(ctx, user.GetPasswordHash(), in.Password())
	if err != nil {
		return auth, fmt.Errorf("basic: hash verify: %w (%w)", err, security.ErrInvalidCredentials)
	}

	if !ok {
		return auth, fmt.Errorf("basic: password mismatch: %w", security.ErrInvalidCredentials)
	}

	var authorities []string
	if a.authResolv != nil {
		authorities = a.authResolv(user)
	}

	return in.WithAuthenticated(user, authorities), nil
}

// Compile-time interface check.
var _ security.Authenticator = (*Authenticator)(nil)
