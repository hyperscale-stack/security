// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security"
)

// PrincipalLoader resolves the decoded session values into a live
// [security.Principal]. Implementations live in the application layer
// (they hit the user store); this module ships none so it stays
// storage-agnostic.
//
// A typical loader reads values["sub"] and fetches the user record:
//
//	func (l myLoader) Load(ctx context.Context, v map[string]any) (security.Principal, []string, error) {
//	    sub, _ := v["sub"].(string)
//	    user, err := l.db.FindUser(ctx, sub)
//	    ...
//	}
type PrincipalLoader interface {
	// Load resolves the principal and its authorities from the session
	// values. Name roles security.RolePrefix + role ("ROLE_ADMIN") and
	// scopes one security.ScopePrefix + scope authority each
	// ("scope:read"): that is what voter.HasRole and voter.HasScope match.
	//
	// A session without a subject — opened with Manager.Login(ctx, c, nil)
	// — MUST be refused with security.ErrInvalidCredentials, never mapped
	// to a principal (anonymous or guest): the Authenticator would return
	// an authenticated value that voter.Authenticated grants. Keep such
	// sessions (a sign-in form's) on a Manager no Extractor reads.
	//
	// Returning an error fails authentication, and its sentinel tells the
	// transports how to answer: wrap security.ErrInvalidCredentials for a
	// session that must be refused (unknown or disabled user: 401),
	// security.ErrUnavailable for a user store that is temporarily down
	// (503 / Unavailable, retryable); an error wrapping no sentinel is an
	// internal error (500 / Internal).
	Load(ctx context.Context, values map[string]any) (security.Principal, []string, error)
}

// Authenticator implements [security.Authenticator] for the cookie-session
// scheme. It takes the pending [Authentication] produced by the
// [Extractor] and resolves the live principal through a [PrincipalLoader].
type Authenticator struct {
	loader PrincipalLoader
}

// NewAuthenticator returns an [Authenticator]. A nil loader panics at
// construction time — a session authenticator with nothing to resolve the
// principal would silently authenticate every cookie as anonymous.
func NewAuthenticator(loader PrincipalLoader) *Authenticator {
	if loader == nil {
		panic("session: NewAuthenticator: nil PrincipalLoader")
	}

	return &Authenticator{loader: loader}
}

// AuthenticatorName implements [security.NamedAuthenticator].
func (a *Authenticator) AuthenticatorName() string { return schemeName }

// Supports reports whether auth is a session [Authentication].
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

	principal, authorities, err := a.loader.Load(ctx, in.session.Values)
	if err != nil {
		return auth, fmt.Errorf("session: load principal: %w", err)
	}

	if principal == nil {
		return auth, fmt.Errorf("session: loader returned nil principal: %w", security.ErrInvalidCredentials)
	}

	return in.withAuthenticated(principal, authorities), nil
}

// Compile-time interface check.
var _ security.Authenticator = (*Authenticator)(nil)
