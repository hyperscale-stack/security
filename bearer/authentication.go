// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer

import (
	"slices"

	"github.com/hyperscale-stack/security"
)

// Authentication is the [security.Authentication] produced by the bearer
// [Extractor]. Before validation it carries only the opaque token; after
// validation a [TokenVerifier] is expected to return a new value where
// Principal, Authorities and IsAuthenticated are populated.
type Authentication struct {
	token       string
	principal   security.Principal
	authorities []string
	authed      bool
	name        string
}

// New constructs an unauthenticated bearer Authentication from an opaque
// token. Reserved for [Extractor] implementations.
func New(token string) Authentication {
	return Authentication{token: token}
}

// Token returns the raw bearer token of an unauthenticated value — the one
// the [Extractor] read — and "" once it is authenticated:
// [Authentication.WithAuthenticated] drops it. To relay the token to another
// service, read the request's Authorization field instead.
func (a Authentication) Token() string { return a.token }

// WithAuthenticated returns a new Authentication marked as validated, with
// the provided principal, authorities and display name. It drops the token:
// a verified value never carries the credential it was verified from, so it
// can flow through the request context, logs and panics without it.
func (a Authentication) WithAuthenticated(p security.Principal, authorities []string, name string) Authentication {
	cp := authorities
	if authorities != nil {
		cp = make([]string, len(authorities))
		copy(cp, authorities)
	}

	if name == "" && p != nil {
		name = p.Subject()
	}

	return Authentication{
		principal:   p,
		authorities: cp,
		authed:      true,
		name:        name,
	}
}

// Principal implements [security.Authentication].
func (a Authentication) Principal() security.Principal {
	if a.principal != nil {
		return a.principal
	}

	return security.AnonymousPrincipal
}

// Credentials implements [security.Authentication]. Returns the token before
// authentication, nil after (WithAuthenticated drops it).
func (a Authentication) Credentials() any {
	if a.authed {
		return nil
	}

	return a.token
}

// Authorities implements [security.Authentication]. It returns a copy: the
// Authentication stays immutable whatever the caller does with the slice.
func (a Authentication) Authorities() []string { return slices.Clone(a.authorities) }

// IsAuthenticated implements [security.Authentication].
func (a Authentication) IsAuthenticated() bool { return a.authed }

// Name implements [security.Authentication]. Returns the validated name when
// authenticated, the principal subject otherwise, or "bearer" as a last
// resort so log lines remain non-empty.
func (a Authentication) Name() string {
	if a.name != "" {
		return a.name
	}

	if a.principal != nil {
		return a.principal.Subject()
	}

	return schemeName
}

// schemeName is the canonical scheme label used both as a fallback
// Authentication.Name and as the [Authenticator.AuthenticatorName] return
// value (so span attribution stays consistent).
const schemeName = "bearer"
