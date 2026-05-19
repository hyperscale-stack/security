// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer

import "github.com/hyperscale-stack/security"

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

// Token returns the raw bearer token. Once a [TokenVerifier] has produced an
// authenticated value, the token can be redacted by calling
// [Authentication.WithAuthenticated] with a verifier that builds a fresh
// value from scratch.
func (a Authentication) Token() string { return a.token }

// WithAuthenticated returns a new Authentication marked as validated, with
// the provided principal, authorities and display name. The token is
// preserved so adapters that issue refresh challenges can still inspect it.
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
		token:       a.token,
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
// authentication, nil after (the verifier is expected to redact via a fresh
// WithAuthenticated call).
func (a Authentication) Credentials() any {
	if a.authed {
		return nil
	}

	return a.token
}

// Authorities implements [security.Authentication].
func (a Authentication) Authorities() []string { return a.authorities }

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
