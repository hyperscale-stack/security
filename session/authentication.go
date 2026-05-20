// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import "github.com/hyperscale-stack/security"

// Authentication is the [security.Authentication] produced by the session
// [Extractor]. Before validation it only carries the decoded [Session];
// the [Authenticator] resolves the principal and returns a new,
// authenticated value.
type Authentication struct {
	session     *Session
	principal   security.Principal
	authorities []string
	authed      bool
}

// newPending wraps a freshly decoded session in an unauthenticated
// Authentication.
func newPending(s *Session) Authentication {
	return Authentication{session: s}
}

// Session returns the underlying [Session]. Always non-nil for values
// produced by this package.
func (a Authentication) Session() *Session { return a.session }

// withAuthenticated returns a new, authenticated Authentication carrying
// the resolved principal and authorities.
func (a Authentication) withAuthenticated(p security.Principal, authorities []string) Authentication {
	cp := authorities
	if authorities != nil {
		cp = make([]string, len(authorities))
		copy(cp, authorities)
	}

	return Authentication{
		session:     a.session,
		principal:   p,
		authorities: cp,
		authed:      true,
	}
}

// Principal implements [security.Authentication].
func (a Authentication) Principal() security.Principal {
	if a.principal != nil {
		return a.principal
	}

	return security.AnonymousPrincipal
}

// Credentials implements [security.Authentication]. A session is not a
// bearer secret the handler should read, so this is always nil.
func (a Authentication) Credentials() any { return nil }

// Authorities implements [security.Authentication].
func (a Authentication) Authorities() []string { return a.authorities }

// IsAuthenticated implements [security.Authentication].
func (a Authentication) IsAuthenticated() bool { return a.authed }

// Name implements [security.Authentication]. Returns the principal subject
// once authenticated, "session" beforehand.
func (a Authentication) Name() string {
	if a.principal != nil {
		return a.principal.Subject()
	}

	return schemeName
}
