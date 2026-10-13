// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic

import (
	"slices"

	"github.com/hyperscale-stack/security"
)

// Authentication is the [security.Authentication] produced by the Basic
// [Extractor]. It carries the supplied username/password pair before
// validation and the resolved [PasswordUser] after. The struct is immutable;
// "mutations" return a fresh value.
type Authentication struct {
	username    string
	password    string
	user        PasswordUser
	authorities []string
	authed      bool
}

// New constructs an unauthenticated Authentication from a username/password
// pair: the [Extractor] builds it from an Authorization header, and a form
// login (or an OAuth2 password grant) may build it from its own fields and
// hand it to the [Authenticator], which checks the pair again before any
// lookup.
func New(username, password string) Authentication {
	return Authentication{username: username, password: password}
}

// Username returns the user-id as typed by the client. It MAY differ from
// the resolved [PasswordUser]'s subject (e.g. login by email) and may even
// be a password typed in the wrong field: log [Authentication.Name], never
// Username.
func (a Authentication) Username() string { return a.username }

// Password returns the cleartext password. Once an [Authenticator] has
// validated the credential, the returned value is zeroed (see WithAuthenticated).
func (a Authentication) Password() string { return a.password }

// WithAuthenticated returns a new Authentication marked as validated, with
// the resolved user attached, the cleartext password redacted, and the
// authorities materialized from the user.
func (a Authentication) WithAuthenticated(user PasswordUser, authorities []string) Authentication {
	cp := authorities
	if authorities != nil {
		cp = make([]string, len(authorities))
		copy(cp, authorities)
	}

	return Authentication{
		username:    a.username,
		password:    "", // redact cleartext after successful auth
		user:        user,
		authorities: cp,
		authed:      true,
	}
}

// Principal implements [security.Authentication]. Returns the resolved
// [PasswordUser] when the value is authenticated, the [security.AnonymousPrincipal]
// otherwise (so downstream code can rely on a non-nil principal).
func (a Authentication) Principal() security.Principal {
	if a.user != nil {
		return a.user
	}

	return security.AnonymousPrincipal
}

// Credentials implements [security.Authentication]. Returns the cleartext
// password before authentication, nil after.
func (a Authentication) Credentials() any {
	if a.password == "" {
		return nil
	}

	return a.password
}

// Authorities implements [security.Authentication]. It returns a copy: the
// Authentication stays immutable whatever the caller does with the slice.
func (a Authentication) Authorities() []string { return slices.Clone(a.authorities) }

// IsAuthenticated implements [security.Authentication].
func (a Authentication) IsAuthenticated() bool { return a.authed }

// Name implements [security.Authentication]. Returns the authenticated
// user's subject, or "basic" before authentication: the typed user-id is
// not safe to log (see [Authentication.Username]).
func (a Authentication) Name() string {
	if a.user != nil {
		return a.user.Subject()
	}

	return schemeLabel
}

// schemeLabel names the scheme in Name before authentication, like the
// bearer and session schemes do.
const schemeLabel = "basic"

// User returns the resolved [PasswordUser], or nil when the value is still
// pre-authentication.
func (a Authentication) User() PasswordUser { return a.user }
