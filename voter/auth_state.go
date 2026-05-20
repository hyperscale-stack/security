// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"

	"github.com/hyperscale-stack/security"
)

// Authenticated returns a voter that grants when the request carries an
// authenticated [security.Authentication]. Useful as the universal
// "must be logged in" check before more specific role/scope voters run.
func Authenticated() security.Voter { return authStateVoter{requireAuth: true} }

// Anonymous returns a voter that grants when the request is NOT
// authenticated. Useful for endpoints reserved to logged-out clients
// (signup, password-reset request, ...).
func Anonymous() security.Voter { return authStateVoter{requireAuth: false} }

// FullyAuthenticated is a stricter variant of [Authenticated] reserved for
// flows where "remember-me" / passive sessions must NOT be enough (e.g.
// password change, billing changes). It currently behaves like
// Authenticated; it is the hook a future "remember-me" session flag would
// key off to refuse passively-authenticated requests.
func FullyAuthenticated() security.Voter { return authStateVoter{requireAuth: true, fully: true} }

type authStateVoter struct {
	requireAuth bool
	fully       bool
}

// Supports always returns true: the auth-state voters do not need a specific
// attribute; they observe the request itself.
func (authStateVoter) Supports(security.Attribute) bool { return true }

func (v authStateVoter) Vote(_ context.Context, auth security.Authentication, _ []security.Attribute) security.Decision {
	if v.requireAuth {
		if !auth.IsAuthenticated() {
			return security.DecisionDeny
		}

		// The "fully" flag will gain teeth when session.Authentication
		// exposes IsRememberMe(); for now any authenticated value qualifies.
		_ = v.fully

		return security.DecisionGrant
	}

	if auth.IsAuthenticated() {
		return security.DecisionDeny
	}

	return security.DecisionGrant
}
