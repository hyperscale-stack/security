// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"
	"slices"

	"github.com/hyperscale-stack/security"
)

// Authenticated returns a voter that evaluates the [security.IsAuthenticated]
// attribute: it grants an authenticated principal and denies anything else.
// It abstains on every other attribute — list [security.IsAuthenticated]
// among the route's attributes to require a logged-in principal.
func Authenticated() security.Voter { return stateVoter{state: security.IsAuthenticated} }

// Anonymous returns a voter that evaluates the [security.IsAnonymous]
// attribute: it grants an unauthenticated request and denies an
// authenticated one — for endpoints reserved to logged-out clients (signup,
// password-reset request, ...). It abstains on every other attribute.
func Anonymous() security.Voter { return stateVoter{state: security.IsAnonymous} }

// stateVoter evaluates one authentication-state attribute.
type stateVoter struct {
	state security.StateAttribute
}

// Supports reports whether a is the voter's state attribute.
func (v stateVoter) Supports(a security.Attribute) bool {
	s, ok := a.(security.StateAttribute)

	return ok && s == v.state
}

// Vote abstains without the voter's attribute; otherwise it grants when the
// authentication is in the required state.
func (v stateVoter) Vote(_ context.Context, auth security.Authentication, attrs []security.Attribute) security.Decision {
	if !slices.ContainsFunc(attrs, v.Supports) {
		return security.DecisionAbstain
	}

	if auth.IsAuthenticated() == (v.state == security.IsAuthenticated) {
		return security.DecisionGrant
	}

	return security.DecisionDeny
}
