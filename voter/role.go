// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"
	"slices"

	"github.com/hyperscale-stack/security"
)

// HasRole returns a [security.Voter] that grants when the authenticated
// principal carries the given role (matched on Authorities() with the
// Spring-style ROLE_ prefix). Unauthenticated requests always vote Deny;
// foreign attribute families produce Abstain.
//
// The voter compares against [security.Authentication.Authorities] in two
// shapes: with and without the ROLE_ prefix, so applications can use either
// convention in their user store.
func HasRole(role string) security.Voter {
	return roleVoter{wanted: []string{role}, anyOf: false}
}

// HasAnyRole grants when the principal carries at least one of the listed
// roles. Same comparison rules as [HasRole].
func HasAnyRole(roles ...string) security.Voter {
	return roleVoter{wanted: roles, anyOf: true}
}

type roleVoter struct {
	wanted []string
	anyOf  bool
}

func (v roleVoter) Supports(a security.Attribute) bool {
	_, ok := a.(security.RoleAttribute)

	return ok
}

func (v roleVoter) Vote(_ context.Context, auth security.Authentication, attrs []security.Attribute) security.Decision {
	if !auth.IsAuthenticated() {
		return security.DecisionDeny
	}

	for _, want := range v.wanted {
		if hasRole(auth.Authorities(), want) {
			return security.DecisionGrant
		}

		if !v.anyOf {
			// Single-role mode: every wanted role MUST match; one miss is
			// enough to deny. But there's only one entry, so the loop is
			// degenerate — fall through to deny below.
			break
		}
	}
	// Touch attrs to keep the parameter meaningful in tests that supply
	// attributes; voters do not need to inspect them when the role list
	// is pre-bound.
	_ = attrs

	return security.DecisionDeny
}

// hasRole reports whether authorities contains role either verbatim or with
// the Spring-style ROLE_ prefix.
func hasRole(authorities []string, role string) bool {
	if slices.Contains(authorities, role) {
		return true
	}

	return slices.Contains(authorities, "ROLE_"+role)
}
