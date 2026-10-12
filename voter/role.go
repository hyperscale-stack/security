// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"slices"

	"github.com/hyperscale-stack/security"
)

// HasRole returns a [security.Voter] bound to one role: it votes on the
// [security.RoleAttribute] naming that role and abstains on every other
// attribute. It grants when the authenticated principal carries the role
// (matched on Authorities() with the Spring-style ROLE_ prefix) and denies
// otherwise; unauthenticated requests always vote Deny.
//
// The voter compares against [security.Authentication.Authorities] in two
// shapes: with and without the ROLE_ prefix, so applications can use either
// convention in their user store.
func HasRole(role string) security.Voter {
	return newRoleVoter(role)
}

// HasAnyRole returns a [security.Voter] bound to several roles: it votes on
// the role attributes naming one of them and grants when the principal
// carries at least one of the roles the route requests (OR, like Spring's
// RoleVoter). Same comparison rules as [HasRole].
func HasAnyRole(roles ...string) security.Voter {
	return newRoleVoter(roles...)
}

func newRoleVoter(roles ...string) security.Voter {
	return nameVoter{names: slices.Clone(roles), nameOf: roleName, holds: hasRole}
}

// roleName returns the bare name of a role attribute.
func roleName(a security.Attribute) (string, bool) {
	r, ok := a.(security.RoleAttribute)

	return r.Name(), ok
}

// hasRole reports whether authorities contains role either verbatim or with
// the Spring-style ROLE_ prefix.
func hasRole(authorities []string, role string) bool {
	if slices.Contains(authorities, role) {
		return true
	}

	return slices.Contains(authorities, "ROLE_"+role)
}
