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
// attribute. It grants when the authenticated principal carries the
// authority security.RolePrefix + role ("ROLE_ADMIN") and denies otherwise;
// unauthenticated requests always vote Deny. A bare "ADMIN" authority is not
// a role.
//
// HasRole panics if role is empty or already starts with "ROLE_" (such a
// role could never match).
func HasRole(role string) security.Voter {
	return newRoleVoter("HasRole", role)
}

// HasAnyRole returns a [security.Voter] bound to several roles: it votes on
// the role attributes naming one of them and grants when the principal
// carries at least one of the roles the route requests (OR, like Spring's
// RoleVoter). Same comparison rules as [HasRole]; it panics without a role
// or on a role HasRole refuses.
func HasAnyRole(roles ...string) security.Voter {
	return newRoleVoter("HasAnyRole", roles...)
}

func newRoleVoter(constructor string, roles ...string) security.Voter {
	return nameVoter{
		names:  mustNames(constructor, "role", roles, checkRole),
		nameOf: roleName,
		holds:  hasRole,
	}
}

// roleName returns the bare name of a role attribute.
func roleName(a security.Attribute) (string, bool) {
	r, ok := a.(security.RoleAttribute)

	return r.Name(), ok
}

// hasRole reports whether authorities contains the role authority.
func hasRole(authorities []string, role string) bool {
	return slices.Contains(authorities, rolePrefix+role)
}

const rolePrefix = security.RolePrefix
