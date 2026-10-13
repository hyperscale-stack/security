// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"
	"slices"

	"github.com/hyperscale-stack/security"
)

// nameVoter is the role, scope and authority voter. Following Spring
// Security's RoleVoter, it is bound to a set of names and votes only on the
// attributes of its family whose name is in that set: the attributes a route
// lists are the policy, the voter checks the ones it knows.
type nameVoter struct {
	names []string
	// nameOf returns the name of an attribute of the voter's family.
	nameOf func(security.Attribute) (string, bool)
	// holds reports whether the authorities grant the named requirement.
	holds func(authorities []string, name string) bool
}

// Supports reports whether a is an attribute of the voter's family whose
// name the voter is bound to.
func (v nameVoter) Supports(a security.Attribute) bool {
	name, ok := v.nameOf(a)

	return ok && slices.Contains(v.names, name)
}

// Vote abstains when attrs carries none of the voter's names, denies an
// unauthenticated principal, and grants when the principal holds at least
// one of the requested names.
func (v nameVoter) Vote(_ context.Context, auth security.Authentication, attrs []security.Attribute) security.Decision {
	requested := v.requested(attrs)
	if len(requested) == 0 {
		return security.DecisionAbstain
	}

	if !auth.IsAuthenticated() {
		return security.DecisionDeny
	}

	authorities := auth.Authorities()

	for _, name := range requested {
		if v.holds(authorities, name) {
			return security.DecisionGrant
		}
	}

	return security.DecisionDeny
}

// requested returns the names of the supported attributes of attrs.
func (v nameVoter) requested(attrs []security.Attribute) []string {
	var out []string

	for _, a := range attrs {
		if name, ok := v.nameOf(a); ok && slices.Contains(v.names, name) {
			out = append(out, name)
		}
	}

	return out
}
