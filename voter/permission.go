// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"

	"github.com/hyperscale-stack/security"
)

// HasPermission returns a [security.Voter] that evaluates every
// [security.PermissionAttribute] passed to it via its embedded predicate.
//
// Vote semantics:
//   - Unauthenticated => Deny.
//   - No PermissionAttribute in attrs => Abstain (Supports() will short-
//     circuit before reaching Vote in practice).
//   - Any predicate returning false => Deny.
//   - Every predicate returning true => Grant.
//   - A nil predicate is treated as Deny (defensive default; refusing to
//     authorize on an empty rule is safer than the alternative).
func HasPermission() security.Voter { return permissionVoter{} }

type permissionVoter struct{}

func (permissionVoter) Supports(a security.Attribute) bool {
	_, ok := a.(security.PermissionAttribute)

	return ok
}

func (permissionVoter) Vote(ctx context.Context, auth security.Authentication, attrs []security.Attribute) security.Decision {
	if !auth.IsAuthenticated() {
		return security.DecisionDeny
	}

	saw := false

	for _, a := range attrs {
		p, ok := a.(security.PermissionAttribute)
		if !ok {
			continue
		}

		saw = true

		if p.Predicate == nil {
			return security.DecisionDeny
		}

		if !p.Predicate(ctx, auth) {
			return security.DecisionDeny
		}
	}

	if !saw {
		return security.DecisionAbstain
	}

	return security.DecisionGrant
}
