// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"
	"slices"
	"strings"

	"github.com/hyperscale-stack/security"
)

// HasScope returns a [security.Voter] that grants when the authenticated
// principal carries the given OAuth2 scope. Scope matching is exact and
// supports two storage conventions on [security.Authentication.Authorities]:
//
//   - bare scope name ("read:mail")
//   - "scope:" prefix ("scope:read:mail")
//
// Unauthenticated requests always vote Deny; non-scope attributes Abstain.
func HasScope(scope string) security.Voter {
	return scopeVoter{wanted: []string{scope}, anyOf: false}
}

// HasAnyScope grants when the principal carries at least one of the listed
// scopes. Same comparison rules as [HasScope].
func HasAnyScope(scopes ...string) security.Voter {
	return scopeVoter{wanted: scopes, anyOf: true}
}

type scopeVoter struct {
	wanted []string
	anyOf  bool
}

func (v scopeVoter) Supports(a security.Attribute) bool {
	_, ok := a.(security.ScopeAttribute)

	return ok
}

func (v scopeVoter) Vote(_ context.Context, auth security.Authentication, _ []security.Attribute) security.Decision {
	if !auth.IsAuthenticated() {
		return security.DecisionDeny
	}

	for _, want := range v.wanted {
		if hasScope(auth.Authorities(), want) {
			return security.DecisionGrant
		}

		if !v.anyOf {
			break
		}
	}

	return security.DecisionDeny
}

func hasScope(authorities []string, scope string) bool {
	if slices.Contains(authorities, scope) {
		return true
	}

	prefixed := "scope:" + scope

	for _, a := range authorities {
		if a == prefixed {
			return true
		}
		// Also accept the OAuth2 "scope" claim packaged as a
		// space-separated string in a single authority.
		if strings.HasPrefix(a, "scope:") {
			for _, s := range strings.Split(a[len("scope:"):], " ") {
				if s == scope {
					return true
				}
			}
		}
	}

	return false
}
