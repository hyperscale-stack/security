// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"slices"
	"strings"

	"github.com/hyperscale-stack/security"
)

// HasScope returns a [security.Voter] bound to one OAuth2 scope: it votes on
// the [security.ScopeAttribute] naming that scope and abstains on every other
// attribute. It grants when the authenticated principal carries the scope
// and denies otherwise; unauthenticated requests always vote Deny. Scope
// matching is exact and supports two storage conventions on
// [security.Authentication.Authorities]:
//
//   - bare scope name ("read:mail")
//   - "scope:" prefix ("scope:read:mail")
func HasScope(scope string) security.Voter {
	return newScopeVoter(scope)
}

// HasAnyScope returns a [security.Voter] bound to several scopes: it grants
// when the principal carries at least one of the scopes the route requests.
// Same comparison rules as [HasScope].
func HasAnyScope(scopes ...string) security.Voter {
	return newScopeVoter(scopes...)
}

func newScopeVoter(scopes ...string) security.Voter {
	return nameVoter{names: slices.Clone(scopes), nameOf: scopeName, holds: hasScope}
}

// scopeName returns the name of a scope attribute.
func scopeName(a security.Attribute) (string, bool) {
	s, ok := a.(security.ScopeAttribute)

	return s.Name(), ok
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
