// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"slices"

	"github.com/hyperscale-stack/security"
)

// HasScope returns a [security.Voter] bound to one OAuth2 scope: it votes on
// the [security.ScopeAttribute] naming that scope and abstains on every other
// attribute. It grants when the authenticated principal carries the
// authority security.ScopePrefix + scope ("scope:read:mail" — one scope per
// authority, as jwtsec.DefaultAuthorityResolver emits) and denies otherwise;
// unauthenticated requests always vote Deny. A bare "read:mail" authority is
// not a scope, and "scope:a b" is the single scope "a b".
//
// HasScope panics if scope is not an RFC 6749 §3.3 scope-token (empty, with
// a space, a double quote, a backslash or a non-ASCII character) or already
// starts with "scope:" — such a scope could never match.
func HasScope(scope string) security.Voter {
	return newScopeVoter("HasScope", scope)
}

// HasAnyScope returns a [security.Voter] bound to several scopes: it grants
// when the principal carries at least one of the scopes the route requests.
// Same comparison rules as [HasScope]; it panics without a scope or on a
// scope HasScope refuses.
func HasAnyScope(scopes ...string) security.Voter {
	return newScopeVoter("HasAnyScope", scopes...)
}

func newScopeVoter(constructor string, scopes ...string) security.Voter {
	return nameVoter{
		names:  mustNames(constructor, "scope", scopes, checkScope),
		nameOf: scopeName,
		holds:  hasScope,
	}
}

// scopeName returns the name of a scope attribute.
func scopeName(a security.Attribute) (string, bool) {
	s, ok := a.(security.ScopeAttribute)

	return s.Name(), ok
}

// hasScope reports whether authorities contains the scope authority.
func hasScope(authorities []string, scope string) bool {
	return slices.Contains(authorities, scopePrefix+scope)
}

const scopePrefix = security.ScopePrefix
