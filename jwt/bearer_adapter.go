// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
)

// AuthorityResolver maps the parsed standard claims to the authorities
// attached to the resulting [security.Authentication]. The default resolver
// (when none is provided) splits StandardClaims.Scope on spaces and prefixes
// each entry with "scope:" so the voter package recognizes them.
type AuthorityResolver func(claims *StandardClaims) []string

// BearerVerifier adapts a JWT [Verifier] to the [bearer.TokenVerifier]
// contract. The returned TokenVerifier produces an authenticated
// [bearer.Authentication] whose principal is the JWT `sub` claim and whose
// authorities are the values returned by the resolver.
//
// When resolver is nil, [DefaultAuthorityResolver] is used.
func BearerVerifier(v Verifier, resolver AuthorityResolver) bearer.TokenVerifier {
	if resolver == nil {
		resolver = DefaultAuthorityResolver
	}

	return bearer.VerifierFunc(func(ctx context.Context, token string) (security.Authentication, error) {
		claims, err := v.Verify(ctx, token, nil)
		if err != nil {
			return nil, err //nolint:wrapcheck // verifier already wraps with sentinels
		}

		principal := claimPrincipal{sub: claims.Subject}
		authorities := resolver(claims)

		return bearer.New(token).WithAuthenticated(principal, authorities, claims.Subject), nil
	})
}

// DefaultAuthorityResolver materializes authorities from the OAuth2 `scope`
// claim. Each space-separated scope is prefixed with "scope:" so the voter
// package recognizes it via [security.ScopeAttribute].
func DefaultAuthorityResolver(claims *StandardClaims) []string {
	if claims.Scope == "" {
		return nil
	}

	out := make([]string, 0, 4)

	for s := range splitFields(claims.Scope) {
		out = append(out, "scope:"+s)
	}

	return out
}

// splitFields yields the space-separated fields of s without allocating an
// intermediate slice. Mirrors strings.Fields in iterator form.
func splitFields(s string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		start := -1

		for i, r := range s {
			if r == ' ' || r == '\t' {
				if start >= 0 {
					if !yield(s[start:i]) {
						return
					}

					start = -1
				}

				continue
			}

			if start < 0 {
				start = i
			}
		}

		if start >= 0 {
			_ = yield(s[start:])
		}
	}
}

// claimPrincipal is the [security.Principal] returned by BearerVerifier.
type claimPrincipal struct{ sub string }

// Subject implements [security.Principal].
func (p claimPrincipal) Subject() string { return p.sub }
