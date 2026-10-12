// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
)

// AuthorityResolver maps the parsed standard claims to the authorities
// attached to the resulting [security.Authentication]. The default resolver
// (when none is provided) splits StandardClaims.Scope on spaces and prefixes
// each entry with "scope:" so the voter package recognizes them.
type AuthorityResolver func(claims *StandardClaims) []string

// BearerOption configures [BearerVerifier].
type BearerOption func(*bearerConfig)

type bearerConfig struct {
	typ string // the access-token type the verifier must require
}

// WithAccessTokenType makes [BearerVerifier] accept a verifier that
// requires typ — WithType(typ) — instead of [TypeAccessToken], for an
// authorization server that types its access tokens otherwise, typically
// [TypeJWT]. Such tokens are told apart from OpenID Connect ID Tokens of the
// same issuer by their audience only (RFC 8725 §3.12): this is safe only
// when the verifier's audience is never the client_id of a client of that
// issuer — an application registered as both the client and the API, whose
// ID Tokens carry its own ID as aud, does not qualify. An untyped token is
// never accepted. An empty typ panics.
func WithAccessTokenType(typ string) BearerOption {
	if typ == "" {
		panic("jwtsec.WithAccessTokenType: empty type")
	}

	return func(c *bearerConfig) { c.typ = typ }
}

// BearerVerifier adapts a JWT [Verifier] to the [bearer.TokenVerifier]
// contract as an RFC 9068 §4 resource server: the returned TokenVerifier
// produces an authenticated [bearer.Authentication] whose principal is the
// JWT `sub` claim and whose authorities are the values returned by the
// resolver ([DefaultAuthorityResolver] when nil).
//
// RFC 9068 §4 requires the resource server to check the token's typ
// (at+jwt), iss and aud, and that the current time is before exp, so
// BearerVerifier panics unless v was built by [NewVerifier] with
// [WithIssuer], a non-empty [WithAudience] and [WithType]([TypeAccessToken])
// — or the type named by [WithAccessTokenType] — and without
// [WithOptionalExpiry]. A verifier of another implementation cannot be
// inspected and is refused: wrap it in your own bearer.VerifierFunc. A
// token without sub (RFC 9068 §2.2: REQUIRED) is refused with
// [ErrInvalidClaims].
func BearerVerifier(v Verifier, resolver AuthorityResolver, opts ...BearerOption) bearer.TokenVerifier {
	cfg := bearerConfig{typ: TypeAccessToken}
	for _, o := range opts {
		o(&cfg)
	}

	checkResourceServer(v, cfg.typ)

	if resolver == nil {
		resolver = DefaultAuthorityResolver
	}

	return bearer.VerifierFunc(func(ctx context.Context, token string) (security.Authentication, error) {
		claims, err := v.Verify(ctx, token, nil)
		if err != nil {
			return nil, err //nolint:wrapcheck // verifier already wraps with sentinels
		}

		if claims.Subject == "" {
			return nil, fmt.Errorf("%w: sub is required (RFC 9068 §2.2)", ErrInvalidClaims)
		}

		principal := claimPrincipal{sub: claims.Subject}
		authorities := resolver(claims)

		return bearer.New(token).WithAuthenticated(principal, authorities, claims.Subject), nil
	})
}

// checkResourceServer panics unless v applies the RFC 9068 §4 checks with
// the access-token type typ.
func checkResourceServer(v Verifier, typ string) {
	vv, ok := v.(*verifier)

	switch {
	case !ok || vv == nil:
		panic("jwtsec.BearerVerifier: the verifier must be built by NewVerifier")
	case vv.cfg.issuer == "":
		panic("jwtsec.BearerVerifier: the verifier needs WithIssuer (RFC 9068 §4)")
	case len(vv.cfg.audiences) == 0:
		panic("jwtsec.BearerVerifier: the verifier needs WithAudience (RFC 9068 §4)")
	case !typeMatches(typ, vv.cfg.typ):
		panic("jwtsec.BearerVerifier: the verifier needs WithType(TypeAccessToken), or WithAccessTokenType naming its type (RFC 9068 §4)")
	case !vv.cfg.requireExpiry:
		panic("jwtsec.BearerVerifier: the verifier must require exp (RFC 9068 §2.2, §4): drop WithOptionalExpiry")
	}
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
