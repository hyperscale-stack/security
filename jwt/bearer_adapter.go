// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

// AuthorityResolver maps the parsed standard claims to the authorities
// attached to the resulting [security.Authentication]. The default resolver
// (when none is provided) splits StandardClaims.Scope on spaces and prefixes
// each entry with "scope:" so the voter package recognizes them. A resolver
// granting authorities by client keys them on claims.ClientID, never on
// Subject: a client_credentials token's sub is its client ID, which a
// resource owner's sub may equal (RFC 9700 §4.15).
type AuthorityResolver func(claims *StandardClaims) []string

// BearerOption configures [BearerVerifier].
type BearerOption func(*bearerConfig)

type bearerConfig struct {
	typ    string           // the access-token type the verifier must require
	active ActiveTokenCheck // optional, see WithActiveTokenCheck
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

// ActiveTokenCheck reports whether an access token [BearerVerifier] has
// verified — signature, typ, iss, aud, exp and sub — is still active at
// the authorization server: nil accepts it, an error refuses it. It is the
// backend interaction RFC 7009 §3 leaves to implementations for the
// immediate revocation of self-contained tokens: a revocation in the
// authorization server's store (RFC 7009 §2.1, a token family revoked on a
// replayed code or refresh token) otherwise reaches a resource server only
// when the token expires.
//
// It receives the raw token and its claims. Answer active only for a token
// found active — the string the authorization server issued, looked up in
// its store, or RFC 7662 introspection answering "active": true — and
// never through a deny-list of token strings: a token string is not unique
// (an ECDSA signature has a second valid form), so a deny-listed token's
// twin would pass. With a store shared with the oauth2 module, look the
// token up by oauth2.HashToken(nil, token) with LookupAccessToken: an
// invalid_grant *oauth2.Error means inactive; any other error means the
// check could not be made.
//
// Errors: wrap [security.ErrUnavailable] when the check could not be made
// (the store or the introspection endpoint is down) — BearerVerifier then
// fails with security.ErrUnavailable (503 / Unavailable), as it does when
// the context ends; any other error refuses the token as
// [ErrTokenInactive] (401 invalid_token). The error text travels with the
// returned error: never put the token in it.
type ActiveTokenCheck func(ctx context.Context, token string, claims *StandardClaims) error

// WithActiveTokenCheck makes [BearerVerifier] call check for every token
// that passed all its other verifications, before resolving authorities;
// without it a verified token is accepted until it expires. The call runs
// in a jwtsec.BearerVerifier.ActiveTokenCheck span. A nil check panics.
func WithActiveTokenCheck(check ActiveTokenCheck) BearerOption {
	if check == nil {
		panic("jwtsec.WithActiveTokenCheck: nil check")
	}

	return func(c *bearerConfig) { c.active = check }
}

// BearerVerifier adapts a JWT [Verifier] to the [bearer.TokenVerifier]
// contract as an RFC 9068 §4 resource server: the returned TokenVerifier
// produces an authenticated [bearer.Authentication] whose principal is an
// [AccessTokenPrincipal] — the JWT `sub` and `client_id` claims — and whose
// authorities are the values returned by the resolver
// ([DefaultAuthorityResolver] when nil).
//
// RFC 9068 §4 requires the resource server to check the token's typ
// (at+jwt), iss and aud, and that the current time is before exp, so
// BearerVerifier panics unless v was built by [NewVerifier] with
// [WithIssuer], a non-empty [WithAudience] and [WithType]([TypeAccessToken])
// — or the type named by [WithAccessTokenType] — and without
// [WithOptionalExpiry]. A verifier of another implementation cannot be
// inspected and is refused: wrap it in your own bearer.VerifierFunc. A
// token without sub (RFC 9068 §2.2: REQUIRED) is refused with
// [ErrInvalidClaims]. A token is accepted until it expires, unless
// [WithActiveTokenCheck] asks the authorization server.
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

		if cfg.active != nil {
			if err := checkActive(ctx, cfg.active, token, claims); err != nil {
				return nil, err
			}
		}

		principal := AccessTokenPrincipal{subject: claims.Subject, clientID: claims.ClientID}
		authorities := resolver(claims)

		return bearer.New(token).WithAuthenticated(principal, authorities, claims.Subject), nil
	})
}

// checkActive runs check in its own span, which records the error class
// only — the error text may carry the check's input. A check that could
// not be made — an error wrapping security.ErrUnavailable, or the context
// ending — fails with security.ErrUnavailable; any other error with
// ErrTokenInactive.
func checkActive(ctx context.Context, check ActiveTokenCheck, token string, claims *StandardClaims) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "jwtsec.BearerVerifier.ActiveTokenCheck")
	defer span.End()

	err := check(ctx, token, claims)
	if err == nil {
		return nil
	}

	if errors.Is(err, security.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("jwt: active token check: %w: %w", security.ErrUnavailable, err)
	} else {
		err = fmt.Errorf("%w: %w", ErrTokenInactive, err)
	}

	class := security.ErrorClass(err)
	span.SetStatus(codes.Error, class)
	span.SetAttributes(security.AttrErrorType.String(class))

	return err
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

// AccessTokenPrincipal is the [security.Principal] of an access token
// [BearerVerifier] accepted: its `sub` and `client_id` claims (RFC 9068
// §2.2). Read it with a type assertion on Authentication.Principal(). An
// immutable value: the zero value designates no subject and no client.
type AccessTokenPrincipal struct {
	subject  string
	clientID string
}

// Subject implements [security.Principal]: the `sub` claim — a resource
// owner, or, for a token no resource owner is involved in
// (client_credentials), the client itself (RFC 9068 §2.2).
func (p AccessTokenPrincipal) Subject() string { return p.subject }

// ClientID returns the `client_id` claim — the client the token was issued
// to (RFC 8693 §4.3) — or "" when the token carries none.
func (p AccessTokenPrincipal) ClientID() string { return p.clientID }

// SubjectIsClient reports whether the token's subject is its client — sub
// equals a non-empty client_id —, as in the client_credentials tokens of
// this module's authorization server (oauth2's grant.ClientCredentials) and
// of the others that follow RFC 9068 §2.2 to the letter (e.g. Amazon
// Cognito). A client registered with an ID equal to a user's subject then
// cannot be served that user's resources (RFC 9700 §4.15): refuse
// resource-owner access when it is true.
//
// Use it to refuse, never to grant. A resource owner whose subject equals
// the ID of the very client they use also reports true, so grant client
// privileges by client_id and scope authorities, not by this method; and an
// authorization server whose client tokens carry another sub (Keycloak's
// service-account user, Auth0's "…@clients", Okta, Microsoft Entra ID)
// always reports false — such servers keep client and user identifiers
// disjoint, which RFC 9700 §4.15.1 asks of any server letting clients
// choose their ID.
func (p AccessTokenPrincipal) SubjectIsClient() bool {
	return p.clientID != "" && p.subject == p.clientID
}
