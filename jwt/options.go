// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"slices"
	"strings"
	"time"

	"github.com/hyperscale-stack/security"
)

// Option configures a [Signer] or a [Verifier].
type Option func(*config)

type config struct {
	// typ is the "typ" header: written by a signer, required by a
	// verifier (see WithType).
	typ           string
	allowed       []Algorithm
	issuer        string
	audiences     []string
	skew          time.Duration
	clock         security.Clock
	requireExpiry bool
	maxTokenSize  int
}

// defaults seeds the verifier configuration with the strict baseline:
// asymmetric algorithms only, no issuer / audience restriction (the user
// MUST opt-in), zero clock skew, and a mandatory `exp` claim.
func defaults() *config {
	return &config{
		allowed:       slices.Clone(defaultAllowedAlgorithms),
		clock:         security.DefaultClock,
		requireExpiry: true,
		maxTokenSize:  DefaultMaxTokenSize,
	}
}

// WithAllowedAlgorithms overrides the algorithm allowlist. Passing zero
// algorithms is invalid and panics at construction time: a verifier that
// accepts every algorithm is the gateway to the "alg=none" family of
// attacks.
func WithAllowedAlgorithms(algs ...Algorithm) Option {
	if len(algs) == 0 {
		panic("jwtsec.WithAllowedAlgorithms: empty list")
	}

	return func(c *config) { c.allowed = slices.Clone(algs) }
}

// WithIssuer pins the expected `iss` claim. Empty issuer disables the check
// (the default), which is acceptable only when the verifier sits behind a
// trust boundary that already authenticates the issuer.
func WithIssuer(iss string) Option {
	return func(c *config) { c.issuer = iss }
}

// WithAudience pins the expected `aud` claim values. At verification time
// the token is accepted when AT LEAST ONE of its audiences is in the list.
// Passing zero audiences disables the check.
func WithAudience(aud ...string) Option {
	return func(c *config) { c.audiences = slices.Clone(aud) }
}

// WithClockSkew tolerates the given amount of clock drift on `exp` and
// `nbf` comparisons. Recommended values: 30s–2min for inter-service hops.
func WithClockSkew(d time.Duration) Option {
	return func(c *config) {
		if d < 0 {
			d = 0
		}

		c.skew = d
	}
}

// DefaultMaxTokenSize is the largest token, in bytes of its compact
// serialization, a [Verifier] and [VerifySignature] accept by default:
// 16 KiB. A token over the bound is refused with [ErrMalformedToken]
// before anything is decoded — without it, a header of small members made
// go-jose allocate about 100 times the token's size before any check.
//
// The bound holds the largest tokens in common use — an Entra ID token
// carrying its maximum of 200 group IDs is 11–13 KB, Keycloak tokens with
// many roles 6–12 KB — and matches the single-header limit of common front
// ends (Node.js, AWS ALB, IIS: 16 KiB; nginx and Apache: 8 KiB by
// default). Lower it with [WithMaxTokenSize]; cap the transports too
// (http.Server.MaxHeaderBytes, grpc.MaxHeaderListSize).
const DefaultMaxTokenSize = 16 << 10

// WithMaxTokenSize sets the largest token, in bytes of its compact
// serialization, a [Verifier] parses (default [DefaultMaxTokenSize]); a
// longer token is refused with [ErrMalformedToken] before any decoding.
// Signers ignore it. n < 1 panics.
func WithMaxTokenSize(n int) Option {
	if n < 1 {
		panic("jwtsec.WithMaxTokenSize: the bound must be positive")
	}

	return func(c *config) { c.maxTokenSize = n }
}

// WithClock injects a clock for deterministic tests. Defaults to
// [security.DefaultClock] (wall clock).
func WithClock(c security.Clock) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.clock = c
		}
	}
}

// WithOptionalExpiry allows tokens without an `exp` claim. By default the
// verifier rejects them with [ErrMissingExpiry] (fail-closed): a token that
// never expires cannot be invalidated by time and, if leaked, stays valid
// forever. RFC 9068 §2.2 also makes `exp` REQUIRED for JWT access tokens.
//
// Enable this only for general-purpose JWT verification where non-expiring
// assertions are an expected, deliberate part of the design.
func WithOptionalExpiry() Option {
	return func(c *config) { c.requireExpiry = false }
}

// The "typ" header values this package knows (RFC 7515 §4.1.9).
const (
	// TypeJWT is the generic JWT type (RFC 7519 §5.1): the default of
	// [NewSigner], and the type OpenID Connect ID Tokens carry.
	TypeJWT = "JWT"
	// TypeAccessToken is the explicit type of an RFC 9068 JWT access token
	// (RFC 9068 §2.1): it tells an access token apart from an ID Token,
	// which a resource server MUST refuse (RFC 9068 §4, RFC 8725 §3.11).
	TypeAccessToken = "at+jwt"
)

// WithType sets the JWT's explicit type — the "typ" header (RFC 7515
// §4.1.9, RFC 8725 §3.11). On a [Signer] it is the value written (default
// [TypeJWT]). On a [Verifier] it is required: a token whose typ is absent
// or another type is refused with [ErrInvalidType]; the comparison follows
// RFC 7515 §4.1.9 — media types are case-insensitive, and a value without
// "/" reads as if "application/" were prepended — so a verifier requiring
// [TypeAccessToken] accepts "at+jwt" and "application/at+jwt" (RFC 9068
// §4). Without it, a verifier ignores typ. An empty typ panics.
func WithType(typ string) Option {
	if typ == "" {
		panic("jwtsec.WithType: empty type")
	}

	return func(c *config) { c.typ = typ }
}

// typeMatches reports whether the typ header got denotes the media type
// want (RFC 7515 §4.1.9). An absent typ matches nothing.
func typeMatches(want, got string) bool {
	return got != "" && normalizeType(want) == normalizeType(got)
}

// normalizeType returns the full, lower-cased media type of a typ value.
func normalizeType(typ string) string {
	typ = strings.ToLower(typ)
	if !strings.Contains(typ, "/") {
		typ = "application/" + typ
	}

	return typ
}
