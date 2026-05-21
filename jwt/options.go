// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"slices"
	"time"

	"github.com/hyperscale-stack/security"
)

// Option configures a [Signer] or a [Verifier].
type Option func(*config)

type config struct {
	allowed       []Algorithm
	issuer        string
	audiences     []string
	skew          time.Duration
	clock         security.Clock
	requireExpiry bool
}

// defaults seeds the verifier configuration with the strict baseline:
// asymmetric algorithms only, no issuer / audience restriction (the user
// MUST opt-in), zero clock skew, and a mandatory `exp` claim.
func defaults() *config {
	return &config{
		allowed:       slices.Clone(defaultAllowedAlgorithms),
		clock:         security.DefaultClock,
		requireExpiry: true,
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

// algorithmAllowed reports whether alg appears in the allowlist.
func (c *config) algorithmAllowed(alg Algorithm) bool {
	return slices.Contains(c.allowed, alg)
}
