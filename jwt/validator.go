// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"fmt"
	"slices"
	"time"
)

// validateStandardClaims runs the issuer / audience / exp / nbf checks per
// RFC 7519 §4.1, observing the configured clock skew. iat is informational
// (no rejection) but tokens with iat in the future beyond the skew window
// are refused as a defense against tokens forged with a tampered clock.
//
// An `exp` claim is mandatory unless the verifier opted into
// [WithOptionalExpiry]: a token that never expires is rejected fail-closed.
func validateStandardClaims(c *config, claims *StandardClaims) error {
	now := c.clock.Now()

	if c.issuer != "" && claims.Issuer != c.issuer {
		return fmt.Errorf("%w: have %q, want %q", ErrInvalidIssuer, claims.Issuer, c.issuer)
	}

	if len(c.audiences) > 0 {
		if !audienceMatches(c.audiences, claims.Audience) {
			return fmt.Errorf("%w: have %v, want one of %v",
				ErrInvalidAudience, []string(claims.Audience), c.audiences)
		}
	}

	if claims.ExpiresAt == nil {
		if c.requireExpiry {
			return ErrMissingExpiry
		}
	} else {
		exp := claims.ExpiresAt.Time()
		if !exp.IsZero() && now.After(exp.Add(c.skew)) {
			return fmt.Errorf("%w (now=%s exp=%s)", ErrTokenExpired,
				now.Format(time.RFC3339), exp.Format(time.RFC3339))
		}
	}

	if claims.NotBefore != nil {
		nbf := claims.NotBefore.Time()
		if !nbf.IsZero() && now.Before(nbf.Add(-c.skew)) {
			return fmt.Errorf("%w (now=%s nbf=%s)", ErrTokenNotYetValid,
				now.Format(time.RFC3339), nbf.Format(time.RFC3339))
		}
	}

	if claims.IssuedAt != nil {
		iat := claims.IssuedAt.Time()
		if !iat.IsZero() && iat.After(now.Add(c.skew)) {
			return fmt.Errorf("%w (now=%s iat=%s)", ErrTokenNotYetValid,
				now.Format(time.RFC3339), iat.Format(time.RFC3339))
		}
	}

	return nil
}

// audienceMatches reports whether at least one element of the token's aud
// matches one of the configured audiences.
func audienceMatches(configured []string, token Audience) bool {
	for _, a := range token {
		if slices.Contains(configured, a) {
			return true
		}
	}

	return false
}
