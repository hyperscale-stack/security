// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security"
)

// Sentinel errors. Every JWT validation failure wraps one of these so the
// HTTP / gRPC error mappers can produce the right RFC 6750 / RFC 7519
// status code without parsing message strings.
var (
	// ErrInvalidSignature signals that the JWS signature did not match the
	// payload (corrupted token, wrong key). Wraps [security.ErrInvalidCredentials].
	ErrInvalidSignature = newJWTError("invalid signature", security.ErrInvalidCredentials)

	// ErrInvalidIssuer signals that the `iss` claim does not match the
	// configured allowlist.
	ErrInvalidIssuer = newJWTError("invalid issuer", security.ErrInvalidCredentials)

	// ErrInvalidAudience signals that none of the `aud` values match the
	// configured allowlist.
	ErrInvalidAudience = newJWTError("invalid audience", security.ErrInvalidCredentials)

	// ErrTokenExpired signals that the `exp` claim is in the past
	// (allowing for the configured clock skew). Wraps
	// [security.ErrTokenExpired].
	ErrTokenExpired = newJWTError("token expired", security.ErrTokenExpired)

	// ErrMissingExpiry signals that the token carries no `exp` claim while
	// the verifier requires one — the default; see [WithOptionalExpiry].
	// Wraps [security.ErrTokenExpired] so transport mappers classify a
	// non-expiring token like any other temporally-invalid token.
	ErrMissingExpiry = newJWTError("missing exp claim", security.ErrTokenExpired)

	// ErrTokenNotYetValid signals that the `nbf` claim is in the future
	// (allowing for the configured clock skew).
	ErrTokenNotYetValid = newJWTError("token not yet valid", security.ErrInvalidCredentials)

	// ErrAlgorithmNotAllowed signals that the token's `alg` header is not in
	// the configured allowlist. The canonical defense against the "alg=none"
	// and "RSA public key as HMAC secret" key-confusion attacks.
	ErrAlgorithmNotAllowed = newJWTError("algorithm not allowed", security.ErrInvalidCredentials)

	// ErrMalformedToken signals that the input string is not a parseable
	// JWS structure (wrong dot count, bad base64, ...).
	ErrMalformedToken = newJWTError("malformed token", security.ErrInvalidCredentials)
)

// newJWTError builds a sentinel that wraps a core security sentinel via
// fmt.Errorf %w so errors.Is bridges both layers transparently.
func newJWTError(msg string, parent error) error {
	return fmt.Errorf("jwt: %s: %w", msg, parent)
}

// errAlgorithmDisallowed augments [ErrAlgorithmNotAllowed] with the offending
// algorithm so server-side telemetry can pinpoint suspicious clients without
// surfacing the value to the response.
type errAlgorithmDisallowed struct {
	alg string
}

func (e *errAlgorithmDisallowed) Error() string {
	return fmt.Sprintf("jwt: algorithm %q not allowed", e.alg)
}

// Unwrap exposes the sentinel chain for errors.Is.
func (e *errAlgorithmDisallowed) Unwrap() error { return ErrAlgorithmNotAllowed }

// AsAlgorithmName extracts the disallowed algorithm name from err, returning
// (name, true) when err is a [errAlgorithmDisallowed] instance.
func AsAlgorithmName(err error) (string, bool) {
	var e *errAlgorithmDisallowed
	if errors.As(err, &e) {
		return e.alg, true
	}

	return "", false
}
