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

	// ErrInvalidType signals a token whose "typ" header is absent or not the
	// type the verifier requires (see [WithType]) — e.g. an OpenID Connect
	// ID Token presented as an RFC 9068 access token (RFC 9068 §4).
	ErrInvalidType = newJWTError("invalid token type", security.ErrInvalidCredentials)

	// ErrInvalidKey signals a key unfit for its use: not the public — or
	// private — key its algorithm takes, too short, on another curve, an
	// HMAC secret where a public key is required, a missing or repeated kid
	// in a JWK Set (see [PublicKey.Validate], [PrivateKey.Validate],
	// [MarshalJWKS]). The key material never appears in the error.
	ErrInvalidKey = newJWTError("invalid key", security.ErrInvalidCredentials)

	// ErrInvalidClaims signals a well-formed, verified token whose claims
	// the verifier refuses: [BearerVerifier] requires a non-empty sub, the
	// principal (RFC 9068 §2.2). Wraps [security.ErrInvalidCredentials].
	ErrInvalidClaims = newJWTError("invalid claims", security.ErrInvalidCredentials)

	// ErrUnsignableClaims signals claims a signer refuses to sign: claims
	// that cannot be encoded — a [NumericDate] before 1970 or after year
	// 9999, the zero time.Time included — or, for the RFC 9068 access
	// tokens of [OAuth2AccessTokenSigner], a REQUIRED claim missing or
	// empty (RFC 9068 §2.2). Nothing is signed. A server-side error, not a
	// credential failure: it wraps no security sentinel.
	ErrUnsignableClaims = errors.New("jwt: unsignable claims")

	// ErrKeySetUnavailable signals that no usable verification key set
	// could be obtained: a remote JWK Set never fetched, or older than
	// [MaxKeySetStaleness] while refreshes fail, a [JWKSProvider] failing,
	// the caller's context ending while it waits for a fetch. An
	// infrastructure failure, not a credential one: it wraps
	// [security.ErrUnavailable] and no credential sentinel, so transports
	// answer it with 503 / Unavailable, never as an invalid token.
	ErrKeySetUnavailable = newJWTError("key set unavailable", security.ErrUnavailable)
)

// newJWTError builds a sentinel that wraps a core security sentinel via
// fmt.Errorf %w so errors.Is bridges both layers transparently.
func newJWTError(msg string, parent error) error {
	return fmt.Errorf("jwt: %s: %w", msg, parent)
}

// errAlgorithmDisallowed augments [ErrAlgorithmNotAllowed] with the offending
// algorithm — clipped, it comes from the token — so server-side telemetry
// can pinpoint suspicious clients without surfacing the value to the
// response.
type errAlgorithmDisallowed struct {
	alg string
}

func (e *errAlgorithmDisallowed) Error() string {
	return fmt.Sprintf("jwt: algorithm %q not allowed", e.alg)
}

// Unwrap exposes the sentinel chain for errors.Is.
func (e *errAlgorithmDisallowed) Unwrap() error { return ErrAlgorithmNotAllowed }

// AsAlgorithmName extracts the disallowed algorithm name — at most 128
// bytes of it — from an [ErrAlgorithmNotAllowed] error returned by a
// [Verifier] or [VerifySignature]: (name, true), or ("", false) for any
// other error.
func AsAlgorithmName(err error) (string, bool) {
	var e *errAlgorithmDisallowed
	if errors.As(err, &e) {
		return e.alg, true
	}

	return "", false
}
