// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// VerifiedToken is a JWS whose signature [VerifySignature] verified, and
// nothing else: its claims are as the signer wrote them, unchecked.
type VerifiedToken struct {
	// Algorithm is the "alg" header the signature was verified with.
	Algorithm Algorithm
	// KeyID is the "kid" header; empty when the token names none.
	KeyID string
	// Type is the "typ" header (RFC 7515 §4.1.9); empty when absent.
	Type string
	// Payload is the verified JWS payload — for a JWT, its claims set.
	Payload []byte
}

// VerifySignature verifies the signature of token, a JWS Compact
// Serialization (the JSON serializations are refused), against keys:
// exactly one signature, an "alg" among allowed (the asymmetric default
// allowlist when none is given; "none" can never be allowed), the one key
// of keys whose KeyID equals the token's "kid" — a token without kid only
// against a single-key set — and whose Algorithm, which every key MUST
// set, equals the token's alg (RFC 8725 §3.1: one key, one algorithm).
// The token is parsed under the rules of [Verifier]: at most
// [DefaultMaxTokenSize] bytes of canonical base64url, a strict JSON header
// without the crit or b64 extensions (RFC 7515 §4.1.11, RFC 7797).
//
// IT VALIDATES NO CLAIM — not exp, nbf, iat, iss nor aud — and returns the
// payload undecoded. It is the building block of a caller that validates
// the claims itself because it needs a rule [Verifier] does not apply, e.g.
// an OpenID Provider accepting its own expired ID Token as an
// id_token_hint (OIDC Core §3.1.2.2). Use [Verifier] everywhere else.
//
// Failures wrap [ErrMalformedToken] (oversized, not a canonical compact
// JWS, a refused header), [ErrAlgorithmNotAllowed] (an algorithm outside
// allowed) or [ErrInvalidSignature] (no single key for the kid, a key
// bound to another algorithm, a bad signature); token-supplied values in
// them are clipped.
func VerifySignature(ctx context.Context, token string, keys []PublicKey, allowed ...Algorithm) (*VerifiedToken, error) {
	_, span := otel.Tracer(tracerName).Start(ctx, "jwtsec.VerifySignature")
	defer span.End()

	if len(allowed) == 0 {
		allowed = defaultAllowedAlgorithms
	}

	// The allowlist is enforced here, before any key is consulted.
	parsed, header, err := parseCompact(token, allowed, DefaultMaxTokenSize)
	if err != nil {
		span.SetStatus(codes.Error, "parse")
		span.RecordError(err)

		return nil, err
	}

	alg := Algorithm(header.Algorithm)
	span.SetAttributes(attribute.String("jwt.alg", string(alg)), attribute.String("jwt.kid", clip(header.KeyID)))

	key, err := signatureKey(keys, header.KeyID, alg)
	if err != nil {
		span.SetStatus(codes.Error, "kid")

		return nil, err
	}

	payload, err := parsed.Verify(key.verificationKey())
	if err != nil {
		span.SetStatus(codes.Error, "signature")

		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, clipError(err))
	}

	return &VerifiedToken{Algorithm: alg, KeyID: header.KeyID, Type: headerType(header), Payload: payload}, nil
}

// signatureKey returns the one key of keys that may verify a signature by
// kid with alg (see bindKey).
func signatureKey(keys []PublicKey, kid string, alg Algorithm) (PublicKey, error) {
	candidates := keys
	if kid != "" {
		candidates = nil

		for _, k := range keys {
			if k.KeyID == kid {
				candidates = append(candidates, k)
			}
		}
	}

	if len(candidates) != 1 {
		return PublicKey{}, fmt.Errorf("%w: no single key for the token's kid", ErrInvalidSignature)
	}

	// A parsed alg is never empty: a key without Algorithm never matches.
	if err := bindKey(candidates[0], alg); err != nil {
		return PublicKey{}, err
	}

	return candidates[0], nil
}
