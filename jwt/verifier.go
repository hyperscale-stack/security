// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// Verifier parses and validates a compact-serialized JWT, returning the
// decoded standard claims plus the raw payload for caller-specific claim
// decoding.
type Verifier interface {
	// Verify parses token, validates the signature against the JWKS, runs
	// the iss/aud/exp/nbf checks per the configured Options, and
	// unmarshals the payload into claimsOut. claimsOut MAY be nil when the
	// caller only needs the standard claims (returned separately).
	Verify(ctx context.Context, token string, claimsOut any) (*StandardClaims, error)
}

// NewVerifier returns a Verifier sourcing keys from provider. Defaults:
// asymmetric algorithm allowlist (HS* opt-in only), no issuer / audience
// pinning, no clock skew, wall clock.
func NewVerifier(provider JWKSProvider, opts ...Option) Verifier {
	cfg := defaults()
	for _, o := range opts {
		o(cfg)
	}

	return &verifier{provider: provider, cfg: cfg}
}

type verifier struct {
	provider JWKSProvider
	cfg      *config
}

// Verify implements [Verifier].
func (v *verifier) Verify(ctx context.Context, token string, claimsOut any) (*StandardClaims, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "jwtsec.Verifier.Verify")
	defer span.End()

	parsed, err := jose.ParseSignedCompact(token, joseAllowed(v.cfg.allowed))
	if err != nil {
		span.SetStatus(codes.Error, "parse")
		span.RecordError(err)

		return nil, fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}

	if len(parsed.Signatures) != 1 {
		err := fmt.Errorf("%w: expected exactly one signature", ErrMalformedToken)

		span.SetStatus(codes.Error, "multi-sig")

		return nil, err
	}

	header := parsed.Signatures[0].Header
	alg := Algorithm(header.Algorithm)
	span.SetAttributes(
		attribute.String("jwt.alg", string(alg)),
		attribute.String("jwt.kid", header.KeyID),
	)

	if !v.cfg.algorithmAllowed(alg) {
		// errAlgorithmDisallowed wraps ErrAlgorithmNotAllowed and keeps the
		// offending alg reachable via AsAlgorithmName for telemetry.
		err := &errAlgorithmDisallowed{alg: string(alg)}

		span.SetStatus(codes.Error, "alg")
		span.RecordError(err)

		return nil, err
	}

	keys, err := v.provider.KeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("jwt: load JWKS: %w", err)
	}

	pub, ok := keys.ByKeyID(header.KeyID)
	if !ok {
		err := fmt.Errorf("%w: unknown kid %q", ErrInvalidSignature, header.KeyID)

		span.SetStatus(codes.Error, "kid")
		span.RecordError(err)

		return nil, err
	}

	payload, err := parsed.Verify(pub.toJOSE())
	if err != nil {
		span.SetStatus(codes.Error, "signature")
		span.RecordError(err)

		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	var std StandardClaims
	if err := json.Unmarshal(payload, &std); err != nil {
		span.SetStatus(codes.Error, "unmarshal")

		return nil, fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}

	if err := validateStandardClaims(v.cfg, &std); err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	if claimsOut != nil {
		if err := json.Unmarshal(payload, claimsOut); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedToken, err)
		}
	}

	span.SetAttributes(attribute.String("jwt.iss", std.Issuer))

	return &std, nil
}

// joseAllowed converts the typed allowlist to go-jose's SignatureAlgorithm
// slice so ParseSignedCompact rejects unknown algs without consulting the
// underlying key.
func joseAllowed(in []Algorithm) []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, 0, len(in))

	for _, a := range slices.Clone(in) {
		out = append(out, a.joseAlg())
	}

	return out
}
