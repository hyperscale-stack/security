// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// Signer produces signed JWS tokens.
type Signer interface {
	// Sign serializes claims to JSON and signs them with the active key
	// configured at construction time. claims MAY be a [StandardClaims]
	// value, a struct embedding it, or any json-marshalable type.
	Sign(ctx context.Context, claims any) (string, error)

	// Algorithm returns the JOSE alg used by this signer.
	Algorithm() Algorithm

	// KeyID returns the kid attached to the active key (if any). Verifiers
	// rely on the header kid to select the right key from a JWKS.
	KeyID() string
}

// NewSigner returns a Signer using the supplied PrivateKey. The key's
// Algorithm MUST be non-empty; the function panics otherwise to refuse a
// silently-misconfigured signer.
func NewSigner(active PrivateKey, _ ...Option) Signer {
	if active.Algorithm == "" {
		panic("jwtsec.NewSigner: PrivateKey.Algorithm is required")
	}

	if active.Key == nil {
		panic("jwtsec.NewSigner: PrivateKey.Key is required")
	}

	return &signer{key: active}
}

type signer struct {
	key PrivateKey
}

// Algorithm implements [Signer].
func (s *signer) Algorithm() Algorithm { return s.key.Algorithm }

// KeyID implements [Signer].
func (s *signer) KeyID() string { return s.key.KeyID }

// Sign implements [Signer].
func (s *signer) Sign(ctx context.Context, claims any) (string, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "jwtsec.Signer.Sign")
	defer span.End()

	span.SetAttributes(
		attribute.String("jwt.alg", string(s.key.Algorithm)),
		attribute.String("jwt.kid", s.key.KeyID),
	)

	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("jwt: context canceled: %w", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt: marshal claims: %w", err)
	}

	jwk := s.key.toJOSE()

	jws, err := jose.NewSigner(
		jose.SigningKey{Algorithm: s.key.Algorithm.joseAlg(), Key: jwk},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("jwt: new signer: %w", err)
	}

	signed, err := jws.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}

	out, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("jwt: serialize: %w", err)
	}

	return out, nil
}

// Unwrap-aware helper for the unused errors import in this file.
var _ = errors.Is
