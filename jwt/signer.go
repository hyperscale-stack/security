// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"encoding/json"
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

	// KeyID returns the kid of the active key (if any), which every token
	// carries as its "kid" header — HMAC tokens included (RFC 7515
	// §4.1.4): verifiers select the key of a multi-key set by it.
	KeyID() string
}

// NewSigner returns a Signer using the supplied PrivateKey, or, wrapping
// [ErrInvalidKey], why the key cannot sign with its Algorithm (RFC 7518
// §3.2-§3.5, RFC 8725 §3.5). Accepted keys:
//   - an *rsa.PrivateKey of 2048 to 4096 bits for RS*/PS*, an
//     *ecdsa.PrivateKey on the algorithm's curve for ES*, an
//     ed25519.PrivateKey for EdDSA (see [PrivateKey.Validate]);
//   - a jose.OpaqueSigner — a KMS or HSM key, e.g. through go-jose's
//     cryptosigner.Opaque — that offers the algorithm and whose public half
//     passes [PublicKey.Validate], an RSA one of at most 4096 bits;
//   - a jose.JSONWebKey, or a pointer to one, holding one of the above;
//   - for HS256 / HS384 / HS512, a []byte secret of at least 32 / 48 / 64
//     bytes.
//
// Of the options, a signer honors [WithType] only — the "typ" header it
// writes, [TypeJWT] by default; the others configure verifiers and are
// ignored. A Signer checks no claim: [OAuth2AccessTokenSigner] signs RFC
// 9068 access tokens.
func NewSigner(active PrivateKey, opts ...Option) (Signer, error) {
	if err := validateSigningKey(active); err != nil {
		return nil, err
	}

	cfg := &config{typ: TypeJWT}
	for _, o := range opts {
		o(cfg)
	}

	return &signer{key: active, typ: cfg.typ}, nil
}

type signer struct {
	key PrivateKey
	typ string
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
		return "", fmt.Errorf("%w: %w", ErrUnsignableClaims, err)
	}

	jws, err := jose.NewSigner(
		jose.SigningKey{Algorithm: s.key.Algorithm.joseAlg(), Key: s.key.toJOSE()},
		s.options(),
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

// options returns the JOSE header the signer writes besides alg: typ and,
// when the key has a KeyID, kid (RFC 7515 §4.1.4) — written explicitly,
// since go-jose writes it from a key's public half only and an HMAC secret
// has none; for the other keys it is the value go-jose would write.
func (s *signer) options() *jose.SignerOptions {
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(s.typ))
	if s.key.KeyID != "" {
		opts = opts.WithHeader(jose.HeaderKey("kid"), s.key.KeyID)
	}

	return opts
}
