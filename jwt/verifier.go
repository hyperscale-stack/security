// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"errors"
	"fmt"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Verifier parses and validates a compact-serialized JWT, returning the
// decoded standard claims and decoding the payload into a caller-specific
// claims type.
type Verifier interface {
	// Verify parses token, validates the signature against the JWKS, runs
	// the iss/aud/exp/nbf checks per the configured Options, and decodes
	// the payload into claimsOut — case-sensitively, by go-jose's decoder:
	// give its fields their exact claim names as json tags, and no
	// encoding/json.Number field. claimsOut MAY be nil when the caller only
	// needs the standard claims (returned separately); its content is
	// unspecified when Verify fails.
	Verify(ctx context.Context, token string, claimsOut any) (*StandardClaims, error)
}

// NewVerifier returns a Verifier sourcing keys from provider. Defaults:
// asymmetric algorithm allowlist (HS* opt-in only), tokens of at most
// DefaultMaxTokenSize bytes, exp required, no issuer / audience / type
// pinning (BearerVerifier requires them), no clock skew, wall clock.
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

	std, err := v.verify(ctx, span, token, claimsOut)
	if err != nil {
		// Every error is bounded: token-supplied values are clipped.
		span.RecordError(err)

		return nil, err
	}

	span.SetAttributes(attribute.String("jwt.iss", clip(std.Issuer)))

	return std, nil
}

// verify runs the checks of Verify in order — parse, type, key, signature,
// claims — setting the span's attributes and its status on failure.
func (v *verifier) verify(ctx context.Context, span trace.Span, token string, claimsOut any) (*StandardClaims, error) {
	parsed, header, err := parseCompact(token, v.cfg.allowed, v.cfg.maxTokenSize)
	if err != nil {
		if alg, ok := AsAlgorithmName(err); ok {
			span.SetAttributes(attribute.String("jwt.alg", alg))
		}

		span.SetStatus(codes.Error, "parse")

		return nil, err
	}

	alg := Algorithm(header.Algorithm)
	span.SetAttributes(
		attribute.String("jwt.alg", string(alg)),
		attribute.String("jwt.kid", clip(header.KeyID)),
	)

	// An explicitly typed token is refused under another type (RFC 8725
	// §3.11, RFC 9068 §4); the header is protected by the signature checked
	// below, so a forged type cannot pass either.
	if v.cfg.typ != "" && !typeMatches(v.cfg.typ, headerType(header)) {
		span.SetStatus(codes.Error, "typ")

		return nil, ErrInvalidType
	}

	pub, err := v.key(ctx, header.KeyID, alg)
	if err != nil {
		span.SetStatus(codes.Error, "kid")

		return nil, err
	}

	payload, err := parsed.Verify(pub.toJOSE())
	if err != nil {
		span.SetStatus(codes.Error, "signature")

		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, clippedError{err: err})
	}

	return v.claims(span, payload, claimsOut)
}

// key returns the verification key the token's kid designates, bound to
// alg (see bindKey). An unknown kid makes a provider that can refresh
// (the remote JWK Set) fetch its set again, at most once per
// MinKeySetRefreshInterval (key rotation, OpenID Connect Core §10.1.1);
// a known kid never does.
func (v *verifier) key(ctx context.Context, kid string, alg Algorithm) (PublicKey, error) {
	keys, err := v.provider.KeySet(ctx)
	if err != nil || keys == nil {
		return PublicKey{}, keySetUnavailable(err)
	}

	pub, ok := keys.ByKeyID(kid)
	if !ok && kid != "" {
		if r, canRefresh := v.provider.(keyRefresher); canRefresh {
			if keys, err = r.refreshKeySet(ctx); err != nil {
				return PublicKey{}, keySetUnavailable(err)
			}

			pub, ok = keys.ByKeyID(kid)
		}
	}

	if !ok {
		return PublicKey{}, fmt.Errorf("%w: no single key for kid %q", ErrInvalidSignature, clip(kid))
	}

	pub.Algorithm = boundAlgorithm(pub, v.cfg.allowed)

	if err := bindKey(pub, alg); err != nil {
		return PublicKey{}, err
	}

	return pub, nil
}

// keySetUnavailable wraps a key set failure in ErrKeySetUnavailable.
func keySetUnavailable(err error) error {
	switch {
	case err == nil:
		return fmt.Errorf("%w: the provider returned no key set", ErrKeySetUnavailable)
	case errors.Is(err, ErrKeySetUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrKeySetUnavailable, err)
	}
}

// claims decodes the verified payload — strictly, see decodeClaims — runs
// the standard claim checks and decodes claimsOut.
func (v *verifier) claims(span trace.Span, payload []byte, claimsOut any) (*StandardClaims, error) {
	std, err := decodeClaims(payload)
	if err != nil {
		span.SetStatus(codes.Error, "unmarshal")

		return nil, fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}

	if err := validateStandardClaims(v.cfg, std); err != nil {
		span.SetStatus(codes.Error, "claims")

		return nil, err
	}

	if claimsOut != nil {
		// The payload passed validateJSON in decodeClaims: decode it into
		// the caller's type with the same exact name matching.
		if err := unmarshalExact(payload, claimsOut); err != nil {
			span.SetStatus(codes.Error, "unmarshal")

			return nil, fmt.Errorf("%w: %w", ErrMalformedToken, err)
		}
	}

	return std, nil
}

// headerType returns the "typ" header parameter, "" when absent or not a
// string.
func headerType(h jose.Header) string {
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)

	return typ
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
