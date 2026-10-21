// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"

	jose "github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
)

// JWK Set bounds.
const (
	// maxJWKSKeys bounds the number of keys of a JWK Set: a larger set is
	// a failed fetch.
	maxJWKSKeys = 100
)

// privateMembers are the JWK members that carry private or symmetric key
// material (RFC 7518 §6.2.2, §6.3.2, §6.4.1): a key publishing one is
// never used.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// errJWKSet reports a JWK Set document the provider refuses as a whole.
var errJWKSet = errors.New("not a JWK Set")

// parseJWKS reads a JWK Set (RFC 7517 §5): strict JSON (see validateJSON),
// a keys member holding at most maxJWKSKeys objects — anything else fails
// the fetch, keeping the previous set. Each key is then judged on its own
// (parseJWK): an unusable key is ignored, the others are kept (RFC 7517
// §5). It returns the usable keys and the number of ignored ones.
func parseJWKS(data []byte) ([]PublicKey, int, error) {
	var set struct {
		Keys []josejson.RawMessage `json:"keys"`
	}

	if err := decodeStrict(data, &set); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errJWKSet, err)
	}

	switch {
	case set.Keys == nil:
		return nil, 0, fmt.Errorf("%w: no keys array", errJWKSet)
	case len(set.Keys) > maxJWKSKeys:
		return nil, 0, fmt.Errorf("%w: more than %d keys", errJWKSet, maxJWKSKeys)
	}

	for _, raw := range set.Keys {
		if jsonKind(raw) != '{' {
			return nil, 0, fmt.Errorf("%w: a key is not a JSON object", errJWKSet)
		}
	}

	keys := make([]PublicKey, 0, len(set.Keys))

	for _, raw := range set.Keys {
		if k, ok := parseJWK(raw); ok {
			keys = append(keys, k)
		}
	}

	return keys, len(set.Keys) - len(keys), nil
}

// parseJWK returns the verification key raw describes, false when it is
// unusable: private or symmetric material, a use other than sig or
// key_ops without verify (RFC 7517 §4.2, §4.3), a key type or curve go-jose
// does not parse, RSA outside 2048–4096 bits (maxRSABits, whatever
// jose.MaxRSAModulusBits), an alg the key cannot verify
// (PublicKey.Validate). A key without alg gets the algorithm its curve
// implies — EC, Ed25519 — and an RSA key without alg is marked for the
// verifier to bind (see boundAlgorithm). A panic of the JWK parser on a
// hostile document ignores that key alone (no known input triggers one).
func parseJWK(raw []byte) (k PublicKey, ok bool) {
	defer func() {
		if recover() != nil {
			k, ok = PublicKey{}, false
		}
	}()

	var members map[string]josejson.RawMessage
	if unmarshalExact(raw, &members) != nil || hasPrivateMaterial(members) || !signatureUse(members) {
		return PublicKey{}, false
	}

	var jwk jose.JSONWebKey
	if jwk.UnmarshalJSON(raw) != nil {
		return PublicKey{}, false
	}

	k = PublicKey{KeyID: jwk.KeyID, Algorithm: Algorithm(jwk.Algorithm), Key: jwk.Key}

	switch key := jwk.Key.(type) {
	case *rsa.PublicKey:
		if key.N == nil || key.N.BitLen() > maxRSABits {
			return PublicKey{}, false
		}

		if k.Algorithm == "" {
			// Validated as an RS256 key; bound per verifier.
			k.impliedRSA = true

			return k, PublicKey{Algorithm: RS256, Key: key}.Validate() == nil
		}
	case *ecdsa.PublicKey:
		if k.Algorithm == "" {
			k.Algorithm = curveAlgorithm(key.Curve)
		}
	case ed25519.PublicKey:
		if k.Algorithm == "" {
			k.Algorithm = EdDSA
		}
	default:
		return PublicKey{}, false // symmetric, private or unknown
	}

	return k, k.Validate() == nil
}

// hasPrivateMaterial reports whether a JWK carries private or symmetric
// key material.
func hasPrivateMaterial(members map[string]josejson.RawMessage) bool {
	for _, name := range privateMembers {
		if _, ok := members[name]; ok {
			return true
		}
	}

	return false
}

// signatureUse reports whether a JWK may verify signatures: use absent or
// "sig", key_ops absent or listing "verify" (RFC 7517 §4.2, §4.3).
func signatureUse(members map[string]josejson.RawMessage) bool {
	if raw, ok := members["use"]; ok {
		var use string
		if josejson.Unmarshal(raw, &use) != nil || use != keyUseSignature {
			return false
		}
	}

	if raw, ok := members["key_ops"]; ok {
		var ops []string
		if josejson.Unmarshal(raw, &ops) != nil || !slices.Contains(ops, "verify") {
			return false
		}
	}

	return true
}

// curveAlgorithm returns the ES algorithm of an ECDSA curve (RFC 7518
// §3.4), "" for another curve.
func curveAlgorithm(curve elliptic.Curve) Algorithm {
	switch curve {
	case elliptic.P256():
		return ES256
	case elliptic.P384():
		return ES384
	case elliptic.P521():
		return ES512
	default:
		return ""
	}
}

// boundAlgorithm returns the one algorithm pub verifies for a verifier
// allowing allowed: its Algorithm, or — for an RSA key published without
// alg — RS256 when allowed (the algorithm RFC 9068 §2.1 and OpenID
// Connect make mandatory to implement), otherwise the only RSA algorithm
// of allowed, otherwise none (RFC 8725 §3.1: one key, one algorithm).
func boundAlgorithm(pub PublicKey, allowed []Algorithm) Algorithm {
	if !pub.impliedRSA {
		return pub.Algorithm
	}

	if slices.Contains(allowed, RS256) {
		return RS256
	}

	var only Algorithm

	for _, alg := range allowed {
		if family, _ := familyOf(alg); family == familyRSA {
			if only != "" {
				return ""
			}

			only = alg
		}
	}

	return only
}
