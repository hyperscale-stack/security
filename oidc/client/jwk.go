// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

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
	maxKeys    = 100
	minRSABits = 2048 // RFC 7518 §3.3
	// maxRSABits bounds the verification cost a provider can impose. It is
	// go-jose's default jose.MaxRSAModulusBits since v4.1.6, kept as the
	// package's own bound: raising that process-wide variable does not move
	// it.
	maxRSABits = 4096
)

// privateMembers are the JWK members that carry private or symmetric key
// material (RFC 7518 §6.2.2, §6.3.2, §6.4.1): a symmetric ("oct") key
// always carries k.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// errPrivateKeyMaterial reports a JWK Set publishing private or symmetric
// key material.
var errPrivateKeyMaterial = errors.New("the JWK Set publishes private or symmetric key material")

// keyKind is the family of a verification key.
type keyKind int

const (
	kindRSA keyKind = iota + 1
	kindEC
	kindEd25519
)

// verificationKey is a usable public signing key of the provider.
type verificationKey struct {
	kid string
	// alg is the algorithm the JWK declares, "" when it declares none.
	alg  Algorithm
	kind keyKind
	// implied is the only algorithm an EC or Ed25519 key can verify,
	// determined by its curve.
	implied Algorithm
	key     any
}

// parseKeySet reads a JWK Set (RFC 7517 §5). The document is strict JSON;
// a set publishing private or symmetric key material is refused as a whole
// (OpenID Connect Discovery §3: "The JWK Set MUST NOT contain private or
// symmetric key values"); keys that cannot verify ID Tokens — unknown or
// malformed, encryption keys, RSA keys outside 2048-4096 bits, other curves
// — are ignored (RFC 7517 §5).
func parseKeySet(data []byte) ([]verificationKey, error) {
	var set struct {
		Keys []josejson.RawMessage `json:"keys"`
	}

	if err := decodeStrict(data, &set); err != nil {
		return nil, err
	}

	switch {
	case set.Keys == nil:
		return nil, fmt.Errorf("%w: no keys member", errJSON)
	case len(set.Keys) > maxKeys:
		return nil, fmt.Errorf("more than %d keys", maxKeys)
	}

	keys := make([]verificationKey, 0, len(set.Keys))

	for _, raw := range set.Keys {
		var members map[string]josejson.RawMessage
		if err := josejson.Unmarshal(raw, &members); err != nil {
			return nil, fmt.Errorf("%w: a key is not an object", errJSON)
		}

		if hasPrivateMaterial(members) {
			return nil, errPrivateKeyMaterial
		}

		if k, ok := parseVerificationKey(raw, members); ok {
			keys = append(keys, k)
		}
	}

	return keys, nil
}

func hasPrivateMaterial(members map[string]josejson.RawMessage) bool {
	for _, name := range privateMembers {
		if _, ok := members[name]; ok {
			return true
		}
	}

	return false
}

// parseVerificationKey returns the key raw describes when it can verify ID
// Tokens.
func parseVerificationKey(raw []byte, members map[string]josejson.RawMessage) (verificationKey, bool) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(raw); err != nil {
		return verificationKey{}, false
	}

	if jwk.Use != "" && jwk.Use != "sig" {
		return verificationKey{}, false
	}

	if ops, ok := members["key_ops"]; ok {
		var list []string
		if err := josejson.Unmarshal(ops, &list); err != nil || !slices.Contains(list, "verify") {
			return verificationKey{}, false
		}
	}

	k := verificationKey{kid: jwk.KeyID, alg: Algorithm(jwk.Algorithm), key: jwk.Key}

	switch pub := jwk.Key.(type) {
	case *rsa.PublicKey:
		if bits := pub.N.BitLen(); bits < minRSABits || bits > maxRSABits {
			return verificationKey{}, false
		}

		k.kind = kindRSA
	case *ecdsa.PublicKey:
		alg, ok := curveAlgorithm(pub.Curve)
		if !ok {
			return verificationKey{}, false
		}

		k.kind, k.implied = kindEC, alg
	case ed25519.PublicKey:
		k.kind, k.implied = kindEd25519, EdDSA
	default:
		return verificationKey{}, false
	}

	if k.alg != "" && !k.fits(k.alg) {
		return verificationKey{}, false
	}

	return k, true
}

// curveAlgorithm returns the ES algorithm of an ECDSA curve (RFC 7518
// §3.4).
func curveAlgorithm(curve elliptic.Curve) (Algorithm, bool) {
	switch curve {
	case elliptic.P256():
		return ES256, true
	case elliptic.P384():
		return ES384, true
	case elliptic.P521():
		return ES512, true
	default:
		return "", false
	}
}

// rsaAlgorithms are the algorithms an RSA key can verify.
var rsaAlgorithms = []Algorithm{RS256, RS384, RS512, PS256, PS384, PS512}

func isRSAAlgorithm(alg Algorithm) bool { return slices.Contains(rsaAlgorithms, alg) }

// fits reports whether the key type can verify alg at all.
func (k verificationKey) fits(alg Algorithm) bool {
	if k.kind == kindRSA {
		return isRSAAlgorithm(alg)
	}

	return alg == k.implied
}

// accepts reports whether k may verify a signature made with alg: each key
// is used with exactly one algorithm (RFC 8725 §3.1) — the one its JWK
// declares, the one its curve implies, or, for an RSA key declaring none,
// RS256 (OpenID Connect Core §3.1.3.7 default) or the only RSA algorithm of
// the effective set.
func (k verificationKey) accepts(alg Algorithm, effective []Algorithm) bool {
	switch {
	case k.alg != "":
		return k.alg == alg
	case k.kind == kindRSA:
		return alg == implicitRSAAlgorithm(effective)
	default:
		return alg == k.implied
	}
}

func implicitRSAAlgorithm(effective []Algorithm) Algorithm {
	if slices.Contains(effective, RS256) {
		return RS256
	}

	var only Algorithm

	for _, alg := range effective {
		if isRSAAlgorithm(alg) {
			if only != "" {
				return ""
			}

			only = alg
		}
	}

	return only
}

// candidates returns the keys that may verify a signature made with alg
// and designated by kid ("" designates every key).
func candidates(keys []verificationKey, kid string, alg Algorithm, effective []Algorithm) []verificationKey {
	var out []verificationKey

	for _, k := range keys {
		if kid != "" && k.kid != kid {
			continue
		}

		if k.accepts(alg, effective) {
			out = append(out, k)
		}
	}

	return out
}
