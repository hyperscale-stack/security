// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// pssHashes maps each RSASSA-PSS algorithm to its hash, used for the
// message digest and for MGF1 alike (RFC 7518 §3.5).
var pssHashes = map[Algorithm]crypto.Hash{PS256: crypto.SHA256, PS384: crypto.SHA384, PS512: crypto.SHA512}

// errPSSAlgorithm reports a signature algorithm a pssVerifier is not bound
// to.
var errPSSAlgorithm = errors.New("jwt: not the RSASSA-PSS algorithm of the key")

// isPSS reports whether alg is an RSASSA-PSS algorithm.
func isPSS(alg Algorithm) bool {
	_, ok := pssHashes[alg]

	return ok
}

// pssVerifier verifies the RSASSA-PSS signatures of one key and one
// algorithm as RFC 7518 §3.5 defines them: "The size of the salt value is
// the same size as the hash function output". go-jose verifies PS* with
// any salt length (rsa.PSSSaltLengthAuto); as a jose.OpaqueVerifier,
// pssVerifier replaces that primitive only — go-jose still parses the JWS
// and computes its signing input.
type pssVerifier struct {
	key *rsa.PublicKey
	alg Algorithm
}

// VerifyPayload implements jose.OpaqueVerifier. An algorithm other than the
// key's is refused, whatever the caller checked before.
func (v pssVerifier) VerifyPayload(payload, signature []byte, alg jose.SignatureAlgorithm) error {
	h, ok := pssHashes[v.alg]
	if !ok || Algorithm(alg) != v.alg {
		return errPSSAlgorithm
	}

	d := h.New()
	d.Write(payload)

	if err := rsa.VerifyPSS(v.key, h, d.Sum(nil), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		return fmt.Errorf("jwt: RSASSA-PSS: %w", err)
	}

	return nil
}

// verificationKey returns what go-jose verifies a signature of k with: for
// an RSASSA-PSS key, the strict pssVerifier; otherwise the key itself.
func (k PublicKey) verificationKey() any {
	if key, ok := k.Key.(*rsa.PublicKey); ok && isPSS(k.Algorithm) {
		return pssVerifier{key: key, alg: k.Algorithm}
	}

	return k.toJOSE()
}

// opaquePSSCheck returns, for an RSASSA-PSS key held by a jose.OpaqueSigner
// (a KMS or an HSM, bare or in a jose.JSONWebKey), the verifier of the
// signatures it makes, nil for any other key. The signer checks each
// signature against it: an opaque signer chooses its own salt length — go-
// jose's cryptosigner.Opaque asks crypto/rsa for the maximum outside FIPS
// 140-3 mode — and a token whose salt is not the hash size is refused by
// every verifier of this package.
func opaquePSSCheck(k PrivateKey) *pssVerifier {
	opaque, ok := opaqueSigner(k.Key)
	if !ok {
		return nil
	}

	var key any
	if pub := opaque.Public(); pub != nil {
		key = pub.Key
	}

	if v, ok := (PublicKey{Algorithm: k.Algorithm, Key: key}).verificationKey().(pssVerifier); ok {
		return &v
	}

	return nil
}

// opaqueSigner returns the jose.OpaqueSigner key is or wraps.
func opaqueSigner(key crypto.PrivateKey) (jose.OpaqueSigner, bool) {
	switch k := key.(type) {
	case jose.OpaqueSigner:
		return k, true
	case jose.JSONWebKey:
		return opaqueSigner(k.Key)
	case *jose.JSONWebKey:
		if k != nil {
			return opaqueSigner(k.Key)
		}
	}

	return nil, false
}
