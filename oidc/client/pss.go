// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"crypto"
	"crypto/rsa"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
)

// errNotPSS reports a pssVerifier asked to verify another algorithm than
// the PS256, PS384 or PS512 it is bound to.
var errNotPSS = errors.New("not an RSASSA-PSS algorithm")

// pssHashes are the hash functions of the RSASSA-PSS algorithms (RFC 7518
// §3.5), used for the message digest and for MGF1 alike.
var pssHashes = map[jose.SignatureAlgorithm]crypto.Hash{
	jose.PS256: crypto.SHA256,
	jose.PS384: crypto.SHA384,
	jose.PS512: crypto.SHA512,
}

// pssVerifier verifies PS256, PS384 and PS512 signatures with a salt as
// long as the hash output, as RFC 7518 §3.5 requires ("The size of the salt
// value is the same size as the hash function output"): go-jose verifies
// them with rsa.PSSSaltLengthAuto, any salt length. It implements
// jose.OpaqueVerifier, so go-jose still parses the JWS and hands over its
// signing input. It is bound to one algorithm, the one its key verifies
// (RFC 8725 §3.1), and refuses any other.
type pssVerifier struct {
	pub *rsa.PublicKey
	alg jose.SignatureAlgorithm
}

// VerifyPayload implements jose.OpaqueVerifier.
func (v pssVerifier) VerifyPayload(payload, signature []byte, alg jose.SignatureAlgorithm) error {
	hash, ok := pssHashes[alg]
	if !ok || alg != v.alg {
		return errNotPSS
	}

	h := hash.New()
	h.Write(payload)

	return rsa.VerifyPSS(v.pub, hash, h.Sum(nil), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) //nolint:wrapcheck // mapped to ErrIDTokenSignature by the caller
}
