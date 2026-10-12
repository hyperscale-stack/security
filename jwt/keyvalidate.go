// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
)

// minRSABits is the smallest RSA modulus the RS* and PS* algorithms accept
// (RFC 7518 §3.3, §3.5: "A key of size 2048 bits or larger MUST be used").
const minRSABits = 2048

// keyFamily is the kind of key an asymmetric algorithm signs with.
type keyFamily int

const (
	familyNone keyFamily = iota
	familyRSA
	familyEC
	familyEd25519
)

// familyOf returns the key family of alg, and for an ECDSA algorithm the
// curve it is bound to (RFC 7518 §3.4). Symmetric, unknown and empty
// algorithms have no family.
func familyOf(alg Algorithm) (keyFamily, elliptic.Curve) {
	switch alg {
	case RS256, RS384, RS512, PS256, PS384, PS512:
		return familyRSA, nil
	case ES256:
		return familyEC, elliptic.P256()
	case ES384:
		return familyEC, elliptic.P384()
	case ES512:
		return familyEC, elliptic.P521()
	case EdDSA:
		return familyEd25519, nil
	case HS256, HS384, HS512:
		// Symmetric: an HMAC key is a shared secret, not a signature key
		// pair — never published, never validated here.
		return familyNone, nil
	default:
		return familyNone, nil
	}
}

// Validate reports, wrapping [ErrInvalidKey], why k cannot verify the
// signatures of its algorithm: an Algorithm that is not an asymmetric
// signature algorithm (HMAC keys are secrets, never published), or a Key
// that is not the public key that algorithm takes — an *rsa.PublicKey of at
// least 2048 bits for RS* and PS* (RFC 7518 §3.3, §3.5), an *ecdsa.PublicKey
// on the curve of ES256 / ES384 / ES512 (RFC 7518 §3.4), an
// ed25519.PublicKey for EdDSA (RFC 8037). A private key is refused: one key,
// one use, and private material never travels as a PublicKey. The kid is
// not checked.
func (k PublicKey) Validate() error {
	family, curve := familyOf(k.Algorithm)

	var ok bool

	switch key := k.Key.(type) {
	case *rsa.PublicKey:
		ok = family == familyRSA && key.N != nil && key.N.BitLen() >= minRSABits && key.E > 1
	case *ecdsa.PublicKey:
		ok = family == familyEC && key.Curve == curve && validECPublicKey(key)
	case ed25519.PublicKey:
		ok = family == familyEd25519 && len(key) == ed25519.PublicKeySize
	}

	if !ok {
		return fmt.Errorf("%w: not a public %q signature key", ErrInvalidKey, k.Algorithm)
	}

	return nil
}

// Validate reports, wrapping [ErrInvalidKey], why k cannot sign with its
// algorithm: the private counterpart of [PublicKey.Validate] — an
// *rsa.PrivateKey of at least 2048 bits for RS* and PS*, an
// *ecdsa.PrivateKey on the algorithm's curve for ES*, an
// ed25519.PrivateKey for EdDSA. HMAC secrets and public keys are refused.
func (k PrivateKey) Validate() error {
	if _, err := k.Public(); err != nil {
		return err
	}

	return nil
}

// Public returns the verification key of k — its public half, with the
// same KeyID and Algorithm — or, wrapping [ErrInvalidKey], why k is not a
// valid signing key (see [PrivateKey.Validate]).
func (k PrivateKey) Public() (PublicKey, error) {
	family, curve := familyOf(k.Algorithm)

	var ok bool

	switch key := k.Key.(type) {
	case *rsa.PrivateKey:
		ok = family == familyRSA && key.N != nil && key.N.BitLen() >= minRSABits && key.D != nil && len(key.Primes) >= 2
	case *ecdsa.PrivateKey:
		ok = family == familyEC && key.Curve == curve && validECPrivateKey(key)
	case ed25519.PrivateKey:
		ok = family == familyEd25519 && len(key) == ed25519.PrivateKeySize
	}

	if !ok {
		return PublicKey{}, fmt.Errorf("%w: not a private %q signature key", ErrInvalidKey, k.Algorithm)
	}

	signer, _ := k.Key.(crypto.Signer) // every type accepted above is one

	return PublicKey{KeyID: k.KeyID, Algorithm: k.Algorithm, Key: signer.Public()}, nil
}

// validECPublicKey reports whether key is a valid point of its curve.
// Bytes dereferences the coordinates: a key without them is refused first,
// so a malformed key fails validation instead of panicking.
func validECPublicKey(key *ecdsa.PublicKey) bool {
	//nolint:staticcheck // SA1019: X and Y are only read, never modified, to keep Bytes from dereferencing nil.
	if key.X == nil || key.Y == nil {
		return false
	}

	_, err := key.Bytes()

	return err == nil
}

// validECPrivateKey reports whether key is a valid scalar of its curve,
// with a valid public point.
func validECPrivateKey(key *ecdsa.PrivateKey) bool {
	//nolint:staticcheck // SA1019: D is only read, never modified, to keep Bytes from dereferencing nil.
	if key.D == nil || !validECPublicKey(&key.PublicKey) {
		return false
	}

	_, err := key.Bytes()

	return err == nil
}
