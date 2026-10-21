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
	"slices"

	jose "github.com/go-jose/go-jose/v4"
)

// minRSABits is the smallest RSA modulus the RS* and PS* algorithms accept
// (RFC 7518 §3.3, §3.5: "A key of size 2048 bits or larger MUST be used").
const minRSABits = 2048

// maxRSABits is the largest RSA modulus of a remote JWK Set key (a larger
// one is ignored), of a signing key and of a published key (refused). It is
// go-jose's default jose.MaxRSAModulusBits since v4.1.6
// (GHSA-mgcc-cww5-fp2q): it bounds the cost of a key a tenant chooses, and a
// larger published key breaks its consumers — this package's remote key
// sets and oidc/client ignore it, go-jose's JSONWebKeySet (go-oidc among
// others) refuses the whole JWK Set — so a token signed with one would
// verify nowhere. It is the package's own bound: raising that process-wide
// variable does not move it. Verification keys given directly
// (NewStaticJWKS) are not bounded.
const maxRSABits = 4096

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

// validateSigningKey reports, wrapping ErrInvalidKey, why k cannot sign
// with its Algorithm (see NewSigner for the accepted forms).
func validateSigningKey(k PrivateKey) error {
	switch key := k.Key.(type) {
	case []byte:
		if n := hmacKeySize(k.Algorithm); n == 0 || len(key) < n {
			return fmt.Errorf("%w: not a %q secret of the required size", ErrInvalidKey, k.Algorithm)
		}

		return nil
	case jose.OpaqueSigner:
		return validateOpaqueSigner(k.Algorithm, key)
	case jose.JSONWebKey:
		return validateSigningKey(PrivateKey{KeyID: k.KeyID, Algorithm: k.Algorithm, Key: key.Key})
	case *jose.JSONWebKey:
		if key == nil {
			return fmt.Errorf("%w: nil JSON Web Key", ErrInvalidKey)
		}

		return validateSigningKey(PrivateKey{KeyID: k.KeyID, Algorithm: k.Algorithm, Key: key.Key})
	default:
		return k.Validate()
	}
}

// validateOpaqueSigner checks an opaque (KMS, HSM) signer through its
// public half: it must offer alg, and its public key must fit alg — an RSA
// key of at most maxRSABits, like any signing key.
func validateOpaqueSigner(alg Algorithm, s jose.OpaqueSigner) error {
	if !slices.Contains(s.Algs(), alg.joseAlg()) {
		return fmt.Errorf("%w: the opaque signer does not offer %q", ErrInvalidKey, alg)
	}

	pub := s.Public()
	if pub == nil {
		return fmt.Errorf("%w: the opaque signer has no public key", ErrInvalidKey)
	}

	if err := (PublicKey{Algorithm: alg, Key: pub.Key}).Validate(); err != nil {
		return err
	}

	return checkPublishable(pub.Key)
}

// checkPublishable refuses, wrapping ErrInvalidKey, an RSA key over
// maxRSABits: once published, go-jose's JSONWebKeySet refuses the whole JWK
// Set holding it.
func checkPublishable(key crypto.PublicKey) error {
	if k, ok := key.(*rsa.PublicKey); ok && k.N != nil && k.N.BitLen() > maxRSABits {
		return fmt.Errorf("%w: RSA key over %d bits", ErrInvalidKey, maxRSABits)
	}

	return nil
}

// hmacKeySizes are the smallest secrets the HMAC algorithms accept: the
// size of their hash output (RFC 7518 §3.2).
var hmacKeySizes = map[Algorithm]int{HS256: 32, HS384: 48, HS512: 64}

// hmacKeySize returns the smallest secret alg accepts, 0 when alg is not
// an HMAC algorithm.
func hmacKeySize(alg Algorithm) int { return hmacKeySizes[alg] }

// bindKey checks that pub may verify a signature made with alg: the key is
// bound to exactly that algorithm (RFC 8725 §3.1 — an empty Algorithm
// verifies nothing) and, for an asymmetric algorithm, is a valid public key
// for it (PublicKey.Validate: RSA of at least 2048 bits, the algorithm's
// curve, never a private key, a wrapper or another type — RFC 7518 §3.3 to
// §3.5); for an HMAC algorithm, it is a []byte secret, never a wrapper —
// go-jose checks the secret's length itself (RFC 7518 §3.2). Failures wrap
// ErrInvalidSignature (and ErrInvalidKey for an invalid key); no key
// material appears in them.
func bindKey(pub PublicKey, alg Algorithm) error {
	if pub.Algorithm != alg {
		return fmt.Errorf("%w: the key is bound to another algorithm", ErrInvalidSignature)
	}

	if isHMAC(alg) {
		if _, ok := pub.Key.([]byte); !ok {
			return fmt.Errorf("%w: %w: not a %q secret", ErrInvalidSignature, ErrInvalidKey, alg)
		}

		return nil
	}

	if err := pub.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	return nil
}

// isHMAC reports whether alg is a symmetric (HMAC) algorithm.
func isHMAC(alg Algorithm) bool { return hmacKeySize(alg) > 0 }

// Validate reports, wrapping [ErrInvalidKey], why k cannot verify the
// signatures of its algorithm: an Algorithm that is not an asymmetric
// signature algorithm (HMAC keys are secrets, never published), or a Key
// that is not the public key that algorithm takes — an *rsa.PublicKey of at
// least 2048 bits for RS* and PS* (RFC 7518 §3.3, §3.5), an *ecdsa.PublicKey
// on the curve of ES256 / ES384 / ES512 (RFC 7518 §3.4), an
// ed25519.PublicKey for EdDSA (RFC 8037) that is the canonical encoding
// (RFC 8032 §5.1.3) of a point not of small order — the all-zero key and
// the identity are refused, as forgeries verify against them (RFC 8725
// §3.4). A private key is refused: one key,
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
		ok = family == familyEd25519 && validEd25519PublicKey(key)
	}

	if !ok {
		return fmt.Errorf("%w: not a public %q signature key", ErrInvalidKey, k.Algorithm)
	}

	return nil
}

// ed25519SmallOrderY are the y-coordinates, little-endian with bit 255
// clear, of the 8 points of order dividing 8 on Ed25519: 0 (order 4), 1
// (the identity), p − 1 (order 2) and the two of the order-8 points.
var ed25519SmallOrderY = [][ed25519.PublicKeySize]byte{
	{},
	{0x01},
	{
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
	{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	},
	{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	},
}

// validEd25519PublicKey reports whether key is a 32-byte Ed25519 public key
// a verifier may use: the canonical encoding of a point not of small
// order. RFC 8032 §5.1.3 fails the decoding of a y-coordinate ≥ p (step 1)
// and of x = 0 with its sign bit set (step 4), and §5.1.7 step 1 makes a
// signature under a key that fails to decode invalid — crypto/ed25519
// decodes both. A small-order key verifies forgeries: against the identity
// point, R = B and S = 1 sign any message; against the all-zero key (y =
// 0, order 4), R = identity and S = 0 sign one message in four (RFC 8725
// §3.4: validate cryptographic inputs). The sign bit is ignored when
// comparing with the small-order y-coordinates, which also refuses the
// x = 0 encodings. A point off the curve is not detected here: it verifies
// nothing, crypto/ed25519 failing to decode it.
func validEd25519PublicKey(key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}

	var y [ed25519.PublicKeySize]byte

	copy(y[:], key)
	y[31] &= 0x7f

	if !belowP(y) {
		return false
	}

	return !slices.Contains(ed25519SmallOrderY, y)
}

// belowP reports whether y, a little-endian 255-bit integer, is below the
// field order p = 2^255 − 19 (little-endian: 0xed, then 30 × 0xff, then
// 0x7f): only y ∈ [p, 2^255 − 1] has its 31 high bytes at their maximum
// and its low byte at 0xed or more.
func belowP(y [ed25519.PublicKeySize]byte) bool {
	if y[31] != 0x7f || y[0] < 0xed {
		return true
	}

	for _, b := range y[1:31] {
		if b != 0xff {
			return true
		}
	}

	return false
}

// Validate reports, wrapping [ErrInvalidKey], why k cannot sign with its
// algorithm: the private counterpart of [PublicKey.Validate] — an
// *rsa.PrivateKey of 2048 to 4096 bits for RS* and PS* (see maxRSABits:
// a larger published key breaks go-jose ≥ v4.1.6 consumers), an
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
		ok = family == familyRSA && key.N != nil && key.N.BitLen() >= minRSABits && key.N.BitLen() <= maxRSABits &&
			key.D != nil && len(key.Primes) >= 2
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
