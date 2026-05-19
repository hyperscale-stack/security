// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"context"
	"crypto"
	"sync"

	jose "github.com/go-jose/go-jose/v4"
)

// PublicKey is a verification key paired with its kid. The package wraps
// crypto.PublicKey instead of jose.JSONWebKey to keep the API minimal; the
// JSONWebKey form is reconstructed internally when calling go-jose.
type PublicKey struct {
	// KeyID is the JWS "kid" header value identifying this key. Required
	// when the verifier serves more than one key.
	KeyID string
	// Algorithm is the JOSE alg this key was issued for. Required for
	// signers; verifiers fall back to the token header when it is empty.
	Algorithm Algorithm
	// Key is the underlying crypto.PublicKey (rsa.PublicKey, ecdsa.PublicKey,
	// ed25519.PublicKey, or []byte for HMAC).
	Key crypto.PublicKey
}

// PrivateKey is the signing-key counterpart to [PublicKey].
type PrivateKey struct {
	// KeyID identifies this key in the published JWKS.
	KeyID string
	// Algorithm is the JOSE alg this key signs with.
	Algorithm Algorithm
	// Key is the underlying crypto.PrivateKey.
	Key crypto.PrivateKey
}

// KeySet abstracts a snapshot of verification keys with optional active
// signing key. Implementations are returned by [JWKSProvider.KeySet] and
// MUST be safe for concurrent use.
type KeySet interface {
	// ByKeyID returns the verification key identified by kid, or (zero,
	// false) when the kid is not present. An empty kid argument MAY match
	// the single key in a single-key set; verifiers SHOULD always set kid
	// to remove ambiguity once they rotate.
	ByKeyID(kid string) (PublicKey, bool)

	// Active returns the key currently preferred for SIGNING. Verifiers do
	// not need it; signers do. (PrivateKey{}, false) when no active key is
	// available.
	Active() (PrivateKey, bool)
}

// JWKSProvider returns a [KeySet] snapshot. Implementations span:
//
//   - in-process key holders ([NewStaticJWKS]);
//   - HTTP fetchers backed by the canonical RFC 7517 "jwks_uri" endpoint
//     ([NewRemoteJWKS], in jwks.go).
//
// The KeySet contract gives implementations leeway to refresh in the
// background without coordinating with callers.
type JWKSProvider interface {
	KeySet(ctx context.Context) (KeySet, error)
}

// NewStaticJWKS returns a [JWKSProvider] backed by a fixed list of public
// keys (verifier-side) and an optional list of private keys (signer-side,
// first one wins for Active()). Calls to KeySet are safe for concurrent
// use and never return an error.
func NewStaticJWKS(publicKeys []PublicKey, privateKeys ...PrivateKey) JWKSProvider {
	keys := &staticKeySet{
		publics: append([]PublicKey(nil), publicKeys...),
	}

	if len(privateKeys) > 0 {
		k := privateKeys[0]
		keys.active = &k
	}

	return staticProvider{set: keys}
}

type staticProvider struct{ set *staticKeySet }

func (p staticProvider) KeySet(context.Context) (KeySet, error) { return p.set, nil }

type staticKeySet struct {
	mu      sync.RWMutex
	publics []PublicKey
	active  *PrivateKey
}

// ByKeyID implements [KeySet].
func (s *staticKeySet) ByKeyID(kid string) (PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if kid == "" && len(s.publics) == 1 {
		return s.publics[0], true
	}

	for _, k := range s.publics {
		if k.KeyID == kid {
			return k, true
		}
	}

	return PublicKey{}, false
}

// Active implements [KeySet].
func (s *staticKeySet) Active() (PrivateKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.active == nil {
		return PrivateKey{}, false
	}

	return *s.active, true
}

// toJOSE returns the go-jose JSONWebKey form of the public key. Internal
// helper used by the verifier.
func (k PublicKey) toJOSE() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.Key, KeyID: k.KeyID, Algorithm: string(k.Algorithm), Use: "sig"}
}

// toJOSE returns the go-jose JSONWebKey form of the private key.
func (k PrivateKey) toJOSE() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.Key, KeyID: k.KeyID, Algorithm: string(k.Algorithm), Use: "sig"}
}
