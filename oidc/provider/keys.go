// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"crypto"
	"fmt"
	"slices"

	jwtsec "github.com/hyperscale-stack/security/jwt"
)

// idTokenAlgorithms are the ID Token signing algorithms the provider
// supports, RS256 — mandatory (OpenID Connect Core §15.1, Discovery §3) and
// the default (Registration §2) — first. none, the HMAC algorithms (keyed
// with a client secret, Core §10.1, §16.19) and EdDSA (Core defines no
// at_hash hash function for it) are not supported.
var idTokenAlgorithms = []jwtsec.Algorithm{
	jwtsec.RS256, jwtsec.RS384, jwtsec.RS512,
	jwtsec.PS256, jwtsec.PS384, jwtsec.PS512,
	jwtsec.ES256, jwtsec.ES384, jwtsec.ES512,
}

// KeySource supplies the key ring of an issuer. The provider calls it on
// every use — signing an ID Token, serving the JWK Set or the discovery
// document, verifying an id_token_hint — and validates every ring it
// returns ([KeyRing.Validate]), failing closed on an invalid one; cache in
// the implementation (keys decrypted from a KMS, read from a database).
// Returning the same ring for every issuer is fine; a multi-tenant
// deployment may give each issuer its own keys. Implementations MUST be
// safe for concurrent use and MUST return rings the caller may not mutate
// (copies).
type KeySource interface {
	Keys(ctx context.Context, issuer string) (KeyRing, error)
}

// KeyRing is a snapshot of an issuer's keys (OpenID Connect Core §10.1,
// §10.1.1; RFC 7517).
//
// Rotation without breaking a verifier: (1) add the next key to Published
// and wait at least the JWK Set cache lifetime (5 minutes, plus what relying
// parties cache); (2) move it to Signing and the former signing key to
// Published — relying parties fetch the set again on an unknown kid; (3)
// drop the former key once every ID Token it signed has expired, and no
// id_token_hint it signed should be accepted any more. Keys of JWT access
// tokens (RFC 9068 §4: one jwks_uri) belong in Published.
type KeyRing struct {
	// Signing holds the active ID Token signing keys, at most one per
	// algorithm, RS256 mandatory. Their public halves are published. A
	// client gets ID Tokens signed with the algorithm it registered
	// ([IDTokenSigningClient]), RS256 by default.
	Signing []jwtsec.PrivateKey
	// Published holds further verification keys the JWK Set publishes: the
	// next key, announced before it signs, and retired keys, kept until
	// what they signed has expired.
	Published []jwtsec.PublicKey
}

// Validate reports, wrapping [ErrInvalidKeyRing], why the provider must not
// sign with or publish r:
//   - no signing key, no RS256 signing key (OpenID Connect Core §15.1), two
//     signing keys of one algorithm, a signing algorithm outside RS256/384/
//     512, PS256/384/512 and ES256/384/512;
//   - a key without kid, or a kid used twice across both lists (RFC 7517
//     §4.5, Core §10.1: the kid selects the key);
//   - a key unfit for its algorithm (jwtsec PrivateKey.Validate and
//     PublicKey.Validate: RSA under 2048 bits, an RSA signing key over 4096
//     bits — go-jose ≥ v4.1.6 relying parties ignore it in the JWK Set —
//     another curve, an HMAC secret, a private key in Published);
//   - one key material under two entries — RFC 8725 §3.1: a key is used
//     with exactly one algorithm.
func (r KeyRing) Validate() error {
	if len(r.Signing) == 0 {
		return fmt.Errorf("%w: no signing key", ErrInvalidKeyRing)
	}

	kids := make(map[string]struct{}, len(r.Signing)+len(r.Published))
	algs := make(map[jwtsec.Algorithm]struct{}, len(r.Signing))
	publics := make([]crypto.PublicKey, 0, len(r.Signing)+len(r.Published))

	for i, k := range r.Signing {
		pub, err := validSigningKey(k, kids, algs)
		if err != nil {
			return fmt.Errorf("%w: signing key %d: %w", ErrInvalidKeyRing, i, err)
		}

		publics = append(publics, pub.Key)
	}

	if _, ok := algs[jwtsec.RS256]; !ok {
		return fmt.Errorf("%w: no RS256 signing key", ErrInvalidKeyRing)
	}

	for i, k := range r.Published {
		if err := validKid(k.KeyID, kids); err != nil {
			return fmt.Errorf("%w: published key %d: %w", ErrInvalidKeyRing, i, err)
		}

		if err := k.Validate(); err != nil {
			return fmt.Errorf("%w: published key %d: %w", ErrInvalidKeyRing, i, err)
		}

		publics = append(publics, k.Key)
	}

	for i := range publics {
		for j := i + 1; j < len(publics); j++ {
			if samePublicKey(publics[i], publics[j]) {
				return fmt.Errorf("%w: one key under two entries", ErrInvalidKeyRing)
			}
		}
	}

	return nil
}

// validSigningKey checks one signing key and records its kid and alg.
func validSigningKey(k jwtsec.PrivateKey, kids map[string]struct{}, algs map[jwtsec.Algorithm]struct{}) (jwtsec.PublicKey, error) {
	if err := validKid(k.KeyID, kids); err != nil {
		return jwtsec.PublicKey{}, err
	}

	if !slices.Contains(idTokenAlgorithms, k.Algorithm) {
		return jwtsec.PublicKey{}, fmt.Errorf("unsupported ID Token signing algorithm %q", k.Algorithm)
	}

	if _, dup := algs[k.Algorithm]; dup {
		return jwtsec.PublicKey{}, fmt.Errorf("a second %s signing key", k.Algorithm)
	}

	algs[k.Algorithm] = struct{}{}

	pub, err := k.Public()
	if err != nil {
		return jwtsec.PublicKey{}, fmt.Errorf("oidcprovider: %w", err)
	}

	return pub, nil
}

// validKid checks that kid is set and not seen yet, and records it.
func validKid(kid string, kids map[string]struct{}) error {
	if kid == "" {
		return fmt.Errorf("no kid")
	}

	if _, dup := kids[kid]; dup {
		return fmt.Errorf("kid used twice")
	}

	kids[kid] = struct{}{}

	return nil
}

// samePublicKey reports whether a and b are the same key material.
func samePublicKey(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(x crypto.PublicKey) bool })

	return ok && eq.Equal(b)
}

// StaticKeys returns a [KeySource] serving ring — validated once here, and
// again on every use like any source — to every issuer: development, tests
// and deployments whose keys only change with a redeploy. Each call returns
// a copy of ring.
func StaticKeys(ring KeyRing) (KeySource, error) {
	if err := ring.Validate(); err != nil {
		return nil, err
	}

	return staticKeys{ring: cloneRing(ring)}, nil
}

type staticKeys struct{ ring KeyRing }

// Keys implements [KeySource].
func (s staticKeys) Keys(context.Context, string) (KeyRing, error) {
	return cloneRing(s.ring), nil
}

func cloneRing(r KeyRing) KeyRing {
	return KeyRing{Signing: slices.Clone(r.Signing), Published: slices.Clone(r.Published)}
}

// keySnapshot is a validated ring, indexed for use.
type keySnapshot struct {
	// signing maps each signing algorithm to its key.
	signing map[jwtsec.Algorithm]jwtsec.PrivateKey
	// algorithms lists the signing algorithms, RS256 first, then in ring
	// order.
	algorithms []jwtsec.Algorithm
	// verification holds the signing keys' public halves, then the
	// published keys: the JWK Set, and the keys an id_token_hint may be
	// signed with.
	verification []jwtsec.PublicKey
}

// keys returns the validated key snapshot of issuer.
func (p *Provider) keys(ctx context.Context, issuer string) (*keySnapshot, error) {
	ring, err := p.cfg.Keys.Keys(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: key source: %w", err)
	}

	if err := ring.Validate(); err != nil {
		return nil, err
	}

	snap := &keySnapshot{
		signing:      make(map[jwtsec.Algorithm]jwtsec.PrivateKey, len(ring.Signing)),
		algorithms:   []jwtsec.Algorithm{jwtsec.RS256},
		verification: make([]jwtsec.PublicKey, 0, len(ring.Signing)+len(ring.Published)),
	}

	for _, k := range ring.Signing {
		snap.signing[k.Algorithm] = k

		if k.Algorithm != jwtsec.RS256 {
			snap.algorithms = append(snap.algorithms, k.Algorithm)
		}

		pub, _ := k.Public() // validated above

		snap.verification = append(snap.verification, pub)
	}

	snap.verification = append(snap.verification, ring.Published...)

	return snap, nil
}
