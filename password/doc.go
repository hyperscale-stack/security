// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package password provides password hashing primitives for the security
// library.
//
// The Hasher interface is intentionally minimal: it covers hashing (with
// cancellable context), verification (returning a typed boolean plus an
// error for malformed input), and a NeedsRehash hook so applications can
// upgrade hashes transparently when the configured cost / KDF parameters
// drift away from the stored ones.
//
// Two implementations are shipped:
//
//   - BCryptHasher       — bcrypt via golang.org/x/crypto/bcrypt, default
//     cost 10 (bcrypt.DefaultCost, the OWASP minimum), passwords of at most
//     72 bytes.
//   - Argon2idHasher     — Argon2id via golang.org/x/crypto/argon2, with
//     parameters encoded into the hash so downstream
//     consumers can decode and verify without
//     out-of-band configuration.
//
// Both implementations are safe for concurrent use and never log secrets.
//
// # Stored hashes are untrusted input
//
// Verify decodes the parameters of the stored hash before any hashing and
// refuses what would be unsafe to compute: RFC 9106 §3.1 violations, argon2id
// salts and tags outside 16–64 bytes, missing or repeated parameters
// (ErrMalformedHash), and costs above the hasher's limits
// (ErrCostLimitExceeded, see WithArgon2idLimits and WithBCryptMaxCost).
// Whoever can write or import a hash can therefore neither crash the
// process, exhaust its memory or CPU, nor plant a hash that accepts random
// passwords. An argon2id hash verifies in its canonical encoding only: a
// PHC string with m, t and p in that order, decimal values without leading
// zeros and unpadded standard base64 with zero trailing bits (C2SP
// phc-strings). A bcrypt hash verifies with version $2a$, $2b$ or $2y$
// only — never $2x$, crypt_blowfish's marker of its sign-extension bug,
// nor the older $2$ —, and its cost is checked; x/crypto ignores what
// follows its 60th character and the unused bits of its salt's last
// character (harmless: whoever writes a stored hash controls the account;
// a length check would lock out the space-padded values of fixed-width
// columns). Empty passwords are never hashed nor accepted (RFC 8265 §4.1),
// and bcrypt refuses passwords longer than 72 bytes instead of verifying a
// truncated prefix (NIST SP 800-63B-4 §3.1.1.2).
//
// # Unicode normalization
//
// The hashers hash the password's bytes as given: they apply no Unicode
// normalization, so they verify the hashes of systems that never normalized
// and do not depend on golang.org/x/text. NIST SP 800-63B-4 §3.1.1.2 says
// verifiers SHOULD apply NFC to passwords containing Unicode characters
// (RFC 8265 §4.2, OpaqueString, does as well). An application that wants it
// wraps its hasher in a decorator applied both at enrollment and at login,
// for instance with golang.org/x/text/unicode/norm:
//
//	type nfcHasher struct{ password.Hasher }
//
//	func (h nfcHasher) Hash(ctx context.Context, pw string) (string, error) {
//		return h.Hasher.Hash(ctx, norm.NFC.String(pw))
//	}
//
//	func (h nfcHasher) Verify(ctx context.Context, hash, pw string) (bool, error) {
//		nfc := norm.NFC.String(pw)
//
//		ok, err := h.Hasher.Verify(ctx, hash, nfc)
//		if ok || err != nil || nfc == pw {
//			return ok, err
//		}
//
//		// A password enrolled before the decorator: verify the raw input,
//		// then re-hash it (Hash normalizes) and store the new hash.
//		return h.Hasher.Verify(ctx, hash, pw)
//	}
//
// The fallback costs one more verification for a password that is not in
// NFC; remove it once every account has been re-hashed.
//
// Allowed dependencies:
//   - golang.org/x/crypto
//   - stdlib only
package password
