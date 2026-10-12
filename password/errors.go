// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import "errors"

// Sentinel errors.
var (
	// ErrMismatch is offered to application code that needs an error value
	// for a wrong password (metrics, rate limiting): the shipped hashers
	// never return it — Verify reports a mismatch as (false, nil). Do not
	// tell it apart from "user not found" in user-facing messages: that
	// would leak which accounts exist.
	ErrMismatch = errors.New("password: mismatch")

	// ErrUnsupportedAlgorithm is returned by Verify when the encoded hash
	// uses an algorithm the hasher does not know how to parse. It typically
	// signals a mistake in the application's storage layer (mixing bcrypt
	// and argon2id without an algorithm-aware dispatcher).
	ErrUnsupportedAlgorithm = errors.New("password: unsupported algorithm")

	// ErrMalformedHash is returned by Verify when the encoded hash exists
	// for the right algorithm but cannot be decoded or is out of bounds
	// (truncated, corrupted, wrong number of fields, a parameter missing,
	// repeated or out of its range, a salt or tag of the wrong size…). It
	// typically is a storage-corruption bug, or a hash imported from a
	// system with unsafe parameters.
	ErrMalformedHash = errors.New("password: malformed hash")

	// ErrCostLimitExceeded is returned by Verify, before any hashing, when
	// the cost a stored hash asks for exceeds the hasher's limits
	// (WithArgon2idLimits, WithBCryptMaxCost): honoring it would let
	// whoever can write or import hashes exhaust the server's memory or CPU.
	// Raise the limits when you legitimately import costlier hashes.
	ErrCostLimitExceeded = errors.New("password: stored hash cost exceeds the configured limit")

	// ErrPasswordTooLong is returned by the bcrypt hasher's Hash and Verify
	// for a password longer than 72 bytes, the most bcrypt processes: NIST
	// SP 800-63B-4 §3.1.1.2 requires the entire password to be verified,
	// never a truncated prefix.
	ErrPasswordTooLong = errors.New("password: password longer than 72 bytes")

	// ErrEmptyPassword is returned by Hash for an empty password: "A
	// password MUST NOT be zero bytes in length" (RFC 8265 §4.1). Verify
	// never accepts an empty password either.
	ErrEmptyPassword = errors.New("password: empty password")
)
