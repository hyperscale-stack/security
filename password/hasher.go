// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import "context"

// Hasher is the password-hashing primitive consumed by authentication
// providers. Implementations encode the algorithm identifier and any tuning
// parameters into the returned string so that Verify and NeedsRehash can
// operate without out-of-band configuration.
//
// Hasher implementations MUST be safe for concurrent use.
//
// Two implementations are shipped: NewBCryptHasher and NewArgon2idHasher.
// Both hash the password's bytes as given: they apply no Unicode
// normalization (see the package documentation for a decorator that does).
type Hasher interface {
	// Hash returns a self-describing encoded hash of password. The ctx
	// allows cancellation of slow KDF iterations. Hash refuses an empty
	// password (ErrEmptyPassword) and a password the algorithm cannot
	// process whole (bcrypt: ErrPasswordTooLong). Hash MUST NOT log or
	// otherwise emit the cleartext password.
	Hash(ctx context.Context, password string) (string, error)

	// Verify reports whether password matches encodedHash. A plain mismatch
	// returns (false, nil), and so does an empty password. Errors are
	// reserved for a stored hash that is malformed or out of bounds
	// (ErrMalformedHash), of another algorithm (ErrUnsupportedAlgorithm) or
	// costlier than the hasher's limits (ErrCostLimitExceeded), a password
	// the algorithm cannot process whole (ErrPasswordTooLong), and context
	// cancellation. Every such check runs before any hashing, and the final
	// comparison is constant-time.
	Verify(ctx context.Context, encodedHash, password string) (bool, error)

	// NeedsRehash reports whether encodedHash should be replaced: it uses
	// parameters weaker than the hasher's current configuration, or Verify
	// refuses it. Callers SHOULD invoke it after a successful Verify so that
	// login flows can transparently upgrade stored hashes when the operator
	// bumps cost factors.
	NeedsRehash(encodedHash string) bool
}
