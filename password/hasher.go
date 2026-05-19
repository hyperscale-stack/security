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
type Hasher interface {
	// Hash returns a self-describing encoded hash of password. The ctx
	// allows cancellation of slow KDF iterations; bcrypt is bounded by its
	// cost factor (low ms), Argon2id by its time/memory parameters (tens
	// of ms). Hash MUST NOT log or otherwise emit the cleartext password.
	Hash(ctx context.Context, password string) (string, error)

	// Verify reports whether password matches encodedHash. A plain mismatch
	// returns (false, nil); errors are reserved for malformed input
	// (ErrMalformedHash), unknown algorithms (ErrUnsupportedAlgorithm), or
	// context cancellation. Verify uses constant-time comparison on its
	// final step to avoid timing attacks.
	Verify(ctx context.Context, encodedHash, password string) (bool, error)

	// NeedsRehash reports whether encodedHash uses parameters weaker than
	// the hasher's current configuration. Callers SHOULD invoke it after a
	// successful Verify so that login flows can transparently upgrade
	// stored hashes when the operator bumps cost factors.
	NeedsRehash(encodedHash string) bool
}
