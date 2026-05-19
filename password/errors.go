// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import "errors"

// Sentinel errors.
var (
	// ErrMismatch is returned by Verify when the password does not match the
	// hash. Callers SHOULD NOT distinguish ErrMismatch from "user not found"
	// in user-facing messages to avoid account-enumeration leaks; the typed
	// error is only here so application code can branch on it for metrics
	// or rate-limiting.
	ErrMismatch = errors.New("password: mismatch")

	// ErrUnsupportedAlgorithm is returned by Verify / NeedsRehash when the
	// encoded hash uses an algorithm the hasher does not know how to parse.
	// It typically signals a mistake in the application's storage layer
	// (mixing bcrypt and argon2id without an algorithm-aware dispatcher).
	ErrUnsupportedAlgorithm = errors.New("password: unsupported algorithm")

	// ErrMalformedHash is returned by Verify when the encoded hash exists
	// for the right algorithm but cannot be decoded (truncated, corrupted,
	// wrong number of fields, …). It is typically a storage-corruption bug.
	ErrMalformedHash = errors.New("password: malformed hash")
)
