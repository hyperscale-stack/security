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
//     cost is bcrypt.DefaultCost.
//   - Argon2idHasher     — Argon2id via golang.org/x/crypto/argon2, with
//     parameters encoded into the hash so downstream
//     consumers can decode and verify without
//     out-of-band configuration.
//
// Both implementations are safe for concurrent use and never log secrets.
//
// Allowed dependencies (per architecture plan):
//   - golang.org/x/crypto
//   - stdlib only
package password
