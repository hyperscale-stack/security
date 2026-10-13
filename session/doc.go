// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package session provides cookie-based session management for browser apps:
// a stateless encrypted cookie store, session ID rotation (defense against
// session fixation), logout, a CSRF helper and an optional server-side
// revocation hook.
//
// Defaults are secure: Secure=true, HttpOnly=true, SameSite=Lax. The whole
// session is sealed into the cookie with AES-256-GCM, an AEAD (no separate
// HMAC): keys of at least 32 random bytes expanded with HKDF-SHA256, the
// cookie bound to the format version, its name and an optional purpose,
// key rotation with a multi-key reader and a single active writer (see
// Codec for the cookie format).
//
// A session lives at most its TTL from its creation: the Manager enforces
// CreatedAt + TTL on every read, and neither Rotate nor Touch extends it.
// Numbers in Values come back as json.Number (Session.GetInt64), never as a
// float64 that loses the precision of a 64-bit ID.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - golang.org/x/crypto
//   - stdlib only
package session
