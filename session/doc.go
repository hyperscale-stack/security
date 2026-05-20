// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package session provides cookie-based session management for browser apps:
// signed/encrypted cookie store, session ID rotation after login (defense
// against session fixation), logout, CSRF helper.
//
// Defaults are secure: Secure=true, HttpOnly=true, SameSite=Lax. The cookie
// store uses AES-GCM with HMAC and supports key rotation (multi-key reader,
// single active writer).
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security (core)
//   - golang.org/x/crypto
//   - stdlib only
package session
