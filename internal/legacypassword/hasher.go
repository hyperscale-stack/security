// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package legacypassword keeps the v0 BCrypt-only Hasher API alive for the
// legacy DAO authentication provider. It will be removed when the legacy
// authentication/* tree is dropped at the end of Phase 7. New code MUST
// use github.com/hyperscale-stack/security/password instead.
package legacypassword

// Hasher interface for encoding passwords.
type Hasher interface {
	Hash(password string) (string, error)
	Verify(hashed string, password string) bool
}
