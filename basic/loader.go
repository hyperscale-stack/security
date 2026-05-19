// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic

import (
	"context"

	"github.com/hyperscale-stack/security"
)

// PasswordUser is the [security.Principal] specialisation expected by this
// module's [Authenticator]. It exposes the hashed password so the
// authenticator can call [password.Hasher].Verify against the supplied
// credentials, plus the account-lifecycle predicates so disabled / locked /
// expired accounts can be refused without leaking the cause to the client.
type PasswordUser interface {
	security.Principal

	// GetPasswordHash returns the encoded hash (as produced by a
	// [password.Hasher].Hash call). The value MUST never be logged.
	GetPasswordHash() string

	// IsEnabled reports whether the account is active. Disabled accounts
	// MUST fail authentication.
	IsEnabled() bool

	// IsLocked reports whether the account is temporarily locked (after
	// repeated failed attempts, manual hold, ...).
	IsLocked() bool

	// IsExpired reports whether the account itself has expired (e.g.
	// contractor whose access window is over).
	IsExpired() bool

	// IsCredentialsExpired reports whether the password must be rotated
	// before login is allowed.
	IsCredentialsExpired() bool
}

// UserLoader resolves a username to a [PasswordUser]. Implementations live
// in the application layer; this module ships no implementation to keep
// itself storage-agnostic.
//
// On unknown user, implementations SHOULD return an error wrapping
// [security.ErrInvalidCredentials] to prevent account enumeration via
// response-time / response-code differences.
type UserLoader interface {
	LoadByUsername(ctx context.Context, username string) (PasswordUser, error)
}
