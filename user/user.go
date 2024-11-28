// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package user

// User interface provides core user information
//
//go:generate mockery --name=User --inpackage --case underscore
type User interface {
	GetID() string

	// GetRoles returns the roles granted to the user.
	GetRoles() []string

	// GetPassword returns the password used to authenticate the user
	GetPassword() string

	// GetUsername returns the username used to authenticate the user
	GetUsername() string

	// IsExpired indicates whether the user's account has expired.
	IsExpired() bool

	// IsLocked indicates whether the user is locked or unlocked.
	IsLocked() bool

	// IsEnabled indicates whether the user is enabled or disabled.
	IsEnabled() bool

	// IsCredentialsExpired indicates whether the user's credentials (password) has expired.
	IsCredentialsExpired() bool
}

// PasswordSalt interface.
type PasswordSalt interface {
	GetSalt() string
	SaltPassword(password string, salt string) string
}

// UserPasswordSalt interface.
//
//go:generate mockery --name=UserPasswordSalt --inpackage --case underscore
//nolint:golint
type UserPasswordSalt interface {
	User
	PasswordSalt
}
