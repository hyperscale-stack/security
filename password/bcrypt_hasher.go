// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import "golang.org/x/crypto/bcrypt"

var _ Hasher = (*BCryptHasher)(nil)

// BCryptHasher is a implementation of Hasher that uses the BCrypt strong hashing function.
type BCryptHasher struct {
	cost int
}

// NewBCryptHasher constructor
func NewBCryptHasher(cost int) Hasher {
	return &BCryptHasher{
		cost: cost,
	}
}

// Hash the raw password.
func (e *BCryptHasher) Hash(password string) (string, error) {
	pwd, err := bcrypt.GenerateFromPassword([]byte(password), e.cost)

	return string(pwd), err
}

// Verify the hashed and clear password is equals
func (e *BCryptHasher) Verify(hashed string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))

	return err == nil
}
