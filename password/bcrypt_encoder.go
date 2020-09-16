// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

import "golang.org/x/crypto/bcrypt"

// BCryptEncoder is a implementation of Encoder that uses the BCrypt strong hashing function.
type BCryptEncoder struct {
	cost int
}

// NewBCryptEncoder constructor
func NewBCryptEncoder(cost int) Encoder {
	return &BCryptEncoder{
		cost: cost,
	}
}

// Encode the raw password.
func (e *BCryptEncoder) Encode(password string) (string, error) {
	pwd, err := bcrypt.GenerateFromPassword([]byte(password), e.cost)

	return string(pwd), err
}
