// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

// Hasher interface for encoding passwords.
type Hasher interface {
	Hash(password string) (string, error)
	Verify(hashed string, password string) bool
}
