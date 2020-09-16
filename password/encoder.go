// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password

// Encoder Service interface for encoding passwords
type Encoder interface {
	Encode(password string) (string, error)
}
