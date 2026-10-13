// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

// SealForTest and OpenForTest expose the codec to the black-box tests: only
// the Manager seals and opens cookies, always bound to its cookie name and
// purpose.
func (c *Codec) SealForTest(s *Session, name, purpose string) (string, error) {
	return c.seal(s, name, purpose)
}

func (c *Codec) OpenForTest(value, name, purpose string) (*Session, error) {
	return c.open(value, name, purpose)
}
