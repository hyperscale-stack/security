// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The public constructors map an empty scheme to "Bearer" before checking
// it: the grammar helper itself must still refuse an empty token
// (RFC 9110 §5.6.2, token = 1*tchar).
func TestIsToken(t *testing.T) {
	t.Parallel()

	for s, want := range map[string]bool{
		"":                      false,
		"Bearer":                true,
		"DPoP":                  true,
		"!#$%&'*+-.^_`|~09azAZ": true,
		"Bea rer":               false,
		"Bearer\r\n":            false,
		"a/b":                   false,
		"a=b":                   false,
		"caf\u00e9":             false,
	} {
		assert.Equal(t, want, isToken(s), "%q", s)
	}
}
