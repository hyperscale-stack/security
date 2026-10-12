// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"testing"

	"github.com/hyperscale-stack/security/bearer"
	"github.com/stretchr/testify/assert"
)

// Audit probe TestZZAuditAuthoritiesSliceAliasing: Authorities() exposed the
// backing array, so a caller could rewrite the authorities of an immutable
// Authentication.
func TestAuthoritiesReturnsACopy(t *testing.T) {
	t.Parallel()

	auth := bearer.New("tok").WithAuthenticated(principal{sub: "alice"}, []string{"scope:read"}, "alice")

	auth.Authorities()[0] = "scope:admin"

	assert.Equal(t, []string{"scope:read"}, auth.Authorities())
	assert.Nil(t, bearer.New("tok").Authorities())
}
