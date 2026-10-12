// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Audit probe TestZZAuditAuthoritiesSliceAliasing: Authorities() exposed the
// backing array, so a caller could rewrite the authorities of an immutable
// Authentication.
func TestAuthoritiesReturnsACopy(t *testing.T) {
	t.Parallel()

	auth := newPending(&Session{ID: "sid"}).withAuthenticated(stubPrincipal{sub: "alice"}, []string{"ROLE_USER"})

	auth.Authorities()[0] = "ROLE_ADMIN"

	assert.Equal(t, []string{"ROLE_USER"}, auth.Authorities())
	assert.Nil(t, newPending(&Session{ID: "sid"}).Authorities())
}
