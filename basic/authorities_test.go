// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"testing"

	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
)

// Audit probe TestZZAuditAuthoritiesSliceAliasing: Authorities() exposed the
// backing array, so a caller could rewrite the authorities of an immutable
// Authentication.
func TestAuthoritiesReturnsACopy(t *testing.T) {
	t.Parallel()

	auth := basic.New("alice", "pw").WithAuthenticated(basic.NewMockPasswordUser(t), []string{"ROLE_USER"})

	auth.Authorities()[0] = "ROLE_ADMIN"

	assert.Equal(t, []string{"ROLE_USER"}, auth.Authorities())
	assert.Nil(t, basic.New("alice", "pw").Authorities())
}
