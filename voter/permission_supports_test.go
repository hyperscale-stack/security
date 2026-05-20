// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter_test

import (
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
)

func TestHasPermissionSupports(t *testing.T) {
	t.Parallel()

	v := voter.HasPermission()

	// The permission voter opts in only for PermissionAttribute.
	assert.True(t, v.Supports(security.Permission("owns-doc", nil)))
	assert.False(t, v.Supports(security.Role("ADMIN")))
	assert.False(t, v.Supports(security.Scope("read")))
}
