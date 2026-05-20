// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleAttribute(t *testing.T) {
	t.Parallel()

	attr := security.Role("ADMIN")

	role, ok := attr.(security.RoleAttribute)
	require.True(t, ok)

	// String() carries the Spring-style ROLE_ prefix.
	assert.Equal(t, "ROLE_ADMIN", attr.String())
	// Name() returns the bare role.
	assert.Equal(t, "ADMIN", role.Name())
}

func TestScopeAttribute(t *testing.T) {
	t.Parallel()

	attr := security.Scope("read:mail")

	scope, ok := attr.(security.ScopeAttribute)
	require.True(t, ok)

	assert.Equal(t, "scope:read:mail", attr.String())
	assert.Equal(t, "read:mail", scope.Name())
}

func TestAuthorityAttribute(t *testing.T) {
	t.Parallel()

	attr := security.Authority("billing:export")

	_, ok := attr.(security.AuthorityAttribute)
	require.True(t, ok)

	// Authority carries no convention — String() is the bare value.
	assert.Equal(t, "billing:export", attr.String())
}

func TestPermissionAttribute(t *testing.T) {
	t.Parallel()

	called := false
	predicate := func(context.Context, security.Authentication) bool {
		called = true

		return true
	}

	attr := security.Permission("owns-document", predicate)

	perm, ok := attr.(security.PermissionAttribute)
	require.True(t, ok)

	assert.Equal(t, "permission:owns-document", attr.String())
	assert.Equal(t, "owns-document", perm.Name)

	require.NotNil(t, perm.Predicate)
	assert.True(t, perm.Predicate(context.Background(), security.Anonymous()))
	assert.True(t, called, "the constructed predicate must be the one supplied")
}
