// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
)

func TestHasPermissionEvaluatesPredicate(t *testing.T) {
	t.Parallel()

	owner := security.Permission("owner", func(_ context.Context, a security.Authentication) bool {
		return a.Principal().Subject() == "alice"
	})

	v := voter.HasPermission()

	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAuth("alice"), []security.Attribute{owner}))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("bob"), []security.Attribute{owner}))
}

func TestHasPermissionDeniesUnauthenticated(t *testing.T) {
	t.Parallel()

	always := security.Permission("ok", func(context.Context, security.Authentication) bool { return true })
	v := voter.HasPermission()
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAnonymous(), []security.Attribute{always}))
}

func TestHasPermissionAllPredicatesMustGrant(t *testing.T) {
	t.Parallel()

	pass := security.Permission("pass", func(context.Context, security.Authentication) bool { return true })
	fail := security.Permission("fail", func(context.Context, security.Authentication) bool { return false })
	v := voter.HasPermission()

	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("a"), []security.Attribute{pass, fail}))
}

func TestHasPermissionAbstainsWhenNoPermissionAttribute(t *testing.T) {
	t.Parallel()

	v := voter.HasPermission()
	assert.Equal(t, security.DecisionAbstain,
		v.Vote(context.Background(), newAuth("a"), []security.Attribute{security.Role("X")}))
}

func TestHasPermissionNilPredicateIsDeny(t *testing.T) {
	t.Parallel()

	bad := security.PermissionAttribute{Name: "bad", Predicate: nil}
	v := voter.HasPermission()
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("a"), []security.Attribute{bad}))
}
