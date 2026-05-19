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

func TestHasRoleSupportsOnlyRoleAttribute(t *testing.T) {
	t.Parallel()

	v := voter.HasRole("ADMIN")
	assert.True(t, v.Supports(security.Role("ADMIN")))
	assert.False(t, v.Supports(security.Scope("read")))
}

func TestHasRoleMatchesEitherPrefixedOrBare(t *testing.T) {
	t.Parallel()

	v := voter.HasRole("ADMIN")
	attrs := []security.Attribute{security.Role("ADMIN")}

	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAuth("a", "ADMIN"), attrs))
	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAuth("a", "ROLE_ADMIN"), attrs))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("a", "USER"), attrs))
}

func TestHasRoleDeniesUnauthenticated(t *testing.T) {
	t.Parallel()

	v := voter.HasRole("ADMIN")
	got := v.Vote(context.Background(), newAnonymous(), []security.Attribute{security.Role("ADMIN")})
	assert.Equal(t, security.DecisionDeny, got)
}

func TestHasAnyRoleMatchesAtLeastOne(t *testing.T) {
	t.Parallel()

	v := voter.HasAnyRole("ADMIN", "OWNER")
	attrs := []security.Attribute{security.Role("ADMIN")}

	cases := []struct {
		name string
		auth fakeAuth
		want security.Decision
	}{
		{"first_matches", newAuth("a", "ROLE_ADMIN"), security.DecisionGrant},
		{"second_matches", newAuth("a", "OWNER"), security.DecisionGrant},
		{"neither", newAuth("a", "USER"), security.DecisionDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, v.Vote(context.Background(), c.auth, attrs))
		})
	}
}
