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

func TestHasScopeMatchesOnePrefixedScopePerAuthority(t *testing.T) {
	t.Parallel()

	v := voter.HasScope("read:mail")
	attrs := []security.Attribute{security.Scope("read:mail")}

	cases := []struct {
		name string
		auth fakeAuth
		want security.Decision
	}{
		{"prefixed_match", newAuth("a", "scope:read:mail"), security.DecisionGrant},
		{"bare_is_not_a_scope", newAuth("a", "read:mail"), security.DecisionDeny},
		{"space_packed_is_one_authority", newAuth("a", "scope:foo read:mail write:mail"), security.DecisionDeny},
		{"miss", newAuth("a", "scope:write:mail"), security.DecisionDeny},
		{"unauthenticated", newAnonymous(), security.DecisionDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, v.Vote(context.Background(), c.auth, attrs))
		})
	}
}

func TestHasScopeSupportsOnlyScopeAttribute(t *testing.T) {
	t.Parallel()

	v := voter.HasScope("read")
	assert.True(t, v.Supports(security.Scope("read")))
	assert.False(t, v.Supports(security.Scope("write")), "only the scope it is bound to")
	assert.False(t, v.Supports(security.Role("ADMIN")))
}

func TestHasAnyScopeMatchesAtLeastOneRequestedScope(t *testing.T) {
	t.Parallel()

	v := voter.HasAnyScope("read", "write")

	cases := []struct {
		name  string
		auth  fakeAuth
		attrs []security.Attribute
		want  security.Decision
	}{
		{"first", newAuth("a", "scope:read"), []security.Attribute{security.Scope("read")}, security.DecisionGrant},
		{"second", newAuth("a", "scope:write"), []security.Attribute{security.Scope("read"), security.Scope("write")}, security.DecisionGrant},
		{"held_but_not_requested", newAuth("a", "scope:write"), []security.Attribute{security.Scope("read")}, security.DecisionDeny},
		{"none", newAuth("a", "scope:admin"), []security.Attribute{security.Scope("read")}, security.DecisionDeny},
		{"not_bound", newAuth("a", "scope:admin"), []security.Attribute{security.Scope("admin")}, security.DecisionAbstain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, v.Vote(context.Background(), c.auth, c.attrs))
		})
	}
}
