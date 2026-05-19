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

func TestHasScopeMatchesStorageConventions(t *testing.T) {
	t.Parallel()

	v := voter.HasScope("read:mail")
	attrs := []security.Attribute{security.Scope("read:mail")}

	cases := []struct {
		name string
		auth fakeAuth
		want security.Decision
	}{
		{"bare_match", newAuth("a", "read:mail"), security.DecisionGrant},
		{"prefixed_match", newAuth("a", "scope:read:mail"), security.DecisionGrant},
		{"space_packed_match", newAuth("a", "scope:foo read:mail write:mail"), security.DecisionGrant},
		{"miss", newAuth("a", "write:mail"), security.DecisionDeny},
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
	assert.False(t, v.Supports(security.Role("ADMIN")))
}

func TestHasAnyScopeMatchesAtLeastOne(t *testing.T) {
	t.Parallel()

	v := voter.HasAnyScope("read", "write")
	attrs := []security.Attribute{security.Scope("read")}

	cases := []struct {
		name string
		auth fakeAuth
		want security.Decision
	}{
		{"first", newAuth("a", "read"), security.DecisionGrant},
		{"second", newAuth("a", "write"), security.DecisionGrant},
		{"none", newAuth("a", "admin"), security.DecisionDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, v.Vote(context.Background(), c.auth, attrs))
		})
	}
}
