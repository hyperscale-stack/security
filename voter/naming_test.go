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

func TestAuthorityPrefixes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "ROLE_", security.RolePrefix)
	assert.Equal(t, "scope:", security.ScopePrefix)
	assert.Equal(t, security.RolePrefix+"ADMIN", security.Role("ADMIN").String())
	assert.Equal(t, security.ScopePrefix+"read:mail", security.Scope("read:mail").String())
}

// Audit probe TestZZAuditFlatNamespace: a bare "admin" authority satisfied
// HasRole("admin") and HasScope("admin"), and a "scope:a b" authority was
// split on spaces.
func TestRolesAndScopesUseTheirOwnNamespace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	cases := []struct {
		name string
		v    security.Voter
		auth fakeAuth
		attr security.Attribute
		want security.Decision
	}{
		{"bare authority is not a role", voter.HasRole("admin"), newAuth("svc", "admin"), security.Role("admin"), security.DecisionDeny},
		{"bare authority is not a scope", voter.HasScope("admin"), newAuth("svc", "admin"), security.Scope("admin"), security.DecisionDeny},
		{"scope is not a role", voter.HasRole("admin"), newAuth("svc", "scope:admin"), security.Role("admin"), security.DecisionDeny},
		{"role is not a scope", voter.HasScope("admin"), newAuth("svc", "ROLE_admin"), security.Scope("admin"), security.DecisionDeny},
		{"space-packed scopes are one authority", voter.HasScope("billing:admin"),
			newAuth("u", "scope:payments:write billing:admin"), security.Scope("billing:admin"), security.DecisionDeny},
		{"prefixed role", voter.HasRole("admin"), newAuth("u", "ROLE_admin"), security.Role("admin"), security.DecisionGrant},
		{"prefixed scope", voter.HasScope("admin"), newAuth("u", "scope:admin"), security.Scope("admin"), security.DecisionGrant},
		{"authority verbatim", voter.HasAuthority("admin"), newAuth("u", "admin"), security.Authority("admin"), security.DecisionGrant},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, c.v.Vote(ctx, c.auth, []security.Attribute{c.attr}))
		})
	}
}

func TestVoterConstructorsRefuseUnmatchableNames(t *testing.T) {
	t.Parallel()

	cases := []struct {
		want string
		fn   func()
	}{
		{"voter: HasAnyRole: no role", func() { voter.HasAnyRole() }},
		{"voter: HasRole: empty role", func() { voter.HasRole("") }},
		{`voter: HasRole: role "ROLE_ADMIN" must not start with "ROLE_"`, func() { voter.HasRole("ROLE_ADMIN") }},
		{`voter: HasAnyRole: role "ROLE_X" must not start with "ROLE_"`, func() { voter.HasAnyRole("A", "ROLE_X") }},
		{"voter: HasAnyScope: no scope", func() { voter.HasAnyScope() }},
		{`voter: HasScope: scope "" is not an RFC 6749 scope-token`, func() { voter.HasScope("") }},
		{`voter: HasScope: scope "a b" is not an RFC 6749 scope-token`, func() { voter.HasScope("a b") }},
		{`voter: HasScope: scope "a\"b" is not an RFC 6749 scope-token`, func() { voter.HasScope(`a"b`) }},
		{`voter: HasScope: scope "a\\b" is not an RFC 6749 scope-token`, func() { voter.HasScope(`a\b`) }},
		{`voter: HasScope: scope "café" is not an RFC 6749 scope-token`, func() { voter.HasScope("café") }},
		{`voter: HasAnyScope: scope "scope:read" must not start with "scope:"`, func() { voter.HasAnyScope("scope:read") }},
		{"voter: HasScope: scope \"a\\x7fb\" is not an RFC 6749 scope-token", func() { voter.HasScope("a\x7fb") }},
		{"voter: HasAnyAuthority: no authority", func() { voter.HasAnyAuthority() }},
		{"voter: HasAuthority: empty authority", func() { voter.HasAuthority("") }},
	}

	for _, c := range cases {
		assert.PanicsWithValue(t, c.want, c.fn)
	}

	assert.NotPanics(t, func() { voter.HasScope("read:mail") })
	assert.NotPanics(t, func() { voter.HasScope("!#$%&'()*+,-./:;<=>?@[]^_`{|}~") })
}

// Attributes no voter can be bound to are unsatisfiable: denied.
func TestUnmatchableAttributesAreDenied(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"), voter.HasScope("read"))
	root := newAuth("root", "ROLE_ADMIN", "ROLE_ROLE_ADMIN", "ROLE_", "scope:read")

	for _, attr := range []security.Attribute{security.Role("ROLE_ADMIN"), security.Role(""), security.Scope("")} {
		assert.ErrorIs(t, decide(adm, root, attr), security.ErrAccessDenied, attr.String())
	}
}
