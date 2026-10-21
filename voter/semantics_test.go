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

// pending is an unauthenticated value that nonetheless carries authorities:
// it proves the stock voters check IsAuthenticated, not only the authorities.
func pending(authorities ...string) fakeAuth {
	return fakeAuth{pr: security.AnonymousPrincipal(), authorities: authorities}
}

func decide(adm security.AccessDecisionManager, auth security.Authentication, attrs ...security.Attribute) error {
	return adm.Decide(context.Background(), auth, attrs)
}

// Audit probe TestZZAuditSharedADMIgnoresAttributeValue: the attribute only
// selected the voter family, so a decision manager shared by two routes
// granted the ADMIN route to a USER.
func TestSharedDecisionManagerComparesAttributeValues(t *testing.T) {
	t.Parallel()

	shared := security.NewAffirmativeDecisionManager(voter.HasRole("USER"), voter.HasRole("ADMIN"))
	user := newAuth("bob", "ROLE_USER")
	admin := newAuth("root", "ROLE_ADMIN")

	assert.ErrorIs(t, decide(shared, user, security.Role("ADMIN")), security.ErrAccessDenied)
	assert.NoError(t, decide(shared, admin, security.Role("ADMIN")))
	assert.NoError(t, decide(shared, user, security.Role("USER")))
	assert.ErrorIs(t, decide(shared, admin, security.Role("USER")), security.ErrAccessDenied)
}

func TestVotersAbstainOnValuesTheyAreNotBoundTo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		v     security.Voter
		auth  fakeAuth
		attrs []security.Attribute
	}{
		{"role", voter.HasRole("USER"), newAuth("bob", "ROLE_USER"), []security.Attribute{security.Role("ADMIN")}},
		{"scope", voter.HasScope("read"), newAuth("svc", "scope:read"), []security.Attribute{security.Scope("admin:write")}},
		{"authority", voter.HasAuthority("PERM_READ"), newAuth("svc", "PERM_READ"), []security.Attribute{security.Authority("PERM_DELETE")}},
		{"any role", voter.HasAnyRole("USER", "AUDITOR"), newAuth("bob", "ROLE_USER"), []security.Attribute{security.Role("ADMIN")}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.False(t, c.v.Supports(c.attrs[0]))
			assert.Equal(t, security.DecisionAbstain, c.v.Vote(context.Background(), c.auth, c.attrs))
			assert.ErrorIs(t, decide(security.NewAffirmativeDecisionManager(c.v), c.auth, c.attrs...), security.ErrAccessDenied)
		})
	}
}

// Audit probe TestZZAuditAuthenticatedVoterShortCircuitsRoleCheck: the
// authentication-state voters voted on every attribute, so they granted any
// route under the affirmative strategy.
func TestAuthStateVotersDoNotShortCircuitOtherAttributes(t *testing.T) {
	t.Parallel()

	user := newAuth("bob", "ROLE_USER")

	authenticated := security.NewAffirmativeDecisionManager(voter.Authenticated(), voter.HasRole("ADMIN"))
	assert.ErrorIs(t, decide(authenticated, user, security.Role("ADMIN")), security.ErrAccessDenied)

	anonymous := security.NewAffirmativeDecisionManager(voter.Anonymous(), voter.HasRole("ADMIN"))
	assert.ErrorIs(t, decide(anonymous, newAnonymous(), security.Role("ADMIN")), security.ErrAccessDenied)
}

func TestAuthStateVotersVoteOnTheirAttribute(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	cases := []struct {
		name string
		v    security.Voter
		auth fakeAuth
		attr security.Attribute
		want security.Decision
	}{
		{"authenticated grants a principal", voter.Authenticated(), newAuth("a"), security.IsAuthenticated, security.DecisionGrant},
		{"authenticated denies anonymous", voter.Authenticated(), newAnonymous(), security.IsAuthenticated, security.DecisionDeny},
		{"authenticated abstains on IsAnonymous", voter.Authenticated(), newAuth("a"), security.IsAnonymous, security.DecisionAbstain},
		{"anonymous grants anonymous", voter.Anonymous(), newAnonymous(), security.IsAnonymous, security.DecisionGrant},
		{"anonymous denies a principal", voter.Anonymous(), newAuth("a"), security.IsAnonymous, security.DecisionDeny},
		{"anonymous abstains on IsAuthenticated", voter.Anonymous(), newAnonymous(), security.IsAuthenticated, security.DecisionAbstain},
		{"authenticated abstains on a role", voter.Authenticated(), newAuth("a", "ROLE_X"), security.Role("X"), security.DecisionAbstain},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, c.v.Vote(ctx, c.auth, []security.Attribute{c.attr}))
		})
	}
}

func TestAuthStateVotersSupportOnlyTheirAttribute(t *testing.T) {
	t.Parallel()

	for name, c := range map[string]struct {
		v          security.Voter
		yes, other security.Attribute
	}{
		"authenticated": {voter.Authenticated(), security.IsAuthenticated, security.IsAnonymous},
		"anonymous":     {voter.Anonymous(), security.IsAnonymous, security.IsAuthenticated},
	} {
		assert.True(t, c.v.Supports(c.yes), name)
		assert.False(t, c.v.Supports(c.other), name)
		assert.False(t, c.v.Supports(security.Role("X")), name)
		assert.False(t, c.v.Supports(security.Scope("y")), name)
		assert.False(t, c.v.Supports(security.Authority("z")), name)
	}
}

func TestStateAttributeStrings(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "state:authenticated", security.IsAuthenticated.String())
	assert.Equal(t, "state:anonymous", security.IsAnonymous.String())
	assert.NotEqual(t, security.IsAuthenticated, security.IsAnonymous)
}

// The audit's surviving mutant "IsAuthenticated guard removed": the old
// tests used an anonymous principal without authorities.
func TestStockVotersDenyAnUnauthenticatedValueCarryingTheAuthority(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	cases := []struct {
		name string
		v    security.Voter
		auth fakeAuth
		attr security.Attribute
	}{
		{"role", voter.HasRole("ADMIN"), pending("ROLE_ADMIN"), security.Role("ADMIN")},
		{"scope", voter.HasScope("read"), pending("scope:read"), security.Scope("read")},
		{"authority", voter.HasAuthority("PERM_READ"), pending("PERM_READ"), security.Authority("PERM_READ")},
		{"permission", voter.HasPermission(), pending("ROLE_ADMIN"), security.Permission("always",
			func(context.Context, security.Authentication) bool { return true })},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, security.DecisionDeny, c.v.Vote(ctx, c.auth, []security.Attribute{c.attr}))
		})
	}
}

func TestHasAnyRoleGrantsOnlyTheRequestedRoles(t *testing.T) {
	t.Parallel()

	v := voter.HasAnyRole("ADMIN", "MANAGER")
	adm := security.NewAffirmativeDecisionManager(v)
	manager := newAuth("bob", "ROLE_MANAGER")

	// Audit: Example_compose granted a MANAGER on Role("ADMIN").
	assert.ErrorIs(t, decide(adm, manager, security.Role("ADMIN")), security.ErrAccessDenied)
	assert.NoError(t, decide(adm, manager, security.Role("ADMIN"), security.Role("MANAGER")))
	assert.NoError(t, decide(adm, manager, security.Role("MANAGER")))
}

// Review finding 4: under the unanimous strategy every voter must grant
// (AND across voters) but a multi-name voter grants when the principal
// holds any of the requested names (OR within one voter, like Spring's
// RoleVoter) — express an AND of roles with one voter per role.
func TestUnanimousStrategySemantics(t *testing.T) {
	t.Parallel()

	auditor := newAuth("ann", "ROLE_AUDITOR")
	attrs := []security.Attribute{security.Role("ADMIN"), security.Role("AUDITOR")}

	anyOf := security.NewUnanimousDecisionManager([]security.Voter{voter.HasAnyRole("ADMIN", "AUDITOR")})
	assert.NoError(t, decide(anyOf, auditor, attrs...), "OR within one voter")

	allOf := security.NewUnanimousDecisionManager([]security.Voter{voter.HasRole("ADMIN"), voter.HasRole("AUDITOR")})
	assert.ErrorIs(t, decide(allOf, auditor, attrs...), security.ErrAccessDenied, "AND across voters")
}

// Review finding 2 / user decision U2: an attribute no voter supports used
// to be ignored, which widened access under unanimous and consensus.
func TestDecideDeniesAnAttributeNoVoterSupports(t *testing.T) {
	t.Parallel()

	admin := newAuth("root", "ROLE_ADMIN")

	unanimous := security.NewUnanimousDecisionManager([]security.Voter{voter.HasRole("ADMIN"), voter.HasScope("billing:read")})
	assert.ErrorIs(t, decide(unanimous, admin, security.Role("ADMIN"), security.Scope("billing:write")), security.ErrAccessDenied)

	consensus := security.NewConsensusDecisionManager([]security.Voter{voter.HasRole("ADMIN"), voter.HasRole("USER"), voter.HasScope("read")})
	assert.ErrorIs(t, decide(consensus, admin, security.Role("ADMIN"), security.Scope("write")), security.ErrAccessDenied)

	affirmative := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
	assert.ErrorIs(t, decide(affirmative, admin, security.Role("ADMIN"), security.Role("SUPPORT")), security.ErrAccessDenied)

	fallback := security.NewUnanimousDecisionManager([]security.Voter{voter.HasRole("ADMIN")},
		security.WithAbstainFallback(security.DecisionGrant))
	assert.ErrorIs(t, decide(fallback, admin, security.Scope("anything")), security.ErrAccessDenied)
}

// Review finding 1 / user decision U1: an inner voter that abstains — its
// attribute is not listed — must not let an And grant.
func TestAndRequiresEveryInnerVoterToGrant(t *testing.T) {
	t.Parallel()

	notBanned := voter.And(voter.HasRole("USER"), voter.Not(voter.HasRole("BANNED")))
	adm := security.NewAffirmativeDecisionManager(notBanned)
	banned := newAuth("eve", "ROLE_USER", "ROLE_BANNED")
	user := newAuth("bob", "ROLE_USER")

	assert.ErrorIs(t, decide(adm, banned, security.Role("USER")), security.ErrAccessDenied,
		"the BANNED requirement is not listed: the And denies instead of ignoring it")
	assert.ErrorIs(t, decide(adm, user, security.Role("USER")), security.ErrAccessDenied)
	assert.ErrorIs(t, decide(adm, banned, security.Role("USER"), security.Role("BANNED")), security.ErrAccessDenied)
	assert.NoError(t, decide(adm, user, security.Role("USER"), security.Role("BANNED")))

	scoped := security.NewAffirmativeDecisionManager(voter.And(voter.HasRole("ADMIN"), voter.HasScope("billing:write")))
	admin := newAuth("root", "ROLE_ADMIN")
	assert.ErrorIs(t, decide(scoped, admin, security.Role("ADMIN")), security.ErrAccessDenied)
	assert.ErrorIs(t, decide(scoped, admin, security.Role("ADMIN"), security.Scope("billing:write")), security.ErrAccessDenied)
	assert.NoError(t, decide(scoped, newAuth("root", "ROLE_ADMIN", "scope:billing:write"),
		security.Role("ADMIN"), security.Scope("billing:write")))

	nested := security.NewAffirmativeDecisionManager(voter.And(
		voter.Or(voter.HasRole("ADMIN"), voter.HasRole("OWNER")),
		voter.Not(voter.HasRole("BANNED")),
	))
	owner := newAuth("olga", "ROLE_OWNER")
	assert.ErrorIs(t, decide(nested, owner, security.Role("OWNER")), security.ErrAccessDenied)
	assert.NoError(t, decide(nested, owner, security.Role("OWNER"), security.Role("BANNED")))
}

// Audit probe TestZZAuditNotGrantsAnonymous / decision 7.
func TestNotNeverGrantsAnUnauthenticatedPrincipal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	banned := security.NewAffirmativeDecisionManager(voter.Not(voter.HasRole("BANNED")))
	assert.ErrorIs(t, decide(banned, newAnonymous(), security.Role("BANNED")), security.ErrAccessDenied)
	assert.NoError(t, decide(banned, newAuth("bob", "ROLE_USER"), security.Role("BANNED")), "no over-correction")

	permission := security.NewAffirmativeDecisionManager(voter.Not(voter.HasPermission()))
	owner := security.Permission("owner", func(context.Context, security.Authentication) bool { return true })
	assert.ErrorIs(t, decide(permission, newAnonymous(), owner), security.ErrAccessDenied)

	notAuthenticated := security.NewAffirmativeDecisionManager(voter.Not(voter.Authenticated()))
	assert.ErrorIs(t, decide(notAuthenticated, newAnonymous(), security.IsAuthenticated), security.ErrAccessDenied,
		"use Anonymous() with IsAnonymous to admit anonymous callers")

	for _, c := range []struct {
		in       security.Decision
		authed   bool
		expected security.Decision
	}{
		{security.DecisionGrant, true, security.DecisionDeny},
		{security.DecisionGrant, false, security.DecisionDeny},
		{security.DecisionDeny, true, security.DecisionGrant},
		{security.DecisionDeny, false, security.DecisionDeny},
		{security.DecisionAbstain, true, security.DecisionAbstain},
		{security.DecisionAbstain, false, security.DecisionAbstain},
		{security.Decision(42), true, security.DecisionDeny},
		{security.Decision(42), false, security.DecisionDeny},
	} {
		auth := newAnonymous()
		if c.authed {
			auth = newAuth("a")
		}

		assert.Equal(t, c.expected, voter.Not(constVoter{d: c.in}).Vote(ctx, auth, nil), "in=%v authenticated=%v", c.in, c.authed)
	}
}

func TestCompositesRefuseNilOrMissingVoters(t *testing.T) {
	t.Parallel()

	ok := voter.HasRole("X")

	assert.PanicsWithValue(t, "voter: And: no voter", func() { voter.And() })
	assert.PanicsWithValue(t, "voter: Or: no voter", func() { voter.Or() })
	assert.PanicsWithValue(t, "voter: And: nil voter at index 1", func() { voter.And(ok, nil) })
	assert.PanicsWithValue(t, "voter: Or: nil voter at index 0", func() { voter.Or(nil, ok) })
	assert.PanicsWithValue(t, "voter: Not: nil voter at index 0", func() { voter.Not(nil) })
}
