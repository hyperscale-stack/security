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

// constVoter is a tiny voter returning a fixed verdict; only useful to
// drive the composite tests without setting up real authentications/attrs.
type constVoter struct{ d security.Decision }

func (c constVoter) Supports(security.Attribute) bool { return true }
func (c constVoter) Vote(context.Context, security.Authentication, []security.Attribute) security.Decision {
	return c.d
}

func TestAndTruthTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []security.Decision
		want security.Decision
	}{
		{"all_grant", []security.Decision{security.DecisionGrant, security.DecisionGrant}, security.DecisionGrant},
		{"one_deny", []security.Decision{security.DecisionGrant, security.DecisionDeny}, security.DecisionDeny},
		{"all_abstain", []security.Decision{security.DecisionAbstain, security.DecisionAbstain}, security.DecisionAbstain},
		{"grant_with_abstain", []security.Decision{security.DecisionGrant, security.DecisionAbstain}, security.DecisionGrant},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			vs := make([]security.Voter, len(c.in))
			for i, d := range c.in {
				vs[i] = constVoter{d: d}
			}

			got := voter.And(vs...).Vote(context.Background(), newAuth("a"), nil)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestOrTruthTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []security.Decision
		want security.Decision
	}{
		{"all_deny", []security.Decision{security.DecisionDeny, security.DecisionDeny}, security.DecisionDeny},
		{"one_grant", []security.Decision{security.DecisionGrant, security.DecisionDeny}, security.DecisionGrant},
		{"all_abstain", []security.Decision{security.DecisionAbstain, security.DecisionAbstain}, security.DecisionAbstain},
		{"deny_with_abstain", []security.Decision{security.DecisionDeny, security.DecisionAbstain}, security.DecisionDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			vs := make([]security.Voter, len(c.in))
			for i, d := range c.in {
				vs[i] = constVoter{d: d}
			}

			got := voter.Or(vs...).Vote(context.Background(), newAuth("a"), nil)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestNotInvertsGrantAndDeny(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want security.Decision }{
		{security.DecisionGrant, security.DecisionDeny},
		{security.DecisionDeny, security.DecisionGrant},
		{security.DecisionAbstain, security.DecisionAbstain},
	}
	for _, c := range cases {
		got := voter.Not(constVoter{d: c.in}).Vote(context.Background(), newAuth("a"), nil)
		assert.Equal(t, c.want, got, "in=%v", c.in)
	}
}
