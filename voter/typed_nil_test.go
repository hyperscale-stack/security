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

// ptrVoter is a voter implemented on a pointer: its typed nil satisfies
// security.Voter and panics on the first vote.
type ptrVoter struct{}

func (*ptrVoter) Supports(security.Attribute) bool { return true }
func (*ptrVoter) Vote(context.Context, security.Authentication, []security.Attribute) security.Decision {
	return security.DecisionGrant
}

// Audit I-27: a typed-nil inner voter was accepted and panicked on the
// first decision.
func TestCompositesRefuseTypedNilVoters(t *testing.T) {
	t.Parallel()

	var typedNil *ptrVoter

	assert.PanicsWithValue(t, "voter: And: nil voter at index 1", func() { voter.And(voter.Authenticated(), typedNil) })
	assert.PanicsWithValue(t, "voter: Or: nil voter at index 0", func() { voter.Or(typedNil) })
	assert.PanicsWithValue(t, "voter: Not: nil voter at index 0", func() { voter.Not(typedNil) })
}
