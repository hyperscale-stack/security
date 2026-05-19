// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"

	"github.com/hyperscale-stack/security"
)

// And combines voters with conjunction semantics:
//
//   - Any inner Deny  => Deny.
//   - At least one Grant and no Deny => Grant.
//   - All inner voters Abstain      => Abstain.
//
// Inner abstentions never block the conjunction: a permission voter that
// does not apply to the current attributes should not single-handedly veto.
func And(voters ...security.Voter) security.Voter {
	return compositeVoter{voters: voters, mode: composeAnd}
}

// Or combines voters with disjunction semantics:
//
//   - Any inner Grant => Grant.
//   - No Grant and at least one Deny => Deny.
//   - All inner voters Abstain      => Abstain.
func Or(voters ...security.Voter) security.Voter {
	return compositeVoter{voters: voters, mode: composeOr}
}

// Not inverts an inner voter: Grant <-> Deny; Abstain stays Abstain.
func Not(inner security.Voter) security.Voter {
	return compositeVoter{voters: []security.Voter{inner}, mode: composeNot}
}

type composeMode int

const (
	composeAnd composeMode = iota
	composeOr
	composeNot
)

type compositeVoter struct {
	voters []security.Voter
	mode   composeMode
}

// Supports returns true when at least one inner voter does, plus always for
// the auth-state voters embedded inside the composite (they Supports anything).
func (c compositeVoter) Supports(a security.Attribute) bool {
	for _, v := range c.voters {
		if v.Supports(a) {
			return true
		}
	}

	return false
}

func (c compositeVoter) Vote(ctx context.Context, auth security.Authentication, attrs []security.Attribute) security.Decision {
	if c.mode == composeNot {
		switch c.voters[0].Vote(ctx, auth, attrs) {
		case security.DecisionGrant:
			return security.DecisionDeny
		case security.DecisionDeny:
			return security.DecisionGrant
		case security.DecisionAbstain:
			return security.DecisionAbstain
		}
	}

	var (
		sawGrant bool
		sawDeny  bool
	)

	for _, v := range c.voters {
		switch v.Vote(ctx, auth, attrs) {
		case security.DecisionGrant:
			sawGrant = true
		case security.DecisionDeny:
			sawDeny = true
		case security.DecisionAbstain:
			// ignore
		}
	}

	switch c.mode {
	case composeAnd:
		switch {
		case sawDeny:
			return security.DecisionDeny
		case sawGrant:
			return security.DecisionGrant
		default:
			return security.DecisionAbstain
		}
	case composeOr:
		switch {
		case sawGrant:
			return security.DecisionGrant
		case sawDeny:
			return security.DecisionDeny
		default:
			return security.DecisionAbstain
		}
	case composeNot:
		// Unreachable: composeNot is handled by the early return above; the
		// case is here only to make the switch exhaustive.
		return security.DecisionAbstain
	}

	return security.DecisionAbstain
}
