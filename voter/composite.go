// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter

import (
	"context"
	"fmt"
	"slices"

	"github.com/hyperscale-stack/security"
)

// And combines voters with strict conjunction semantics. A composite
// supports the attributes its inner voters support, and when it votes:
//
//   - Any inner Deny                 => Deny.
//   - Every inner voter grants       => Grant.
//   - A Grant mixed with an Abstain  => Deny.
//   - All inner voters Abstain       => Abstain.
//
// An inner voter abstains when the route does not list its attribute: the
// conjunction then fails closed instead of silently dropping that
// requirement, so list one attribute per inner requirement — e.g.
// [Role("USER"), Role("BANNED")] for And(HasRole("USER"),
// Not(HasRole("BANNED"))).
//
// And panics if it is given no voter or a nil one.
func And(voters ...security.Voter) security.Voter {
	return newComposite("And", voters, func(votes []security.Decision, _ security.Authentication) security.Decision {
		return and(votes)
	})
}

// Or combines voters with disjunction semantics:
//
//   - Any inner Grant                => Grant.
//   - No Grant and at least one Deny => Deny.
//   - All inner voters Abstain       => Abstain.
//
// Or panics if it is given no voter or a nil one.
func Or(voters ...security.Voter) security.Voter {
	return newComposite("Or", voters, func(votes []security.Decision, _ security.Authentication) security.Decision {
		return or(votes)
	})
}

// Not inverts an inner voter: Grant becomes Deny and Deny becomes Grant — but
// only for an authenticated principal. The stock voters deny unauthenticated
// requests; Not never turns that refusal into a grant, so Not(Authenticated())
// does not admit anonymous callers (use [Anonymous] with
// security.IsAnonymous). Abstain stays Abstain. Not panics on a nil voter.
func Not(inner security.Voter) security.Voter {
	return newComposite("Not", []security.Voter{inner}, func(votes []security.Decision, auth security.Authentication) security.Decision {
		return not(votes[0], auth)
	})
}

type compositeVoter struct {
	voters []security.Voter
	// combine folds the inner votes into the composite's decision.
	combine func(votes []security.Decision, auth security.Authentication) security.Decision
}

func newComposite(
	constructor string,
	voters []security.Voter,
	combine func([]security.Decision, security.Authentication) security.Decision,
) compositeVoter {
	if len(voters) == 0 {
		panic("voter: " + constructor + ": no voter")
	}

	for i, v := range voters {
		if v == nil {
			panic(fmt.Sprintf("voter: %s: nil voter at index %d", constructor, i))
		}
	}

	return compositeVoter{voters: slices.Clone(voters), combine: combine}
}

// Supports returns true when at least one inner voter does.
func (c compositeVoter) Supports(a security.Attribute) bool {
	for _, v := range c.voters {
		if v.Supports(a) {
			return true
		}
	}

	return false
}

// Vote combines the inner votes.
func (c compositeVoter) Vote(ctx context.Context, auth security.Authentication, attrs []security.Attribute) security.Decision {
	votes := make([]security.Decision, len(c.voters))

	for i, v := range c.voters {
		votes[i] = v.Vote(ctx, auth, attrs)
	}

	return c.combine(votes, auth)
}

// and is the strict conjunction: Grant only when every vote is a Grant. An
// undefined decision counts as Deny.
func and(votes []security.Decision) security.Decision {
	grants, abstains := 0, 0

	for _, d := range votes {
		switch d {
		case security.DecisionGrant:
			grants++
		case security.DecisionAbstain:
			abstains++
		case security.DecisionDeny:
			return security.DecisionDeny
		default:
			return security.DecisionDeny
		}
	}

	switch len(votes) {
	case abstains:
		return security.DecisionAbstain
	case grants:
		return security.DecisionGrant
	default:
		return security.DecisionDeny
	}
}

// or grants on any Grant; otherwise any Deny (or undefined decision) denies;
// all abstentions abstain.
func or(votes []security.Decision) security.Decision {
	sawDeny := false

	for _, d := range votes {
		switch d {
		case security.DecisionGrant:
			return security.DecisionGrant
		case security.DecisionAbstain:
			// ignore
		case security.DecisionDeny:
			sawDeny = true
		default:
			sawDeny = true
		}
	}

	if sawDeny {
		return security.DecisionDeny
	}

	return security.DecisionAbstain
}

// not inverts d, but never grants an unauthenticated principal. An undefined
// decision counts as Deny.
func not(d security.Decision, auth security.Authentication) security.Decision {
	switch d {
	case security.DecisionGrant:
		return security.DecisionDeny
	case security.DecisionDeny:
		if auth.IsAuthenticated() {
			return security.DecisionGrant
		}

		return security.DecisionDeny
	case security.DecisionAbstain:
		return security.DecisionAbstain
	default:
		return security.DecisionDeny
	}
}
