// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import "context"

// Decision is the verdict returned by a [Voter] for a given authentication
// and attribute set. Three values are defined:
//
//   - [DecisionGrant] — the voter explicitly grants access.
//   - [DecisionDeny]  — the voter explicitly denies access.
//   - [DecisionAbstain] — the voter has no opinion (e.g. it does not support
//     any of the attributes presented). The
//     [AccessDecisionManager] strategy decides what to
//     do when every voter abstains.
type Decision int

// Voting verdicts. The numeric layout (-1/0/1) is deliberate so that
// algorithms summing decisions remain readable.
const (
	DecisionDeny    Decision = -1
	DecisionAbstain Decision = 0
	DecisionGrant   Decision = 1
)

// String returns a stable lowercase form ("permit", "deny", "abstain") used
// for OTel attribute values. "permit" is preferred over "grant" to match the
// XACML vocabulary widely understood by security teams.
func (d Decision) String() string {
	switch d {
	case DecisionGrant:
		return "permit"
	case DecisionDeny:
		return "deny"
	case DecisionAbstain:
		return "abstain"
	default:
		return "unknown"
	}
}

// Voter is the unit of authorisation logic. It inspects an [Authentication]
// against a set of [Attribute]s and returns a [Decision]. Voters MUST be
// pure (no I/O) and safe for concurrent use.
//
// The attributes name what the resource requires, and a voter evaluates the
// ones it understands (Spring Security's RoleVoter / AuthenticatedVoter
// semantics):
//
//   - Supports reports whether the voter evaluates attr — its family AND its
//     value: HasRole("ADMIN") supports Role("ADMIN"), not Role("USER"). The
//     [AccessDecisionManager] denies when an attribute is supported by no
//     voter, records an abstention for a voter that supports none of the
//     attributes, and passes every other voter only the attributes it
//     supports.
//   - Vote MUST consider only the attributes it supports, compare their
//     value with the authentication, and return [DecisionAbstain] when none
//     of them is present.
type Voter interface {
	Supports(attr Attribute) bool
	Vote(ctx context.Context, auth Authentication, attrs []Attribute) Decision
}
