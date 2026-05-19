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
// Supports is a fast-path filter: a voter that does not recognize any of the
// passed attributes SHOULD return false to short-circuit the call. When
// Supports returns false, the [AccessDecisionManager] records an abstention
// for the voter without invoking Vote.
type Voter interface {
	Supports(attr Attribute) bool
	Vote(ctx context.Context, auth Authentication, attrs []Attribute) Decision
}
