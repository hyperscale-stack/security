// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// AccessDecisionManager combines the verdicts of multiple [Voter]s into a
// single decision. Three strategies are provided, named after Spring
// Security's:
//
//   - Affirmative — a single [DecisionGrant] grants access; everything else
//     denies. Abstentions are ignored. With several attributes, one
//     satisfied attribute is enough (OR).
//   - Consensus   — the majority wins. Ties default to deny; pass
//     [WithTieBreak](DecisionGrant) to flip the policy.
//   - Unanimous   — every voter that does not abstain MUST grant. A single
//     deny refuses; if every voter abstains, the result depends on
//     [WithAbstainFallback]. Unlike Spring's UnanimousBased, the voters see
//     all their attributes at once: it is an AND across voters, while a
//     multi-name voter (voter.HasAnyRole) grants when the principal holds
//     any of the requested names — express an AND of roles with one voter
//     per role, or with voter.And.
//
// Whatever the strategy, a decision is denied when one of its attributes is
// supported by no voter (a requirement nobody checks is never ignored), and
// when there is no attribute or no voter at all.
//
// Implementations are safe for concurrent use.
type AccessDecisionManager interface {
	// Decide returns nil on grant, [ErrAccessDenied] on deny.
	// Wrapping callers add a short message indicating the strategy used.
	Decide(ctx context.Context, auth Authentication, attrs []Attribute) error
}

// admOption configures NewAffirmative/NewConsensus/NewUnanimous.
type admOption func(*admConfig)

type admConfig struct {
	tieBreak        Decision // for consensus
	abstainFallback Decision // for unanimous
}

// WithTieBreak controls the consensus strategy when grant and deny votes
// are equal in number. Default: DecisionDeny.
func WithTieBreak(d Decision) admOption { //nolint:revive // exported via constructors
	return func(c *admConfig) { c.tieBreak = d }
}

// WithAbstainFallback controls the verdict when every unanimous voter
// abstains. Default: DecisionDeny.
func WithAbstainFallback(d Decision) admOption { //nolint:revive // exported via constructors
	return func(c *admConfig) { c.abstainFallback = d }
}

// NewAffirmativeDecisionManager returns an [AccessDecisionManager] that
// grants access as soon as one voter does, and denies otherwise. It panics
// if one of the voters is nil.
func NewAffirmativeDecisionManager(voters ...Voter) AccessDecisionManager {
	return &accessDecisionManager{
		strategy: "affirmative",
		voters:   cloneVoters("NewAffirmativeDecisionManager", voters),
		decide:   affirmative,
	}
}

// NewConsensusDecisionManager returns an [AccessDecisionManager] that
// follows majority rule. Pass [WithTieBreak] to override the default
// (deny-on-tie) behavior. It panics if one of the voters is nil.
func NewConsensusDecisionManager(voters []Voter, opts ...admOption) AccessDecisionManager {
	cfg := admConfig{tieBreak: DecisionDeny}
	for _, o := range opts {
		o(&cfg)
	}

	return &accessDecisionManager{
		strategy: "consensus",
		voters:   cloneVoters("NewConsensusDecisionManager", voters),
		decide:   consensus(cfg.tieBreak),
	}
}

// NewUnanimousDecisionManager returns an [AccessDecisionManager] that
// refuses on a single deny and otherwise grants when at least one voter
// grants. Pass [WithAbstainFallback] to control the all-abstain case. It
// panics if one of the voters is nil.
func NewUnanimousDecisionManager(voters []Voter, opts ...admOption) AccessDecisionManager {
	cfg := admConfig{abstainFallback: DecisionDeny}
	for _, o := range opts {
		o(&cfg)
	}

	return &accessDecisionManager{
		strategy: "unanimous",
		voters:   cloneVoters("NewUnanimousDecisionManager", voters),
		decide:   unanimous(cfg.abstainFallback),
	}
}

type accessDecisionManager struct {
	strategy string
	voters   []Voter
	decide   func(votes []Decision) Decision
}

// Decide implements [AccessDecisionManager].
//
// Contract violations fail closed: a nil auth is treated as [Anonymous], a
// nil attribute denies the request before any voter runs, and a voter
// returning a value other than [DecisionGrant] or [DecisionAbstain] is
// counted as [DecisionDeny].
func (m *accessDecisionManager) Decide(ctx context.Context, auth Authentication, attrs []Attribute) error {
	ctx, span := tracer().Start(ctx, "security.AccessDecisionManager.Decide")
	defer span.End()

	span.SetAttributes(
		AttrStrategy.String(m.strategy),
		AttrAttributes.String(joinAttributes(attrs)),
	)

	if auth == nil {
		auth = Anonymous()
	}

	final := DecisionDeny

	if !containsNil(attrs) {
		if unsupported := m.unsupported(attrs); unsupported > 0 {
			span.SetAttributes(AttrAttributesUnsupported.Int(unsupported))
		} else {
			final = m.decide(m.votes(ctx, auth, attrs))
		}
	}

	span.SetAttributes(AttrDecision.String(final.String()))

	if final == DecisionGrant {
		return nil
	}

	recordFailure(span, ErrAccessDenied)

	return ErrAccessDenied
}

// unsupported counts the attributes that no voter supports.
func (m *accessDecisionManager) unsupported(attrs []Attribute) int {
	count := 0

	for _, a := range attrs {
		if !slices.ContainsFunc(m.voters, func(v Voter) bool { return v.Supports(a) }) {
			count++
		}
	}

	return count
}

// votes collects one normalized vote per voter: an abstention for a voter
// that supports none of the attributes, otherwise the voter's verdict on
// the attributes it supports — and only those.
func (m *accessDecisionManager) votes(ctx context.Context, auth Authentication, attrs []Attribute) []Decision {
	votes := make([]Decision, 0, len(m.voters))

	for _, v := range m.voters {
		supported := supportedBy(v, attrs)
		if len(supported) == 0 {
			votes = append(votes, DecisionAbstain)

			continue
		}

		votes = append(votes, normalize(v.Vote(ctx, auth, supported)))
	}

	return votes
}

// normalize maps every value but Grant and Abstain to Deny, so an undefined
// Decision can never be mistaken for an abstention (which a fallback could
// turn into a grant).
func normalize(d Decision) Decision {
	switch d {
	case DecisionGrant, DecisionAbstain:
		return d
	case DecisionDeny:
		return DecisionDeny
	default:
		return DecisionDeny
	}
}

// affirmative returns Grant on first grant, Deny otherwise. Abstentions are
// ignored.
func affirmative(votes []Decision) Decision {
	denySeen := false

	for _, v := range votes {
		switch v {
		case DecisionGrant:
			return DecisionGrant
		case DecisionDeny:
			denySeen = true
		case DecisionAbstain:
			// ignore
		}
	}

	if denySeen {
		return DecisionDeny
	}

	return DecisionDeny // all abstain -> deny by default
}

// consensus returns Grant if grants > denies, Deny if denies > grants, and
// the configured tie-break otherwise. All abstentions -> deny by default.
func consensus(tieBreak Decision) func([]Decision) Decision {
	return func(votes []Decision) Decision {
		grants, denies := 0, 0

		for _, v := range votes {
			switch v {
			case DecisionGrant:
				grants++
			case DecisionDeny:
				denies++
			case DecisionAbstain:
				// ignore
			}
		}

		switch {
		case grants == 0 && denies == 0:
			return DecisionDeny
		case grants > denies:
			return DecisionGrant
		case denies > grants:
			return DecisionDeny
		default:
			return tieBreak
		}
	}
}

// unanimous returns Deny on any deny; otherwise Grant if at least one voter
// granted; otherwise the configured all-abstain fallback.
func unanimous(allAbstainFallback Decision) func([]Decision) Decision {
	return func(votes []Decision) Decision {
		grantSeen := false

		for _, v := range votes {
			if v == DecisionDeny {
				return DecisionDeny
			}

			if v == DecisionGrant {
				grantSeen = true
			}
		}

		if grantSeen {
			return DecisionGrant
		}

		return allAbstainFallback
	}
}

// containsNil reports whether attrs holds a nil Attribute.
func containsNil(attrs []Attribute) bool {
	for _, a := range attrs {
		if a == nil {
			return true
		}
	}

	return false
}

// supportedBy returns the attributes v supports, in order.
func supportedBy(v Voter, attrs []Attribute) []Attribute {
	var out []Attribute

	for _, a := range attrs {
		if v.Supports(a) {
			out = append(out, a)
		}
	}

	return out
}

func joinAttributes(attrs []Attribute) string {
	if len(attrs) == 0 {
		return ""
	}

	parts := make([]string, len(attrs))
	for i, a := range attrs {
		if a == nil {
			parts[i] = "<nil>"

			continue
		}

		parts[i] = a.String()
	}

	return strings.Join(parts, ",")
}

// cloneVoters copies the voter list, panicking on a nil voter: it would
// otherwise surface as a nil dereference on the first request.
func cloneVoters(constructor string, in []Voter) []Voter {
	for i, v := range in {
		if v == nil {
			panic(fmt.Sprintf("security: %s: nil Voter at index %d", constructor, i))
		}
	}

	cp := make([]Voter, len(in))
	copy(cp, in)

	return cp
}
