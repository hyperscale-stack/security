// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel/codes"
)

// AccessDecisionManager combines the verdicts of multiple [Voter]s into a
// single decision. Three strategies are provided, mirroring Spring Security:
//
//   - Affirmative — a single [DecisionGrant] grants access; everything else
//     denies. Abstentions are ignored. The strictest "fail closed
//     by default" policy.
//   - Consensus   — the majority wins. Ties default to deny; pass
//     [WithTieBreak](DecisionGrant) to flip the policy.
//   - Unanimous   — every voter that does not abstain MUST grant. A single
//     deny refuses; if every voter abstains, the result depends on
//     [WithAbstainFallback].
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
// grants access as soon as one voter does, and denies otherwise.
func NewAffirmativeDecisionManager(voters ...Voter) AccessDecisionManager {
	return &accessDecisionManager{
		strategy: "affirmative",
		voters:   cloneVoters(voters),
		decide:   affirmative,
	}
}

// NewConsensusDecisionManager returns an [AccessDecisionManager] that
// follows majority rule. Pass [WithTieBreak] to override the default
// (deny-on-tie) behavior.
func NewConsensusDecisionManager(voters []Voter, opts ...admOption) AccessDecisionManager {
	cfg := admConfig{tieBreak: DecisionDeny}
	for _, o := range opts {
		o(&cfg)
	}

	return &accessDecisionManager{
		strategy: "consensus",
		voters:   cloneVoters(voters),
		decide:   consensus(cfg.tieBreak),
	}
}

// NewUnanimousDecisionManager returns an [AccessDecisionManager] that
// refuses on a single deny and otherwise grants when at least one voter
// grants. Pass [WithAbstainFallback] to control the all-abstain case.
func NewUnanimousDecisionManager(voters []Voter, opts ...admOption) AccessDecisionManager {
	cfg := admConfig{abstainFallback: DecisionDeny}
	for _, o := range opts {
		o(&cfg)
	}

	return &accessDecisionManager{
		strategy: "unanimous",
		voters:   cloneVoters(voters),
		decide:   unanimous(cfg.abstainFallback),
	}
}

type accessDecisionManager struct {
	strategy string
	voters   []Voter
	decide   func(votes []Decision) Decision
}

// Decide implements [AccessDecisionManager].
func (m *accessDecisionManager) Decide(ctx context.Context, auth Authentication, attrs []Attribute) error {
	ctx, span := tracer().Start(ctx, "security.AccessDecisionManager.Decide")
	defer span.End()

	span.SetAttributes(
		AttrStrategy.String(m.strategy),
		AttrAttributes.String(joinAttributes(attrs)),
	)

	votes := make([]Decision, 0, len(m.voters))

	for _, v := range m.voters {
		if !anySupported(v, attrs) {
			votes = append(votes, DecisionAbstain)

			continue
		}

		votes = append(votes, v.Vote(ctx, auth, attrs))
	}

	final := m.decide(votes)
	span.SetAttributes(AttrDecision.String(final.String()))

	if final == DecisionGrant {
		return nil
	}

	span.SetStatus(codes.Error, ErrAccessDenied.Error())

	return ErrAccessDenied
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

func anySupported(v Voter, attrs []Attribute) bool {
	for _, a := range attrs {
		if v.Supports(a) {
			return true
		}
	}

	return false
}

func joinAttributes(attrs []Attribute) string {
	if len(attrs) == 0 {
		return ""
	}

	parts := make([]string, len(attrs))
	for i, a := range attrs {
		parts[i] = a.String()
	}

	return strings.Join(parts, ",")
}

func cloneVoters(in []Voter) []Voter {
	cp := make([]Voter, len(in))
	copy(cp, in)

	return cp
}
