// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAffirmativeGrantsOnAnyGrant(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
	)

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	require.NoError(t, err)
}

func TestAffirmativeDeniesWhenNoGrant(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionAbstain},
	)

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	assert.ErrorIs(t, err, security.ErrAccessDenied)
}

func TestAffirmativeDeniesWhenAllAbstain(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(
		&scriptedVoter{prefix: "role:", vote: security.DecisionGrant}, // does not support scope:
	)

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	assert.ErrorIs(t, err, security.ErrAccessDenied,
		"unsupported attributes cause abstention, not silent grant")
}

func TestConsensusFollowsMajority(t *testing.T) {
	t.Parallel()

	adm := security.NewConsensusDecisionManager([]security.Voter{
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
	})

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	require.NoError(t, err)
}

func TestConsensusTieBreakDefaultsToDeny(t *testing.T) {
	t.Parallel()

	adm := security.NewConsensusDecisionManager([]security.Voter{
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
	})

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	assert.ErrorIs(t, err, security.ErrAccessDenied)
}

func TestConsensusTieBreakOverride(t *testing.T) {
	t.Parallel()

	adm := security.NewConsensusDecisionManager([]security.Voter{
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
	}, security.WithTieBreak(security.DecisionGrant))

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	require.NoError(t, err)
}

func TestUnanimousDeniesOnAnyDeny(t *testing.T) {
	t.Parallel()

	adm := security.NewUnanimousDecisionManager([]security.Voter{
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
	})

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	assert.ErrorIs(t, err, security.ErrAccessDenied)
}

func TestUnanimousGrantsWhenAtLeastOneGrantsAndNoneDeny(t *testing.T) {
	t.Parallel()

	adm := security.NewUnanimousDecisionManager([]security.Voter{
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
		&scriptedVoter{prefix: "role:", vote: security.DecisionGrant}, // abstains on scope:
	})

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	require.NoError(t, err)
}

func TestUnanimousAbstainFallbackDefaultsToDeny(t *testing.T) {
	t.Parallel()

	adm := security.NewUnanimousDecisionManager([]security.Voter{
		&scriptedVoter{prefix: "role:", vote: security.DecisionGrant}, // abstains on scope:
	})

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	assert.ErrorIs(t, err, security.ErrAccessDenied)
}

func TestUnanimousAbstainFallbackOverride(t *testing.T) {
	t.Parallel()

	adm := security.NewUnanimousDecisionManager([]security.Voter{
		&scriptedVoter{prefix: "role:", vote: security.DecisionGrant},
	}, security.WithAbstainFallback(security.DecisionGrant))

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")})

	require.NoError(t, err)
}

func TestADMSpanCarriesStrategyAndDecision(t *testing.T) {
	adm := security.NewAffirmativeDecisionManager(
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
	)

	spans := spanRecorder(func() {
		_ = adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
			[]security.Attribute{stringAttr("scope:read")})
	})

	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal(t, "security.AccessDecisionManager.Decide", span.Name())
	assert.Equal(t, "affirmative", findAttr(span.Attributes(), security.AttrStrategy))
	assert.Equal(t, "permit", findAttr(span.Attributes(), security.AttrDecision))
	assert.Equal(t, "scope:read", findAttr(span.Attributes(), security.AttrAttributes))
}

func TestADMSpanRecordsErrorOnDeny(t *testing.T) {
	adm := security.NewAffirmativeDecisionManager(
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
	)

	spans := spanRecorder(func() {
		_ = adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
			[]security.Attribute{stringAttr("scope:read")})
	})

	require.Len(t, spans, 1)
	assert.Equal(t, "Error", spans[0].Status().Code.String())
}

func TestDecisionString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		d    security.Decision
		want string
	}{
		{security.DecisionGrant, "permit"},
		{security.DecisionDeny, "deny"},
		{security.DecisionAbstain, "abstain"},
		{security.Decision(42), "unknown"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.d.String())
	}
}
