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

// recordingVoter supports the attributes with the given prefix and records
// the attributes it is asked to vote on.
type recordingVoter struct {
	scriptedVoter

	seen []string
}

func (r *recordingVoter) Vote(ctx context.Context, auth security.Authentication, attrs []security.Attribute) security.Decision {
	for _, a := range attrs {
		r.seen = append(r.seen, a.String())
	}

	return r.scriptedVoter.Vote(ctx, auth, attrs)
}

// User decision U2: an attribute that no voter supports denies the
// decision, whatever the strategy or the abstain fallback — it used to be
// ignored, which widened access under unanimous and consensus.
func TestDecideDeniesWhenAnAttributeIsSupportedByNoVoter(t *testing.T) {
	alice := newFakeAuth("alice").withAuthenticated()
	attrs := []security.Attribute{stringAttr("scope:read"), stringAttr("role:ADMIN"), stringAttr("role:USER")}

	for name, adm := range map[string]security.AccessDecisionManager{
		"affirmative": security.NewAffirmativeDecisionManager(&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant}),
		"consensus": security.NewConsensusDecisionManager([]security.Voter{
			&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
		}, security.WithTieBreak(security.DecisionGrant)),
		"unanimous": security.NewUnanimousDecisionManager([]security.Voter{
			&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
		}, security.WithAbstainFallback(security.DecisionGrant)),
	} {
		spans := spanRecorder(func() {
			assert.ErrorIs(t, adm.Decide(context.Background(), alice, attrs), security.ErrAccessDenied, name)
		})

		require.Len(t, spans, 1, name)
		assert.Equal(t, "2", findAttr(spans[0].Attributes(), security.AttrAttributesUnsupported), name)
		assert.Equal(t, security.ErrorClassAccessDenied, findAttr(spans[0].Attributes(), security.AttrErrorType), name)
	}
}

func TestDecideSupportedAttributesRecordNoUnsupportedCount(t *testing.T) {
	adm := security.NewAffirmativeDecisionManager(&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant})

	spans := spanRecorder(func() {
		require.NoError(t, adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
			[]security.Attribute{stringAttr("scope:read")}))
	})

	require.Len(t, spans, 1)
	assert.Empty(t, findAttr(spans[0].Attributes(), security.AttrAttributesUnsupported))
}

// Review nit 14: the decision manager hands each voter only the attributes
// it supports, enforcing the Voter contract for custom voters too.
func TestDecidePassesEachVoterOnlyTheAttributesItSupports(t *testing.T) {
	t.Parallel()

	scopes := &recordingVoter{scriptedVoter: scriptedVoter{prefix: "scope:", vote: security.DecisionGrant}}
	roles := &recordingVoter{scriptedVoter: scriptedVoter{prefix: "role:", vote: security.DecisionGrant}}
	adm := security.NewUnanimousDecisionManager([]security.Voter{scopes, roles})

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read"), stringAttr("role:ADMIN"), stringAttr("scope:write")})

	require.NoError(t, err)
	assert.Equal(t, []string{"scope:read", "scope:write"}, scopes.seen)
	assert.Equal(t, []string{"role:ADMIN"}, roles.seen)
}

// The audit's positive baseline, pinned: every strategy denies when there is
// no attribute, when every voter abstains, and when there is no voter.
func TestEveryStrategyDeniesByDefault(t *testing.T) {
	t.Parallel()

	alice := newFakeAuth("alice").withAuthenticated()
	abstain := &scriptedVoter{prefix: "scope:", vote: security.DecisionAbstain}

	for name, adm := range map[string]security.AccessDecisionManager{
		"affirmative":           security.NewAffirmativeDecisionManager(abstain),
		"consensus":             security.NewConsensusDecisionManager([]security.Voter{abstain}),
		"unanimous":             security.NewUnanimousDecisionManager([]security.Voter{abstain}),
		"affirmative no voters": security.NewAffirmativeDecisionManager(),
	} {
		for attrsName, attrs := range map[string][]security.Attribute{
			"nil attrs":   nil,
			"empty attrs": {},
			"abstained":   {stringAttr("scope:read")},
		} {
			assert.ErrorIs(t, adm.Decide(context.Background(), alice, attrs), security.ErrAccessDenied, "%s, %s", name, attrsName)
		}
	}
}

func TestConsensusDeniesOnAMajorityOfDenies(t *testing.T) {
	t.Parallel()

	adm := security.NewConsensusDecisionManager([]security.Voter{
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionDeny},
		&scriptedVoter{prefix: "scope:", vote: security.DecisionGrant},
	}, security.WithTieBreak(security.DecisionGrant))

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(), []security.Attribute{stringAttr("scope:read")})

	assert.ErrorIs(t, err, security.ErrAccessDenied)
}

func TestStateAttributeStrings(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "state:authenticated", security.IsAuthenticated.String())
	assert.Equal(t, "state:anonymous", security.IsAnonymous.String())
}
