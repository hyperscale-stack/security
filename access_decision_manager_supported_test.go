// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// User decision U2: an attribute that no voter supports denies the
// decision, whatever the strategy or the abstain fallback — it used to be
// ignored, which widened access under unanimous and consensus.
func TestDecideDeniesWhenAnAttributeIsSupportedByNoVoter(t *testing.T) {
	alice := newFakeAuth("alice").withAuthenticated()
	attrs := []security.Attribute{stringAttr("scope:read"), stringAttr("role:ADMIN"), stringAttr("role:USER")}

	for name, adm := range map[string]security.AccessDecisionManager{
		"affirmative": security.NewAffirmativeDecisionManager(prefixVoter(t, "scope:", security.DecisionGrant)),
		"consensus": security.NewConsensusDecisionManager([]security.Voter{
			prefixVoter(t, "scope:", security.DecisionGrant),
		}, security.WithTieBreak(security.DecisionGrant)),
		"unanimous": security.NewUnanimousDecisionManager([]security.Voter{
			prefixVoter(t, "scope:", security.DecisionGrant),
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
	adm := security.NewAffirmativeDecisionManager(prefixVoter(t, "scope:", security.DecisionGrant))

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

	// Each mock accepts one Vote, with exactly the attributes it supports.
	scopes := security.NewMockVoter(t)
	scopes.EXPECT().Supports(mock.Anything).RunAndReturn(hasPrefix("scope:"))
	scopes.EXPECT().Vote(mock.Anything, mock.Anything, []security.Attribute{stringAttr("scope:read"), stringAttr("scope:write")}).
		Return(security.DecisionGrant).Once()

	roles := security.NewMockVoter(t)
	roles.EXPECT().Supports(mock.Anything).RunAndReturn(hasPrefix("role:"))
	roles.EXPECT().Vote(mock.Anything, mock.Anything, []security.Attribute{stringAttr("role:ADMIN")}).
		Return(security.DecisionGrant).Once()

	adm := security.NewUnanimousDecisionManager([]security.Voter{scopes, roles})

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read"), stringAttr("role:ADMIN"), stringAttr("scope:write")})

	require.NoError(t, err)
}

// The audit's positive baseline, pinned: every strategy denies when there is
// no attribute, when every voter abstains, and when there is no voter.
func TestEveryStrategyDeniesByDefault(t *testing.T) {
	t.Parallel()

	alice := newFakeAuth("alice").withAuthenticated()
	abstain := prefixVoter(t, "scope:", security.DecisionAbstain)

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

// Review finding 1 (user decision): no attribute or no voter denies whatever
// the strategy, tie-break and abstain fallback; the fallback only decides
// for voters that support an attribute and abstain.
func TestDecideDeniesWithoutAttributesOrVotersWhateverTheFallback(t *testing.T) {
	t.Parallel()

	abstain := prefixVoter(t, "scope:", security.DecisionAbstain)
	grant := prefixVoter(t, "scope:", security.DecisionGrant)

	for name, adm := range map[string]security.AccessDecisionManager{
		"unanimous, fallback grant": security.NewUnanimousDecisionManager([]security.Voter{abstain},
			security.WithAbstainFallback(security.DecisionGrant)),
		"unanimous, fallback grant, granting voter": security.NewUnanimousDecisionManager([]security.Voter{grant},
			security.WithAbstainFallback(security.DecisionGrant)),
		"unanimous, fallback grant, no voters": security.NewUnanimousDecisionManager(nil,
			security.WithAbstainFallback(security.DecisionGrant)),
		"consensus, tie-break grant, no voters": security.NewConsensusDecisionManager(nil,
			security.WithTieBreak(security.DecisionGrant)),
		"affirmative, granting voter": security.NewAffirmativeDecisionManager(grant),
	} {
		for attrsName, attrs := range map[string][]security.Attribute{"nil attrs": nil, "empty attrs": {}} {
			for _, auth := range []security.Authentication{security.Anonymous(), newFakeAuth("alice").withAuthenticated()} {
				err := adm.Decide(context.Background(), auth, attrs)
				assert.ErrorIs(t, err, security.ErrAccessDenied, "%s, %s, authenticated=%v", name, attrsName, auth.IsAuthenticated())
			}
		}
	}

	noVoters := security.NewUnanimousDecisionManager(nil, security.WithAbstainFallback(security.DecisionGrant))
	assert.ErrorIs(t, noVoters.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(),
		[]security.Attribute{stringAttr("scope:read")}), security.ErrAccessDenied)
}

func TestConsensusDeniesOnAMajorityOfDenies(t *testing.T) {
	t.Parallel()

	adm := security.NewConsensusDecisionManager([]security.Voter{
		prefixVoter(t, "scope:", security.DecisionDeny),
		prefixVoter(t, "scope:", security.DecisionDeny),
		prefixVoter(t, "scope:", security.DecisionGrant),
	}, security.WithTieBreak(security.DecisionGrant))

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(), []security.Attribute{stringAttr("scope:read")})

	assert.ErrorIs(t, err, security.ErrAccessDenied)
}

func TestStateAttributeStrings(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "state:authenticated", security.IsAuthenticated.String())
	assert.Equal(t, "state:anonymous", security.IsAnonymous.String())
}
