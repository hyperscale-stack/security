// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// credentialSentinels are the sentinels that state a verdict on the
// credentials; a contract violation must wrap none of them.
var credentialSentinels = []error{
	security.ErrInvalidCredentials,
	security.ErrClientSecretMismatch,
	security.ErrTokenExpired,
	security.ErrTokenNotFound,
	security.ErrUnsupportedCredential,
	security.ErrAuthenticationRequired,
	security.ErrInvalidRequest,
	security.ErrUnavailable,
}

func assertNoCredentialSentinel(t *testing.T, err error) {
	t.Helper()

	for _, s := range credentialSentinels {
		assert.NotErrorIs(t, err, s, "a contract violation is not a verdict on the credentials")
	}
}

func TestNewSentinelsAreDistinctSecurityErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want string
	}{
		{security.ErrAuthenticationRequired, "security: authentication required"},
		{security.ErrInvalidRequest, "security: invalid authentication request"},
		{security.ErrUnavailable, "security: authentication temporarily unavailable"},
	}

	for _, c := range cases {
		assert.Equal(t, c.want, c.err.Error())

		_, ok := any(c.err).(security.SecurityError)
		assert.True(t, ok, "%v must implement SecurityError", c.err)

		for _, other := range []error{
			security.ErrInvalidCredentials, security.ErrAccessDenied, security.ErrUnsupportedCredential,
			security.ErrNoExtractor, security.ErrAuthenticatorRefused,
		} {
			assert.NotErrorIs(t, c.err, other)
		}
	}

	assert.NotErrorIs(t, security.ErrAuthenticationRequired, security.ErrInvalidRequest)
	assert.NotErrorIs(t, security.ErrInvalidRequest, security.ErrUnavailable)
	assert.NotErrorIs(t, security.ErrUnavailable, security.ErrAuthenticationRequired)
}

// Audit probe TestZZAuditEngineNilResultPanics: an authenticator returning
// (nil, nil) — or an unauthenticated value without an error — breaks the
// Authenticator contract. The Engine must fail closed, never panic.
func TestEngineFailsClosedWhenAnAuthenticatorReturnsNoAuthenticatedValue(t *testing.T) {
	t.Parallel()

	cases := map[string]security.Authentication{
		"nil result":             nil,
		"typed nil result":       typedNilAuth,
		"unauthenticated result": newFakeAuth("alice").withCredentials("pw"),
	}

	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			engine := security.NewEngine(
				security.NewManager(authenticatorReturning(t, result, nil)),
				extractorReturning(t, newFakeAuth("alice").withCredentials("pw"), nil),
			)

			var (
				ctx  context.Context
				auth security.Authentication
				err  error
			)

			require.NotPanics(t, func() {
				ctx, auth, err = engine.Process(context.Background(), newMapCarrier())
			})

			require.Error(t, err)
			assert.ErrorIs(t, err, security.ErrAuthenticatorRefused)
			assertNoCredentialSentinel(t, err)
			assert.Equal(t, security.Anonymous(), auth)

			stored, ok := security.FromContext(ctx)
			assert.True(t, ok)
			assert.Equal(t, security.Anonymous(), stored)
		})
	}
}

func TestEngineFailsClosedWhenTheManagerReturnsNoAuthenticatedValue(t *testing.T) {
	t.Parallel()

	cases := map[string]security.Authentication{
		"nil result":             nil,
		"typed nil result":       typedNilAuth,
		"unauthenticated result": newFakeAuth("alice").withCredentials("pw"),
	}

	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			engine := security.NewEngine(
				managerReturning(t, result, nil),
				extractorReturning(t, newFakeAuth("alice").withCredentials("pw"), nil),
			)

			var (
				ctx  context.Context
				auth security.Authentication
				err  error
			)

			require.NotPanics(t, func() {
				ctx, auth, err = engine.Process(context.Background(), newMapCarrier())
			})

			require.Error(t, err)
			assertNoCredentialSentinel(t, err)
			assert.Equal(t, security.Anonymous(), auth)

			stored, _ := security.FromContext(ctx)
			assert.Equal(t, security.Anonymous(), stored)
		})
	}
}

// Audit probe TestZZAuditEngineFailureKeepsCredentialsInContext: on a
// refusal the Engine stored the extracted value — cleartext password
// included — in the context.
func TestEngineFailureLeavesNoCredentialsInContext(t *testing.T) {
	t.Parallel()

	// The refusing authenticator hands its input — the credentials — back
	// with its error.
	refusing := security.NewMockAuthenticator(t)
	refusing.EXPECT().Supports(mock.Anything).Return(true)
	refusing.EXPECT().Authenticate(mock.Anything, mock.Anything).RunAndReturn(
		func(_ context.Context, a security.Authentication) (security.Authentication, error) {
			return a, fmt.Errorf("load user: %w", security.ErrInvalidCredentials)
		})

	cases := map[string]security.Manager{
		"refused":     security.NewManager(refusing),
		"unsupported": security.NewManager(),
	}

	for name, manager := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			engine := security.NewEngine(manager, extractorReturning(t, newFakeAuth("alice").withCredentials("S3cr3t!"), nil))

			ctx, got, err := engine.Process(context.Background(), newMapCarrier())

			require.Error(t, err)
			assert.Equal(t, security.Anonymous(), got)
			assert.Nil(t, got.Credentials())

			stored, ok := security.FromContext(ctx)
			assert.True(t, ok)
			assert.Equal(t, security.Anonymous(), stored)
			assert.Nil(t, stored.Credentials())
		})
	}
}

func TestManagerFailureReturnsAnonymous(t *testing.T) {
	t.Parallel()

	refusing := authenticatorReturning(t, nil, security.ErrInvalidCredentials)

	for name, m := range map[string]security.Manager{
		"no authenticator": security.NewManager(),
		"refused":          security.NewManager(refusing),
	} {
		got, err := m.Authenticate(context.Background(), newFakeAuth("alice").withCredentials("S3cr3t!"))

		require.Error(t, err, name)
		assert.Equal(t, security.Anonymous(), got, name)
	}
}

// The Authenticator godoc makes ErrUnsupportedCredential the canonical
// runtime bail-out: it is an abstention, never a refusal joined with the
// others (audit CORE-10: a bail-out turned a wrong password into a 400).
func TestManagerTreatsARuntimeBailOutAsAnAbstention(t *testing.T) {
	t.Parallel()

	bailOut := func(t *testing.T) *security.MockAuthenticator {
		t.Helper()

		return authenticatorReturning(t, nil, fmt.Errorf("out of scope: %w", security.ErrUnsupportedCredential))
	}

	t.Run("bail-out then refusal", func(t *testing.T) {
		t.Parallel()

		m := security.NewManager(bailOut(t), authenticatorReturning(t, nil, security.ErrInvalidCredentials))

		_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

		assert.ErrorIs(t, err, security.ErrAuthenticatorRefused)
		assert.ErrorIs(t, err, security.ErrInvalidCredentials)
		assert.NotErrorIs(t, err, security.ErrUnsupportedCredential)
	})

	t.Run("bail-outs only", func(t *testing.T) {
		t.Parallel()

		m := security.NewManager(bailOut(t), bailOut(t))

		_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

		assert.ErrorIs(t, err, security.ErrUnsupportedCredential)
		assert.NotErrorIs(t, err, security.ErrAuthenticatorRefused)
	})

	// Review nit 6: a bail-out that also wraps a higher-ranked sentinel is
	// that verdict, not an abstention (security.ErrorClass order).
	t.Run("bail-out wrapping a verdict", func(t *testing.T) {
		t.Parallel()

		for _, verdict := range []error{security.ErrInvalidRequest, security.ErrUnavailable, security.ErrInvalidCredentials} {
			m := security.NewManager(authenticatorReturning(t, nil, fmt.Errorf("%w: %w", security.ErrUnsupportedCredential, verdict)))

			_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

			require.ErrorIs(t, err, security.ErrAuthenticatorRefused, verdict.Error())
			assert.Equal(t, security.ErrorClass(verdict), security.ErrorClass(err), verdict.Error())
		}
	})

	t.Run("bail-out then success", func(t *testing.T) {
		t.Parallel()

		winner := newFakeAuth("alice").withAuthenticated()
		m := security.NewManager(bailOut(t), authenticatorReturning(t, winner, nil))

		got, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

		require.NoError(t, err)
		assert.Equal(t, security.Authentication(winner), got)
	})
}

func TestManagerTreatsAMissingOrUnauthenticatedResultAsARefusal(t *testing.T) {
	t.Parallel()

	for name, result := range map[string]security.Authentication{
		"nil result":             nil,
		"typed nil result":       typedNilAuth,
		"unauthenticated result": newFakeAuth("alice"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			violator := authenticatorReturning(t, result, nil)

			var err error

			require.NotPanics(t, func() {
				_, err = security.NewManager(violator).Authenticate(context.Background(), newFakeAuth("alice"))
			})

			require.Error(t, err)
			assert.ErrorIs(t, err, security.ErrAuthenticatorRefused)
			assertNoCredentialSentinel(t, err)

			winner := newFakeAuth("alice").withAuthenticated()
			m := security.NewManager(authenticatorReturning(t, result, nil), authenticatorReturning(t, winner, nil))

			got, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

			require.NoError(t, err, "the next authenticator still gets its chance")
			assert.Equal(t, security.Authentication(winner), got)
		})
	}
}

// Audit probe TestZZAuditNilAttributePanics.
func TestDecideDeniesANilAttribute(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(decidingVoter(t, security.DecisionGrant))
	admin := newFakeAuth("root", "ROLE_ADMIN").withAuthenticated()

	for name, attrs := range map[string][]security.Attribute{
		"only nil":               {nil},
		"nil after valid":        {stringAttr("role:ADMIN"), nil},
		"nil before valid":       {nil, stringAttr("role:ADMIN")},
		"only typed nil":         {typedNilAttr},
		"typed nil after valid":  {stringAttr("role:ADMIN"), typedNilAttr},
		"typed nil before valid": {typedNilAttr, stringAttr("role:ADMIN")},
	} {
		var err error

		require.NotPanics(t, func() { err = adm.Decide(context.Background(), admin, attrs) }, name)
		assert.ErrorIs(t, err, security.ErrAccessDenied, name)
	}
}

func TestDecideTreatsANilAuthenticationAsAnonymous(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(authReadingVoter(t))

	for name, auth := range map[string]security.Authentication{"nil": nil, "typed nil": typedNilAuth} {
		var err error

		require.NotPanics(t, func() {
			err = adm.Decide(context.Background(), auth, []security.Attribute{stringAttr("x")})
		}, name)
		assert.ErrorIs(t, err, security.ErrAccessDenied, name)
	}
}

// A typed nil extracted value is the extractor's "nothing found" written
// with a nil pointer: the Engine goes on with the next extractor and never
// hands it to the Manager.
func TestEngineTreatsATypedNilExtractionAsNoCredential(t *testing.T) {
	t.Parallel()

	authenticator := security.NewMockAuthenticator(t) // never consulted: any call fails the test
	next := extractorReturning(t, nil, nil)
	engine := security.NewEngine(security.NewManager(authenticator), extractorReturning(t, typedNilAuth, nil), next)

	var (
		ctx  context.Context
		auth security.Authentication
		err  error
	)

	require.NotPanics(t, func() { ctx, auth, err = engine.Process(context.Background(), newMapCarrier()) })

	require.NoError(t, err)
	assert.Equal(t, security.Anonymous(), auth)
	next.AssertNumberOfCalls(t, "Extract", 1) // the next extractor is consulted
	authenticator.AssertNotCalled(t, "Authenticate", mock.Anything, mock.Anything)

	stored, _ := security.FromContext(ctx)
	assert.Equal(t, security.Anonymous(), stored)
}

// Mutant R71: an extractor returning a value AND an error must not see
// that value stored in the context.
func TestEngineExtractorFailureLeavesNoCredentials(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(), extractorReturning(t,
		newFakeAuth("alice").withCredentials("S3cr3t!"), fmt.Errorf("malformed: %w", security.ErrInvalidRequest)))

	ctx, got, err := engine.Process(context.Background(), newMapCarrier())

	require.ErrorIs(t, err, security.ErrInvalidRequest)
	assert.Equal(t, security.Anonymous(), got)

	stored, _ := security.FromContext(ctx)
	assert.Equal(t, security.Anonymous(), stored)
}

// Mutants R18-R20: the constructors copy the slices they are given, so the
// caller reusing its slice cannot rewire a running Engine, Manager or
// decision manager.
func TestConstructorsCopyTheirSlices(t *testing.T) {
	t.Parallel()

	alice := newFakeAuth("alice").withAuthenticated()

	extractors := []security.Extractor{extractorReturning(t, newFakeAuth("alice"), nil)}
	authenticators := []security.Authenticator{authenticatorReturning(t, alice, nil)}
	engine := security.NewEngine(security.NewManager(authenticators...), extractors...)

	// The replacements are never consulted: any call fails the test.
	extractors[0] = security.NewMockExtractor(t)
	authenticators[0] = security.NewMockAuthenticator(t)

	_, got, err := engine.Process(context.Background(), newMapCarrier())
	require.NoError(t, err)
	assert.Equal(t, security.Authentication(alice), got)

	voters := []security.Voter{decidingVoter(t, security.DecisionGrant)}
	adms := map[string]security.AccessDecisionManager{
		"affirmative": security.NewAffirmativeDecisionManager(voters...),
		"consensus":   security.NewConsensusDecisionManager(voters),
		"unanimous":   security.NewUnanimousDecisionManager(voters),
	}

	voters[0] = security.NewMockVoter(t)

	for name, adm := range adms {
		assert.NoError(t, adm.Decide(context.Background(), alice, []security.Attribute{stringAttr("x")}), name)
	}
}

func TestDecideCountsAnUndefinedDecisionAsDeny(t *testing.T) {
	t.Parallel()

	attrs := []security.Attribute{stringAttr("x")}
	alice := newFakeAuth("alice").withAuthenticated()
	undefined := decidingVoter(t, security.Decision(42))
	grant := decidingVoter(t, security.DecisionGrant)

	unanimous := security.NewUnanimousDecisionManager([]security.Voter{undefined},
		security.WithAbstainFallback(security.DecisionGrant))
	assert.ErrorIs(t, unanimous.Decide(context.Background(), alice, attrs), security.ErrAccessDenied,
		"an undefined decision is not an abstention the fallback may turn into a grant")

	consensus := security.NewConsensusDecisionManager([]security.Voter{undefined, grant})
	assert.ErrorIs(t, consensus.Decide(context.Background(), alice, attrs), security.ErrAccessDenied,
		"one grant against one (undefined) deny is a tie, denied by default")
}

func TestConsensusDeniesWhenAllAbstain(t *testing.T) {
	t.Parallel()

	adm := security.NewConsensusDecisionManager([]security.Voter{
		decidingVoter(t, security.DecisionAbstain),
		decidingVoter(t, security.DecisionAbstain),
	}, security.WithTieBreak(security.DecisionGrant))

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(), []security.Attribute{stringAttr("x")})

	assert.ErrorIs(t, err, security.ErrAccessDenied, "all abstentions deny, even with a granting tie-break")
}

func TestConstructorsRefuseNilDependencies(t *testing.T) {
	t.Parallel()

	voter := security.NewMockVoter(t)
	extractor := security.NewMockExtractor(t)

	cases := []struct {
		name string
		want string
		fn   func()
	}{
		{"engine nil manager", "security: NewEngine: nil Manager",
			func() { security.NewEngine(nil, extractor) }},
		{"engine nil extractor", "security: NewEngine: nil Extractor at index 1",
			func() { security.NewEngine(security.NewManager(), extractor, nil) }},
		{"manager nil authenticator", "security: NewManager: nil Authenticator at index 0",
			func() { security.NewManager(nil) }},
		{"affirmative nil voter", "security: NewAffirmativeDecisionManager: nil Voter at index 0",
			func() { security.NewAffirmativeDecisionManager(nil) }},
		{"consensus nil voter", "security: NewConsensusDecisionManager: nil Voter at index 1",
			func() { security.NewConsensusDecisionManager([]security.Voter{voter, nil}) }},
		{"unanimous nil voter", "security: NewUnanimousDecisionManager: nil Voter at index 0",
			func() { security.NewUnanimousDecisionManager([]security.Voter{nil}) }},
	}

	for _, c := range cases {
		assert.PanicsWithValue(t, c.want, c.fn, c.name)
	}
}
