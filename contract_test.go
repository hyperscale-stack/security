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
	"github.com/stretchr/testify/require"
)

// authReadingVoter dereferences the Authentication it is given: it proves
// that Decide never hands a nil Authentication to a voter.
type authReadingVoter struct{}

func (authReadingVoter) Supports(security.Attribute) bool { return true }

func (authReadingVoter) Vote(_ context.Context, auth security.Authentication, _ []security.Attribute) security.Decision {
	if auth.IsAuthenticated() {
		return security.DecisionGrant
	}

	return security.DecisionDeny
}

// constDecisionVoter supports everything and returns a fixed, possibly
// undefined, Decision.
type constDecisionVoter struct{ d security.Decision }

func (constDecisionVoter) Supports(security.Attribute) bool { return true }

func (v constDecisionVoter) Vote(context.Context, security.Authentication, []security.Attribute) security.Decision {
	return v.d
}

// scriptedManager is a custom Manager returning a fixed result.
type scriptedManager struct {
	result security.Authentication
	err    error
}

func (m scriptedManager) Authenticate(context.Context, security.Authentication) (security.Authentication, error) {
	return m.result, m.err
}

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
		"unauthenticated result": newFakeAuth("alice").withCredentials("pw"),
	}

	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			engine := security.NewEngine(
				security.NewManager(security.AuthenticatorFunc(
					func(context.Context, security.Authentication) (security.Authentication, error) {
						return result, nil
					})),
				scriptedExtractor{auth: newFakeAuth("alice").withCredentials("pw")},
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
		"unauthenticated result": newFakeAuth("alice").withCredentials("pw"),
	}

	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			engine := security.NewEngine(
				scriptedManager{result: result},
				scriptedExtractor{auth: newFakeAuth("alice").withCredentials("pw")},
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

	cases := map[string]security.Manager{
		"refused": security.NewManager(security.AuthenticatorFunc(
			func(_ context.Context, a security.Authentication) (security.Authentication, error) {
				return a, fmt.Errorf("load user: %w", security.ErrInvalidCredentials)
			})),
		"unsupported": security.NewManager(),
	}

	for name, manager := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			engine := security.NewEngine(manager, scriptedExtractor{auth: newFakeAuth("alice").withCredentials("S3cr3t!")})

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

	refusing := &scriptedAuthenticator{name: "x", err: security.ErrInvalidCredentials}

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

	bailOut := func() *scriptedAuthenticator {
		return &scriptedAuthenticator{name: "bail", err: fmt.Errorf("out of scope: %w", security.ErrUnsupportedCredential)}
	}

	t.Run("bail-out then refusal", func(t *testing.T) {
		t.Parallel()

		m := security.NewManager(bailOut(), &scriptedAuthenticator{name: "basic", err: security.ErrInvalidCredentials})

		_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

		assert.ErrorIs(t, err, security.ErrAuthenticatorRefused)
		assert.ErrorIs(t, err, security.ErrInvalidCredentials)
		assert.NotErrorIs(t, err, security.ErrUnsupportedCredential)
	})

	t.Run("bail-outs only", func(t *testing.T) {
		t.Parallel()

		m := security.NewManager(bailOut(), bailOut())

		_, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

		assert.ErrorIs(t, err, security.ErrUnsupportedCredential)
		assert.NotErrorIs(t, err, security.ErrAuthenticatorRefused)
	})

	t.Run("bail-out then success", func(t *testing.T) {
		t.Parallel()

		winner := newFakeAuth("alice").withAuthenticated()
		m := security.NewManager(bailOut(), &scriptedAuthenticator{name: "ok", result: winner})

		got, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

		require.NoError(t, err)
		assert.Equal(t, security.Authentication(winner), got)
	})
}

func TestManagerTreatsAMissingOrUnauthenticatedResultAsARefusal(t *testing.T) {
	t.Parallel()

	for name, result := range map[string]security.Authentication{
		"nil result":             nil,
		"unauthenticated result": newFakeAuth("alice"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			violator := &scriptedAuthenticator{name: "violator", result: result}

			_, err := security.NewManager(violator).Authenticate(context.Background(), newFakeAuth("alice"))

			require.Error(t, err)
			assert.ErrorIs(t, err, security.ErrAuthenticatorRefused)
			assertNoCredentialSentinel(t, err)

			winner := newFakeAuth("alice").withAuthenticated()
			m := security.NewManager(&scriptedAuthenticator{name: "violator", result: result},
				&scriptedAuthenticator{name: "ok", result: winner})

			got, err := m.Authenticate(context.Background(), newFakeAuth("alice"))

			require.NoError(t, err, "the next authenticator still gets its chance")
			assert.Equal(t, security.Authentication(winner), got)
		})
	}
}

// Audit probe TestZZAuditNilAttributePanics.
func TestDecideDeniesANilAttribute(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(constDecisionVoter{d: security.DecisionGrant})
	admin := newFakeAuth("root", "ROLE_ADMIN").withAuthenticated()

	for name, attrs := range map[string][]security.Attribute{
		"only nil":         {nil},
		"nil after valid":  {stringAttr("role:ADMIN"), nil},
		"nil before valid": {nil, stringAttr("role:ADMIN")},
	} {
		var err error

		require.NotPanics(t, func() { err = adm.Decide(context.Background(), admin, attrs) }, name)
		assert.ErrorIs(t, err, security.ErrAccessDenied, name)
	}
}

func TestDecideTreatsANilAuthenticationAsAnonymous(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(authReadingVoter{})

	var err error

	require.NotPanics(t, func() {
		err = adm.Decide(context.Background(), nil, []security.Attribute{stringAttr("x")})
	})
	assert.ErrorIs(t, err, security.ErrAccessDenied)
}

func TestDecideCountsAnUndefinedDecisionAsDeny(t *testing.T) {
	t.Parallel()

	attrs := []security.Attribute{stringAttr("x")}
	alice := newFakeAuth("alice").withAuthenticated()
	undefined := constDecisionVoter{d: security.Decision(42)}
	grant := constDecisionVoter{d: security.DecisionGrant}

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
		constDecisionVoter{d: security.DecisionAbstain},
		constDecisionVoter{d: security.DecisionAbstain},
	}, security.WithTieBreak(security.DecisionGrant))

	err := adm.Decide(context.Background(), newFakeAuth("alice").withAuthenticated(), []security.Attribute{stringAttr("x")})

	assert.ErrorIs(t, err, security.ErrAccessDenied, "all abstentions deny, even with a granting tie-break")
}

func TestConstructorsRefuseNilDependencies(t *testing.T) {
	t.Parallel()

	voter := constDecisionVoter{d: security.DecisionGrant}

	cases := []struct {
		name string
		want string
		fn   func()
	}{
		{"engine nil manager", "security: NewEngine: nil Manager",
			func() { security.NewEngine(nil, scriptedExtractor{}) }},
		{"engine nil extractor", "security: NewEngine: nil Extractor at index 1",
			func() { security.NewEngine(security.NewManager(), scriptedExtractor{}, nil) }},
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
