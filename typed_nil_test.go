// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
)

// Dependencies implemented on pointers: their typed nils satisfy the
// interfaces and panic on the first method call.
type (
	ptrManager       struct{}
	ptrExtractor     struct{}
	ptrAuthenticator struct{}
	ptrVoter         struct{}
)

func (*ptrManager) Authenticate(context.Context, security.Authentication) (security.Authentication, error) {
	return nil, nil
}

func (*ptrExtractor) Extract(context.Context, security.Carrier) (security.Authentication, error) {
	return nil, nil
}

func (*ptrAuthenticator) Supports(security.Authentication) bool { return true }
func (*ptrAuthenticator) Authenticate(context.Context, security.Authentication) (security.Authentication, error) {
	return nil, nil
}

func (*ptrVoter) Supports(security.Attribute) bool { return true }
func (*ptrVoter) Vote(context.Context, security.Authentication, []security.Attribute) security.Decision {
	return security.DecisionGrant
}

// Audit I-27: the constructors compared their dependencies with nil, so a
// typed nil was accepted and panicked on the first request. CHANGELOG: "A
// typed nil … counts as nil wherever the core checks a contract".
func TestConstructorsRefuseTypedNilDependencies(t *testing.T) {
	t.Parallel()

	voter := security.NewMockVoter(t)

	cases := []struct {
		name string
		want string
		fn   func()
	}{
		{"engine typed-nil manager", "security: NewEngine: nil Manager",
			func() { security.NewEngine((*ptrManager)(nil)) }},
		{"engine typed-nil extractor", "security: NewEngine: nil Extractor at index 0",
			func() { security.NewEngine(security.NewManager(), (*ptrExtractor)(nil)) }},
		{"manager typed-nil authenticator", "security: NewManager: nil Authenticator at index 0",
			func() { security.NewManager((*ptrAuthenticator)(nil)) }},
		{"affirmative typed-nil voter", "security: NewAffirmativeDecisionManager: nil Voter at index 1",
			func() { security.NewAffirmativeDecisionManager(voter, (*ptrVoter)(nil)) }},
		{"consensus typed-nil voter", "security: NewConsensusDecisionManager: nil Voter at index 0",
			func() { security.NewConsensusDecisionManager([]security.Voter{(*ptrVoter)(nil)}) }},
		{"unanimous typed-nil voter", "security: NewUnanimousDecisionManager: nil Voter at index 0",
			func() { security.NewUnanimousDecisionManager([]security.Voter{(*ptrVoter)(nil)}) }},
	}

	for _, c := range cases {
		assert.PanicsWithValue(t, c.want, c.fn, c.name)
	}
}
