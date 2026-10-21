// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
)

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
			func() { security.NewEngine((*security.MockManager)(nil)) }},
		{"engine typed-nil extractor", "security: NewEngine: nil Extractor at index 0",
			func() { security.NewEngine(security.NewManager(), (*security.MockExtractor)(nil)) }},
		{"manager typed-nil authenticator", "security: NewManager: nil Authenticator at index 0",
			func() { security.NewManager((*security.MockAuthenticator)(nil)) }},
		{"affirmative typed-nil voter", "security: NewAffirmativeDecisionManager: nil Voter at index 1",
			func() { security.NewAffirmativeDecisionManager(voter, (*security.MockVoter)(nil)) }},
		{"consensus typed-nil voter", "security: NewConsensusDecisionManager: nil Voter at index 0",
			func() { security.NewConsensusDecisionManager([]security.Voter{(*security.MockVoter)(nil)}) }},
		{"unanimous typed-nil voter", "security: NewUnanimousDecisionManager: nil Voter at index 0",
			func() { security.NewUnanimousDecisionManager([]security.Voter{(*security.MockVoter)(nil)}) }},
	}

	for _, c := range cases {
		assert.PanicsWithValue(t, c.want, c.fn, c.name)
	}
}
