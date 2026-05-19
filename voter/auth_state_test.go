// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticatedGrantsLoggedIn(t *testing.T) {
	t.Parallel()

	v := voter.Authenticated()
	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAuth("a"), nil))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAnonymous(), nil))
}

func TestAnonymousGrantsLoggedOut(t *testing.T) {
	t.Parallel()

	v := voter.Anonymous()
	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAnonymous(), nil))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("a"), nil))
}

func TestFullyAuthenticatedCurrentlyTracksAuthenticated(t *testing.T) {
	t.Parallel()

	v := voter.FullyAuthenticated()
	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAuth("a"), nil))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAnonymous(), nil))
}

func TestAuthStateVotersSupportEverything(t *testing.T) {
	t.Parallel()

	// auth-state voters do not consume attribute-specific information;
	// they observe the Authentication itself, so Supports must return true
	// regardless of attribute family (the ADM will still call Vote).
	for _, v := range []security.Voter{voter.Authenticated(), voter.Anonymous(), voter.FullyAuthenticated()} {
		assert.True(t, v.Supports(security.Role("X")))
		assert.True(t, v.Supports(security.Scope("y")))
	}
}
