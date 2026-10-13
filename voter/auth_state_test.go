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
	attrs := []security.Attribute{security.IsAuthenticated}

	assert.Equal(t, security.DecisionGrant, v.Vote(context.Background(), newAuth("a"), attrs))
	assert.Equal(t, security.DecisionDeny, v.Vote(context.Background(), newAnonymous(), attrs))
	assert.Equal(t, security.DecisionAbstain, v.Vote(context.Background(), newAuth("a"), nil),
		"without its attribute the voter has no opinion")
}

func TestAnonymousGrantsLoggedOut(t *testing.T) {
	t.Parallel()

	v := voter.Anonymous()
	attrs := []security.Attribute{security.IsAnonymous}

	assert.Equal(t, security.DecisionGrant, v.Vote(context.Background(), newAnonymous(), attrs))
	assert.Equal(t, security.DecisionDeny, v.Vote(context.Background(), newAuth("a"), attrs))
	assert.Equal(t, security.DecisionAbstain, v.Vote(context.Background(), newAnonymous(), nil),
		"without its attribute the voter has no opinion")
}
