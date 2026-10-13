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

func TestHasAuthorityVerbatim(t *testing.T) {
	t.Parallel()

	v := voter.HasAuthority("billing:write")
	attrs := []security.Attribute{security.Authority("billing:write")}

	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAuth("a", "billing:write"), attrs))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("a", "billing:read"), attrs))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAnonymous(), attrs))
}

func TestHasAuthoritySupportsOnlyAuthorityAttribute(t *testing.T) {
	t.Parallel()

	v := voter.HasAuthority("x")
	assert.True(t, v.Supports(security.Authority("x")))
	assert.False(t, v.Supports(security.Authority("y")), "only the authority it is bound to")
	assert.False(t, v.Supports(security.Role("ADMIN")))
}

func TestHasAnyAuthorityMatchesOneRequestedAuthority(t *testing.T) {
	t.Parallel()

	v := voter.HasAnyAuthority("alpha", "beta")

	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAuth("a", "beta"), []security.Attribute{security.Authority("alpha"), security.Authority("beta")}))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("a", "beta"), []security.Attribute{security.Authority("alpha")}),
		"beta is held but not requested")
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("a", "gamma"), []security.Attribute{security.Authority("alpha")}))
	assert.Equal(t, security.DecisionAbstain,
		v.Vote(context.Background(), newAuth("a", "gamma"), []security.Attribute{security.Authority("gamma")}))
}
