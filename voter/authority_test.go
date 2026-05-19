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
	assert.False(t, v.Supports(security.Role("ADMIN")))
}

func TestHasAnyAuthorityMatchesOne(t *testing.T) {
	t.Parallel()

	v := voter.HasAnyAuthority("alpha", "beta")
	attrs := []security.Attribute{security.Authority("alpha")}

	assert.Equal(t, security.DecisionGrant,
		v.Vote(context.Background(), newAuth("a", "beta"), attrs))
	assert.Equal(t, security.DecisionDeny,
		v.Vote(context.Background(), newAuth("a", "gamma"), attrs))
}
