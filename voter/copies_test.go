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
	"github.com/stretchr/testify/require"
)

// The constructors copy the names and voters they are given: a caller
// reusing its slice for the next route cannot rewire a voter already in use.
func TestConstructorsCopyTheirSlices(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	admin := newAuth("root", "ROLE_ADMIN")
	user := newAuth("alice", "ROLE_USER")

	names := []string{"ADMIN"}
	byName := security.NewAffirmativeDecisionManager(voter.HasAnyRole(names...))
	names[0] = "USER"

	voters := []security.Voter{voter.HasRole("ADMIN")}
	composite := security.NewAffirmativeDecisionManager(voter.Or(voters...))
	voters[0] = voter.HasRole("USER")

	for name, adm := range map[string]security.AccessDecisionManager{"names": byName, "composite": composite} {
		require.NoError(t, adm.Decide(ctx, admin, []security.Attribute{security.Role("ADMIN")}), name)
		assert.ErrorIs(t, adm.Decide(ctx, user, []security.Attribute{security.Role("USER")}), security.ErrAccessDenied, name)
	}
}
