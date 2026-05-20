// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type stubPrincipal struct{ sub string }

func (p stubPrincipal) Subject() string { return p.sub }

func TestAuthenticationValue(t *testing.T) {
	t.Parallel()

	sess := &Session{ID: "sid", Values: map[string]any{"sub": "alice"}}
	pending := newPending(sess)

	// Pre-authentication.
	assert.Same(t, sess, pending.Session())
	assert.False(t, pending.IsAuthenticated())
	assert.Nil(t, pending.Credentials(), "a session is never exposed as a credential")
	assert.Equal(t, schemeName, pending.Name())
	assert.Nil(t, pending.Authorities())

	// Post-authentication.
	authed := pending.withAuthenticated(stubPrincipal{sub: "alice"}, []string{"ROLE_USER"})
	assert.True(t, authed.IsAuthenticated())
	assert.Equal(t, "alice", authed.Name())
	assert.Equal(t, []string{"ROLE_USER"}, authed.Authorities())
	assert.Nil(t, authed.Credentials())
}
