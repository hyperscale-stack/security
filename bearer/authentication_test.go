// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	"github.com/stretchr/testify/assert"
)

type principal struct{ sub string }

func (p principal) Subject() string { return p.sub }

func TestAuthenticationPreAuth(t *testing.T) {
	t.Parallel()

	auth := bearer.New("opaque-token")

	assert.Equal(t, "opaque-token", auth.Token())
	assert.False(t, auth.IsAuthenticated())
	assert.Nil(t, auth.Authorities())
	// Before authentication the token is the credential.
	assert.Equal(t, "opaque-token", auth.Credentials())
	// No principal yet -> anonymous fallback, and Name falls back to the scheme.
	assert.Equal(t, security.AnonymousPrincipal, auth.Principal())
	assert.Equal(t, "bearer", auth.Name())
}

func TestAuthenticationPostAuth(t *testing.T) {
	t.Parallel()

	p := principal{sub: "alice"}
	auth := bearer.New("opaque-token").WithAuthenticated(p, []string{"scope:read"}, "alice")

	assert.True(t, auth.IsAuthenticated())
	assert.Equal(t, p, auth.Principal())
	assert.Equal(t, []string{"scope:read"}, auth.Authorities())
	assert.Equal(t, "alice", auth.Name())
	// The token is no longer exposed as a credential once authenticated.
	assert.Nil(t, auth.Credentials())
}

func TestAuthenticationNameFallsBackToSubject(t *testing.T) {
	t.Parallel()

	// An empty display name falls back to the principal subject.
	auth := bearer.New("t").WithAuthenticated(principal{sub: "bob"}, nil, "")
	assert.Equal(t, "bob", auth.Name())
}
