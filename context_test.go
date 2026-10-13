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

func TestFromContextWithoutStoredValueReturnsAnonymous(t *testing.T) {
	t.Parallel()

	auth, ok := security.FromContext(context.Background())

	assert.False(t, ok, "ok must be false when nothing was stored")
	assert.Equal(t, security.Anonymous(), auth, "must fall back to Anonymous()")
	assert.False(t, auth.IsAuthenticated())
}

func TestWithAuthenticationRoundtrip(t *testing.T) {
	t.Parallel()

	stored := newFakeAuth("alice", "ROLE_USER").withAuthenticated()

	ctx := security.WithAuthentication(context.Background(), stored)

	got, ok := security.FromContext(ctx)

	assert.True(t, ok)
	assert.Equal(t, stored, got)
	assert.True(t, got.IsAuthenticated())
}

func TestWithAuthenticationNilClearsTheSlot(t *testing.T) {
	t.Parallel()

	stored := newFakeAuth("alice").withAuthenticated()
	ctx := security.WithAuthentication(context.Background(), stored)
	ctx = security.WithAuthentication(ctx, nil)

	got, ok := security.FromContext(ctx)

	assert.False(t, ok)
	assert.Equal(t, security.Anonymous(), got)

	// A typed nil reads back as absent too: callers never get a value that
	// panics on its first method call.
	got, ok = security.FromContext(security.WithAuthentication(context.Background(), typedNilAuth))

	assert.False(t, ok)
	assert.Equal(t, security.Anonymous(), got)
}

func TestWithAuthenticationOverwrites(t *testing.T) {
	t.Parallel()

	first := newFakeAuth("alice").withAuthenticated()
	second := newFakeAuth("bob").withAuthenticated()

	ctx := security.WithAuthentication(context.Background(), first)
	ctx = security.WithAuthentication(ctx, second)

	got, ok := security.FromContext(ctx)

	assert.True(t, ok)
	assert.Equal(t, second, got)
}
