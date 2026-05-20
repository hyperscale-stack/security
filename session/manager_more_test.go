// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerCookieOptions(t *testing.T) {
	t.Parallel()

	mgr := newManager(t,
		session.WithCookieName("sid"),
		session.WithPath("/app"),
		session.WithDomain("example.com"),
	)

	assert.Equal(t, "sid", mgr.CookieName())
}

func TestManagerTouchRewritesCookie(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)
	ctx := context.Background()
	c := newCarrier()

	sess, err := mgr.Login(ctx, c, principal{sub: "alice"})
	require.NoError(t, err)

	// Replay the login cookie onto the next request, then Touch slides the
	// idle window by re-writing it.
	next := c.replay()
	require.NoError(t, mgr.Touch(ctx, next, sess))

	reloaded, err := mgr.Get(ctx, next.replay())
	require.NoError(t, err)
	assert.Equal(t, sess.ID, reloaded.ID)
}
