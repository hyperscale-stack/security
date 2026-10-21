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

// Audit I-28 pins the documented limit: with a cookie name that is not
// __Host- (here a Domain makes it __Secure-session), a sibling host can
// plant a cookie of the session's name. Next to the victim's own session
// it denies it (two valid sessions: none); in a signed-out browser it is
// the only session, and the victim is signed into the planted account —
// login CSRF. Only the default __Host- name prevents both.
func TestATossedCookieSignsInASignedOutVictim(t *testing.T) {
	t.Parallel()

	mgr := newManager(t, session.WithDomain("example.com"))
	require.Equal(t, "__Secure-session", mgr.CookieName())

	login := func(sub string) string {
		c := newCarrier()
		_, err := mgr.Login(context.Background(), c, principal{sub: sub})
		require.NoError(t, err)

		return c.replay().cookies[mgr.CookieName()]
	}

	victim, planted := login("victim"), login("mallory")

	signedIn := newCarrier()
	signedIn.cookies[mgr.CookieName()] = victim
	signedIn.more = map[string][]string{mgr.CookieName(): {planted}}

	_, err := mgr.Get(context.Background(), signedIn)
	require.ErrorIs(t, err, session.ErrNoSession, "a signed-in victim is denied a session")

	signedOut := newCarrier()
	signedOut.cookies[mgr.CookieName()] = planted

	s, err := mgr.Get(context.Background(), signedOut)
	require.NoError(t, err)
	assert.Equal(t, "mallory", s.GetString("sub"), "a signed-out victim is signed into the planted session")

	assert.Equal(t, "__Host-session", newManager(t).CookieName(), "the default name is __Host-")
}
