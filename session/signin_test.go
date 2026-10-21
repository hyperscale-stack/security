// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Review finding 1: a sign-in form protected by a session opened with
// Login(ctx, c, nil) on the Manager the Engine reads is extracted on every
// request and refused by the PrincipalLoader (it has no subject): every
// page of the browser answers 401, the sign-in form included. Opened on a
// dedicated Manager — its own cookie name and purpose, a short TTL — the
// form's session never reaches the Engine.
func TestSignInFormSessionOnADedicatedManager(t *testing.T) {
	t.Parallel()

	codec, err := session.NewCodec(testKey)
	require.NoError(t, err)

	sessions := session.NewManager(codec)
	form := session.NewManager(codec,
		session.WithCookieName("__Host-signin"),
		session.WithPurpose("sign-in form"),
		session.WithTTL(15*time.Minute))

	// The Authenticator refuses a session without a subject before the
	// PrincipalLoader, which is never reached.
	loader := session.NewMockPrincipalLoader(t)

	engine := engineFor(sessions, loader)

	// The trap: the form's session opened on the Manager the Engine reads.
	trap := newCarrier()
	_, err = sessions.Login(context.Background(), trap, nil)
	require.NoError(t, err)

	_, _, err = engine.Process(context.Background(), trap.replay())
	require.ErrorIs(t, err, security.ErrInvalidCredentials, "every request of the browser is refused")

	// The pattern: the form's session on its own Manager.
	c := newCarrier()
	s, err := form.Login(context.Background(), c, nil)
	require.NoError(t, err)

	browser := c.replay()
	require.Contains(t, browser.cookies, "__Host-signin")
	require.NotContains(t, browser.cookies, sessions.CookieName())

	_, auth, err := engine.Process(context.Background(), browser)
	require.NoError(t, err, "the Engine does not see the form's session")
	assert.False(t, auth.IsAuthenticated())

	got, err := form.Get(context.Background(), browser)
	require.NoError(t, err)
	assert.True(t, session.VerifyCSRF(got, session.CSRFToken(s)))

	// Not even under the session cookie's name: the cookie name and the
	// purpose are bound into the cookie.
	renamed := newCarrier()
	renamed.cookies[sessions.CookieName()] = browser.cookies["__Host-signin"]

	_, err = sessions.Get(context.Background(), renamed)
	require.ErrorIs(t, err, session.ErrNoSession)
}
