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

func TestCSRFTokenAndVerify(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	s, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	token := session.CSRFToken(s)
	assert.NotEmpty(t, token, "Login must mint a CSRF token")

	assert.True(t, session.VerifyCSRF(s, token), "the minted token must verify")
	assert.False(t, session.VerifyCSRF(s, "wrong-token"), "a wrong token must be rejected")
	assert.False(t, session.VerifyCSRF(s, ""), "an empty presented token must be rejected")
}

func TestCSRFNilSessionSafe(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", session.CSRFToken(nil))
	assert.False(t, session.VerifyCSRF(nil, "anything"))
}

func TestCSRFTokenSurvivesCookieRoundTrip(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	original, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	reloaded, err := mgr.Get(context.Background(), c.replay())
	require.NoError(t, err)

	assert.Equal(t, session.CSRFToken(original), session.CSRFToken(reloaded),
		"the CSRF token must survive the cookie encrypt/decrypt round-trip")
}

func TestCSRFTokenChangesOnRotate(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	original, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	rotated, err := mgr.Rotate(context.Background(), c.replay())
	require.NoError(t, err)

	assert.NotEqual(t, session.CSRFToken(original), session.CSRFToken(rotated),
		"Rotate mints a fresh session, hence a fresh CSRF token")
}
