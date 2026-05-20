// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubLoader resolves the "sub" value to a principal, optionally failing.
type stubLoader struct {
	authorities []string
	err         error
	nilPrincipal bool
}

func (l stubLoader) Load(_ context.Context, values map[string]any) (security.Principal, []string, error) {
	if l.err != nil {
		return nil, nil, l.err
	}

	if l.nilPrincipal {
		return nil, nil, nil
	}

	sub, _ := values["sub"].(string)

	return principal{sub: sub}, l.authorities, nil
}

// engineFor wires the session extractor + authenticator into an Engine.
func engineFor(mgr *session.Manager, loader session.PrincipalLoader) security.Engine {
	return security.NewEngine(
		security.NewManager(session.NewAuthenticator(loader)),
		session.NewExtractor(mgr),
	)
}

func TestSessionEngineEndToEnd(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	// Establish a session.
	loginCarrier := newCarrier()
	_, err := mgr.Login(context.Background(), loginCarrier, principal{sub: "alice"})
	require.NoError(t, err)

	// Next request: the engine extracts + authenticates from the cookie.
	engine := engineFor(mgr, stubLoader{authorities: []string{"ROLE_USER"}})

	_, auth, err := engine.Process(context.Background(), loginCarrier.replay())
	require.NoError(t, err)
	assert.True(t, auth.IsAuthenticated())
	assert.Equal(t, "alice", auth.Principal().Subject())
	assert.Equal(t, []string{"ROLE_USER"}, auth.Authorities())
}

func TestSessionEngineNoCookieIsAnonymous(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)
	engine := engineFor(mgr, stubLoader{})

	_, auth, err := engine.Process(context.Background(), newCarrier())
	require.NoError(t, err)
	assert.False(t, auth.IsAuthenticated(), "no cookie -> anonymous")
}

func TestSessionAuthenticatorLoaderError(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)
	loginCarrier := newCarrier()
	_, err := mgr.Login(context.Background(), loginCarrier, principal{sub: "alice"})
	require.NoError(t, err)

	boom := errors.New("user store down")
	engine := engineFor(mgr, stubLoader{err: boom})

	_, _, err = engine.Process(context.Background(), loginCarrier.replay())
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

func TestSessionAuthenticatorNilPrincipal(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)
	loginCarrier := newCarrier()
	_, err := mgr.Login(context.Background(), loginCarrier, principal{sub: "ghost"})
	require.NoError(t, err)

	engine := engineFor(mgr, stubLoader{nilPrincipal: true})

	_, _, err = engine.Process(context.Background(), loginCarrier.replay())
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
}

func TestSessionAuthenticatorName(t *testing.T) {
	t.Parallel()

	a := session.NewAuthenticator(stubLoader{})
	assert.Equal(t, "session", a.AuthenticatorName())
}

func TestNewAuthenticatorPanicsOnNilLoader(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { session.NewAuthenticator(nil) })
}

func TestSessionAuthenticatorRejectsForeignAuthentication(t *testing.T) {
	t.Parallel()

	a := session.NewAuthenticator(stubLoader{})

	_, err := a.Authenticate(context.Background(), security.Anonymous())
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrUnsupportedCredential)
}
