// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Principals implemented on nilable types: a loader returning their nil —
// `return users[sub], roles, nil` over a map of pointers — hands the
// Authenticator a typed nil.
type (
	ptrUser  struct{ id string }
	mapUser  map[string]string
	funcUser func() string
)

func (u *ptrUser) Subject() string { return u.id }
func (u mapUser) Subject() string  { return u["sub"] }
func (u funcUser) Subject() string { return u() }

// Audit F-15: the Authenticator compared the principal with nil; a typed
// nil passed, the session authenticated as a principal that panics on its
// first use — a deleted user's cookie kept access until it expired.
func TestAuthenticatorRefusesATypedNilPrincipal(t *testing.T) {
	t.Parallel()

	for name, p := range map[string]security.Principal{
		"pointer": (*ptrUser)(nil),
		"map":     mapUser(nil),
		"func":    funcUser(nil),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mgr := newManager(t)

			c := newCarrier()
			_, err := mgr.Login(context.Background(), c, principal{sub: "deleted-user"})
			require.NoError(t, err)

			loader := session.NewMockPrincipalLoader(t)
			loader.EXPECT().Load(mock.Anything, mock.Anything).Return(p, []string{"ROLE_ADMIN"}, nil).Once()

			var (
				ctx  context.Context
				auth security.Authentication
			)

			require.NotPanics(t, func() {
				ctx, auth, err = engineFor(mgr, loader).Process(context.Background(), c.replay())
			})

			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.Equal(t, security.ErrorClassInvalidCredentials, security.ErrorClass(err))
			assert.False(t, auth.IsAuthenticated())

			inCtx, _ := security.FromContext(ctx)
			assert.Equal(t, security.Anonymous(), inCtx)

			adm := security.NewAffirmativeDecisionManager(voter.Authenticated())
			require.ErrorIs(t, adm.Decide(ctx, inCtx, []security.Attribute{security.IsAuthenticated}), security.ErrAccessDenied)
		})
	}
}

// The PrincipalLoader contract says a session without a subject MUST be
// refused: the Authenticator enforces it before calling the loader, which
// is never reached (the generated mock fails on any call).
func TestAuthenticatorRefusesASessionWithoutSubject(t *testing.T) {
	t.Parallel()

	cases := map[string]func(t *testing.T, mgr *session.Manager) *mapCarrier{
		"no subject": func(t *testing.T, mgr *session.Manager) *mapCarrier {
			c := newCarrier()
			_, err := mgr.Login(context.Background(), c, nil)
			require.NoError(t, err)

			return c.replay()
		},
		"empty subject": func(t *testing.T, mgr *session.Manager) *mapCarrier {
			c := newCarrier()
			_, err := mgr.Login(context.Background(), c, principal{sub: ""})
			require.NoError(t, err)

			return c.replay()
		},
		"numeric subject": func(t *testing.T, mgr *session.Manager) *mapCarrier {
			c := newCarrier()
			s, err := mgr.Login(context.Background(), c, nil)
			require.NoError(t, err)

			s.Values["sub"] = 42

			next := newCarrier()
			require.NoError(t, mgr.Touch(context.Background(), next, s))

			return next.replay()
		},
	}

	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mgr := newManager(t)

			_, auth, err := engineFor(mgr, session.NewMockPrincipalLoader(t)).Process(context.Background(), request(t, mgr))

			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.False(t, auth.IsAuthenticated())
		})
	}
}
