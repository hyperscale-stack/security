// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubUser is a [basic.PasswordUser] driven by per-field flags so individual
// tests can dial in the exact lifecycle scenario they need.
type stubUser struct {
	subject              string
	passwordHash         string
	enabled              bool
	locked               bool
	expired              bool
	credentialsExpired   bool
}

func (u *stubUser) Subject() string            { return u.subject }
func (u *stubUser) GetPasswordHash() string    { return u.passwordHash }
func (u *stubUser) IsEnabled() bool            { return u.enabled }
func (u *stubUser) IsLocked() bool             { return u.locked }
func (u *stubUser) IsExpired() bool            { return u.expired }
func (u *stubUser) IsCredentialsExpired() bool { return u.credentialsExpired }

// stubLoader is a tiny in-memory loader.
type stubLoader struct {
	user *stubUser
	err  error
}

func (l *stubLoader) LoadByUsername(_ context.Context, username string) (basic.PasswordUser, error) {
	if l.err != nil {
		return nil, l.err
	}

	if l.user == nil || l.user.Subject() != username {
		return nil, nil
	}

	return l.user, nil
}

func newHasher(t *testing.T) password.Hasher {
	t.Helper()

	return password.NewBCryptHasher(4)
}

func mustHash(t *testing.T, h password.Hasher, plain string) string {
	t.Helper()

	out, err := h.Hash(context.Background(), plain)
	require.NoError(t, err)

	return out
}

func TestAuthenticatorSupportsOnlyBasicAuthentications(t *testing.T) {
	t.Parallel()

	a := basic.NewAuthenticator(&stubLoader{}, newHasher(t))
	assert.True(t, a.Supports(basic.New("u", "p")))
	assert.False(t, a.Supports(security.Anonymous()))
}

func TestAuthenticatorSuccess(t *testing.T) {
	t.Parallel()

	h := newHasher(t)
	u := &stubUser{subject: "alice", passwordHash: mustHash(t, h, "p4ss"), enabled: true}
	auth := basic.NewAuthenticator(&stubLoader{user: u}, h)

	got, err := auth.Authenticate(context.Background(), basic.New("alice", "p4ss"))
	require.NoError(t, err)
	assert.True(t, got.IsAuthenticated())
	assert.Equal(t, "alice", got.Principal().Subject())

	ba := got.(basic.Authentication)
	assert.Equal(t, "", ba.Password(), "cleartext password must be redacted after success")
	assert.Same(t, u, ba.User())
}

func TestAuthenticatorBadPassword(t *testing.T) {
	t.Parallel()

	h := newHasher(t)
	u := &stubUser{subject: "alice", passwordHash: mustHash(t, h, "good"), enabled: true}
	auth := basic.NewAuthenticator(&stubLoader{user: u}, h)

	_, err := auth.Authenticate(context.Background(), basic.New("alice", "bad"))
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
}

func TestAuthenticatorUnknownUser(t *testing.T) {
	t.Parallel()

	auth := basic.NewAuthenticator(&stubLoader{}, newHasher(t))

	_, err := auth.Authenticate(context.Background(), basic.New("ghost", "x"))
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials,
		"unknown user must NOT leak via a distinct error (account enumeration)")
}

func TestAuthenticatorLifecycleFlagsAreEnforced(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*stubUser)
	}{
		{"disabled", func(u *stubUser) { u.enabled = false }},
		{"locked", func(u *stubUser) { u.locked = true }},
		{"expired", func(u *stubUser) { u.expired = true }},
		{"credentials_expired", func(u *stubUser) { u.credentialsExpired = true }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			h := newHasher(t)
			u := &stubUser{subject: "alice", passwordHash: mustHash(t, h, "p"), enabled: true}
			c.mutate(u)

			a := basic.NewAuthenticator(&stubLoader{user: u}, h)
			_, err := a.Authenticate(context.Background(), basic.New("alice", "p"))
			require.Error(t, err)
			assert.ErrorIs(t, err, security.ErrInvalidCredentials,
				"lifecycle failures MUST collapse to ErrInvalidCredentials at the boundary")
		})
	}
}

func TestAuthenticatorLoaderErrorWraps(t *testing.T) {
	t.Parallel()

	boom := errors.New("db unreachable")
	a := basic.NewAuthenticator(&stubLoader{err: boom}, newHasher(t))

	_, err := a.Authenticate(context.Background(), basic.New("alice", "p"))
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.ErrorIs(t, err, boom, "loader error chain must remain inspectable for ops")
}

func TestAuthenticatorAuthorityResolverPopulatesAuthorities(t *testing.T) {
	t.Parallel()

	h := newHasher(t)
	u := &stubUser{subject: "alice", passwordHash: mustHash(t, h, "p"), enabled: true}
	a := basic.NewAuthenticator(&stubLoader{user: u}, h, basic.WithAuthorityResolver(
		func(basic.PasswordUser) []string { return []string{"ROLE_USER", "scope:read"} },
	))

	got, err := a.Authenticate(context.Background(), basic.New("alice", "p"))
	require.NoError(t, err)
	assert.Equal(t, []string{"ROLE_USER", "scope:read"}, got.Authorities())
}

func TestAuthenticatorRejectsForeignAuthentication(t *testing.T) {
	t.Parallel()

	a := basic.NewAuthenticator(&stubLoader{}, newHasher(t))

	_, err := a.Authenticate(context.Background(), security.Anonymous())
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrUnsupportedCredential)
}

func TestAuthenticatorName(t *testing.T) {
	t.Parallel()

	a := basic.NewAuthenticator(nil, nil)
	assert.Equal(t, "basic", a.AuthenticatorName())
}
