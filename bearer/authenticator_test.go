// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePrincipal is the test-local Principal used by bearer tests.
type fakePrincipal struct{ sub string }

func (p fakePrincipal) Subject() string { return p.sub }

func TestNewAuthenticatorPanicsOnNilVerifier(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { bearer.NewAuthenticator(nil) })
}

func TestAuthenticatorName(t *testing.T) {
	t.Parallel()

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
		return nil, nil
	}))
	assert.Equal(t, "bearer", a.AuthenticatorName())
}

func TestAuthenticatorSupportsOnlyBearerAuthentications(t *testing.T) {
	t.Parallel()

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
		return nil, nil
	}))
	assert.True(t, a.Supports(bearer.New("x")))
	assert.False(t, a.Supports(security.Anonymous()))
}

func TestAuthenticatorSuccessHandsBackVerifierOutput(t *testing.T) {
	t.Parallel()

	want := bearer.New("redacted").WithAuthenticated(fakePrincipal{sub: "alice"}, []string{"scope:read"}, "alice")

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(_ context.Context, token string) (security.Authentication, error) {
		assert.Equal(t, "tk", token)

		return want, nil
	}))

	got, err := a.Authenticate(context.Background(), bearer.New("tk"))
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.True(t, got.IsAuthenticated())
	assert.Nil(t, got.Credentials(), "token MUST be redacted from the authenticated value")
}

func TestAuthenticatorVerifierErrorIsWrapped(t *testing.T) {
	t.Parallel()

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
		return nil, security.ErrTokenExpired
	}))

	_, err := a.Authenticate(context.Background(), bearer.New("tk"))
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTokenExpired)
}

func TestAuthenticatorRejectsNilFromVerifier(t *testing.T) {
	t.Parallel()

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
		return nil, nil
	}))

	_, err := a.Authenticate(context.Background(), bearer.New("tk"))
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
}

func TestAuthenticatorRejectsForeignAuthentication(t *testing.T) {
	t.Parallel()

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
		t.Fatal("verifier must not be called")

		return nil, errors.New("unreachable")
	}))

	_, err := a.Authenticate(context.Background(), security.Anonymous())
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrUnsupportedCredential)
}
