// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
)

func TestSentinelErrorsAreDistinct(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		security.ErrInvalidCredentials,
		security.ErrClientSecretMismatch,
		security.ErrTokenExpired,
		security.ErrTokenNotFound,
		security.ErrUnsupportedCredential,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				assert.ErrorIs(t, a, b)

				continue
			}

			assert.NotErrorIs(t, a, b, "sentinels at %d and %d should be distinct", i, j)
		}
	}
}

func TestSentinelImplementsSecurityError(t *testing.T) {
	t.Parallel()

	var marker security.SecurityError
	marker, ok := any(security.ErrInvalidCredentials).(security.SecurityError)
	assert.True(t, ok)
	assert.NotNil(t, marker)
}

func TestSentinelErrorsWrappable(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("context: %w", security.ErrInvalidCredentials)

	assert.ErrorIs(t, wrapped, security.ErrInvalidCredentials)
	assert.NotErrorIs(t, wrapped, security.ErrTokenExpired)
}

func TestSentinelErrorMessages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want string
	}{
		{security.ErrInvalidCredentials, "security: invalid credentials"},
		{security.ErrClientSecretMismatch, "security: oauth2 client secret mismatch"},
		{security.ErrTokenExpired, "security: token expired"},
		{security.ErrTokenNotFound, "security: token not found"},
		{security.ErrUnsupportedCredential, "security: unsupported credential type"},
	}

	for _, c := range cases {
		assert.Equal(t, c.want, c.err.Error())
	}
}

func TestSecurityErrorInterfaceForbidsForeignTypes(t *testing.T) {
	t.Parallel()

	// A foreign error built with errors.New must NOT satisfy SecurityError —
	// the unexported securityError() method is the gate.
	foreign := errors.New("from outside")
	_, ok := any(foreign).(security.SecurityError)
	assert.False(t, ok)
}
