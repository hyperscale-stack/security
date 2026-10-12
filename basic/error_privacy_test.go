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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit CORE-07: the loader error embedded the typed username — sometimes a
// password typed in the username field — and flowed into spans and logs.
func TestAuthenticatorErrorDoesNotEchoTheUsername(t *testing.T) {
	t.Parallel()

	const typed = "Summer2026!-my-password"

	a := basic.NewAuthenticator(&stubLoader{err: errors.New("store unreachable")}, newHasher(t))

	_, err := a.Authenticate(context.Background(), basic.New(typed, "x"))

	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.NotContains(t, err.Error(), typed)
}
