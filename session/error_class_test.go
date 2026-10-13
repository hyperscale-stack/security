// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The PrincipalLoader contract: a refused session, an unavailable store, or
// an internal error without a sentinel.
func TestSessionAuthenticatorKeepsTheLoadersErrorClass(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)
	loginCarrier := newCarrier()
	_, err := mgr.Login(context.Background(), loginCarrier, principal{sub: "alice"})
	require.NoError(t, err)

	for name, c := range map[string]struct {
		err  error
		want string
	}{
		"refused":     {fmt.Errorf("user disabled: %w", security.ErrInvalidCredentials), security.ErrorClassInvalidCredentials},
		"store down":  {fmt.Errorf("db: %w", security.ErrUnavailable), security.ErrorClassUnavailable},
		"no sentinel": {errors.New("loader bug"), security.ErrorClassOther},
	} {
		loader := session.NewMockPrincipalLoader(t)
		loader.EXPECT().Load(mock.Anything, mock.Anything).Return(nil, nil, c.err).Once()

		_, _, err := engineFor(mgr, loader).Process(context.Background(), loginCarrier.replay())

		assert.Equal(t, c.want, security.ErrorClass(err), name)
	}
}
