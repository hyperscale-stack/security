// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	"github.com/stretchr/testify/assert"
)

// The TokenVerifier contract: the verifier's sentinel decides the answer —
// a refused token, an outage, or an internal error without a sentinel.
func TestAuthenticatorKeepsTheVerifiersErrorClass(t *testing.T) {
	t.Parallel()

	for name, c := range map[string]struct {
		err  error
		want string
	}{
		"expired":     {fmt.Errorf("jwt: %w", security.ErrTokenExpired), security.ErrorClassTokenExpired},
		"unknown":     {fmt.Errorf("introspection: %w", security.ErrTokenNotFound), security.ErrorClassTokenNotFound},
		"bad token":   {fmt.Errorf("jwt: %w", security.ErrInvalidCredentials), security.ErrorClassInvalidCredentials},
		"key set out": {fmt.Errorf("jwks: %w", security.ErrUnavailable), security.ErrorClassUnavailable},
		"no sentinel": {errors.New("verifier bug"), security.ErrorClassOther},
	} {
		a := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
			return nil, c.err
		}))

		_, err := a.Authenticate(context.Background(), bearer.New("tk"))

		assert.Equal(t, c.want, security.ErrorClass(err), name)
	}
}
