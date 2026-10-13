// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
)

// The UserLoader contract: an unavailable store is an outage (503), any
// other loader error a refusal (401).
func TestAuthenticatorClassifiesLoaderErrors(t *testing.T) {
	t.Parallel()

	for name, c := range map[string]struct {
		err  error
		want string
	}{
		"unavailable store": {fmt.Errorf("db: %w", security.ErrUnavailable), security.ErrorClassUnavailable},
		"unknown user":      {fmt.Errorf("lookup: %w", security.ErrInvalidCredentials), security.ErrorClassInvalidCredentials},
		"plain error":       {errors.New("db: boom"), security.ErrorClassInvalidCredentials},
	} {
		a := basic.NewAuthenticator(&stubLoader{err: c.err}, newHasher(t))

		_, err := a.Authenticate(context.Background(), basic.New("alice", "p4ss"))

		assert.Equal(t, c.want, security.ErrorClass(err), name)
	}
}
