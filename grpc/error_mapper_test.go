// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDefaultErrorMapperClassification(t *testing.T) {
	t.Parallel()

	mapper := grpcsec.DefaultErrorMapper()

	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"unsupported_credential", security.ErrUnsupportedCredential, codes.InvalidArgument},
		{"access_denied", security.ErrAccessDenied, codes.PermissionDenied},
		{"insufficient_scope", security.ErrInsufficientScope, codes.PermissionDenied},
		{"token_expired", security.ErrTokenExpired, codes.Unauthenticated},
		{"token_not_found", security.ErrTokenNotFound, codes.Unauthenticated},
		{"invalid_credentials", security.ErrInvalidCredentials, codes.Unauthenticated},
		{"client_secret_mismatch", security.ErrClientSecretMismatch, codes.Unauthenticated},
		{"authenticator_refused", security.ErrAuthenticatorRefused, codes.Unauthenticated},
		{"unknown_defaults_to_unauthenticated", errors.New("boom"), codes.Unauthenticated},
		{"wrapped_access_denied", fmt.Errorf("ctx: %w", security.ErrAccessDenied), codes.PermissionDenied},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			got := mapper.Map(context.Background(), c.err)
			assert.Equal(t, c.want, status.Code(got))
		})
	}
}
