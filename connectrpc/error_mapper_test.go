// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultErrorMapperClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"unsupported_credential", security.ErrUnsupportedCredential, connect.CodeInvalidArgument},
		{"access_denied", security.ErrAccessDenied, connect.CodePermissionDenied},
		{"insufficient_scope", security.ErrInsufficientScope, connect.CodePermissionDenied},
		{"token_expired", security.ErrTokenExpired, connect.CodeUnauthenticated},
		{"token_not_found", security.ErrTokenNotFound, connect.CodeUnauthenticated},
		{"invalid_credentials", security.ErrInvalidCredentials, connect.CodeUnauthenticated},
		{"client_secret_mismatch", security.ErrClientSecretMismatch, connect.CodeUnauthenticated},
		{"authenticator_refused", security.ErrAuthenticatorRefused, connect.CodeUnauthenticated},
		{"unknown_error", errors.New("boom"), connect.CodeUnauthenticated},
		{
			"wrapped_access_denied",
			errors.Join(errors.New("ctx"), security.ErrAccessDenied),
			connect.CodePermissionDenied,
		},
	}

	mapper := connectrpcsec.DefaultErrorMapper()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := mapper.Map(context.Background(), tc.err)
			require.Error(t, got)
			assert.Equal(t, tc.want, connect.CodeOf(got))
		})
	}
}
