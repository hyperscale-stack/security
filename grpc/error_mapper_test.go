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

// Audit CORE-I6 (probe TestZZAuditErrorMessages): the messages told the
// client why authentication failed ("token expired", "token not found"),
// and an infrastructure failure was reported as Unauthenticated.
func TestDefaultErrorMapperClassification(t *testing.T) {
	t.Parallel()

	mapper := grpcsec.DefaultErrorMapper()

	refused := func(causes ...error) error {
		return fmt.Errorf("%w: %w", security.ErrAuthenticatorRefused, errors.Join(causes...))
	}

	cases := []struct {
		name string
		err  error
		code codes.Code
		msg  string
	}{
		{"invalid_request", security.ErrInvalidRequest, codes.InvalidArgument, "invalid request"},
		{"unavailable", security.ErrUnavailable, codes.Unavailable, "authentication unavailable"},
		{"unavailable_joined_with_a_verdict", refused(security.ErrTokenNotFound, security.ErrUnavailable), codes.Unavailable, "authentication unavailable"},
		{"token_expired", security.ErrTokenExpired, codes.Unauthenticated, "unauthenticated"},
		{"token_not_found", security.ErrTokenNotFound, codes.Unauthenticated, "unauthenticated"},
		{"invalid_credentials", security.ErrInvalidCredentials, codes.Unauthenticated, "unauthenticated"},
		{"client_secret_mismatch", security.ErrClientSecretMismatch, codes.Unauthenticated, "unauthenticated"},
		{"authenticator_refused", refused(security.ErrInvalidCredentials), codes.Unauthenticated, "unauthenticated"},
		{"authentication_required", security.ErrAuthenticationRequired, codes.Unauthenticated, "unauthenticated"},
		{"unsupported_credential", security.ErrUnsupportedCredential, codes.Unauthenticated, "unauthenticated"},
		{"access_denied", security.ErrAccessDenied, codes.PermissionDenied, "permission denied"},
		{"insufficient_scope", security.ErrInsufficientScope, codes.PermissionDenied, "permission denied"},
		{"wrapped_access_denied", fmt.Errorf("ctx: %w", security.ErrAccessDenied), codes.PermissionDenied, "permission denied"},
		{"anonymous_denial", fmt.Errorf("%w: %w", security.ErrAuthenticationRequired, security.ErrAccessDenied), codes.Unauthenticated, "unauthenticated"},
		{"no_extractor", security.ErrNoExtractor, codes.Internal, "internal error"},
		{"no_sentinel", errors.New("boom"), codes.Internal, "internal error"},
		{"refusal_without_a_sentinel", refused(errors.New("boom")), codes.Internal, "internal error"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			st := status.Convert(mapper.Map(context.Background(), c.err))
			assert.Equal(t, c.code, st.Code())
			assert.Equal(t, c.msg, st.Message(), "the message never says why")
		})
	}
}
