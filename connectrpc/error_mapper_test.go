// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	bearerAPI = `Bearer realm="api"`
	basicAPI  = `Basic realm="api", charset="UTF-8"`
)

// Audit CORE-10 / CORE-I6: a Connect 401 carried no WWW-Authenticate
// (RFC 9110 §11.6.1), and the messages told the client why authentication
// failed. The mapper itself does not know whether the request carried a
// bearer token — the interceptors tell it (see the interceptor tests).
func TestDefaultErrorMapperClassification(t *testing.T) {
	t.Parallel()

	refused := func(causes ...error) error {
		return fmt.Errorf("%w: %w", security.ErrAuthenticatorRefused, errors.Join(causes...))
	}

	tests := []struct {
		name      string
		scheme    string
		err       error
		code      connect.Code
		msg       string
		challenge []string
	}{
		{"invalid_request", "", security.ErrInvalidRequest, connect.CodeInvalidArgument, "invalid request", []string{bearerAPI}},
		{"unavailable", "", security.ErrUnavailable, connect.CodeUnavailable, "authentication unavailable", []string{bearerAPI}},
		{"unavailable_joined", "", refused(security.ErrTokenNotFound, security.ErrUnavailable), connect.CodeUnavailable, "authentication unavailable", []string{bearerAPI}},
		{"token_expired", "", security.ErrTokenExpired, connect.CodeUnauthenticated, "unauthenticated", []string{bearerAPI}},
		{"token_not_found", "", security.ErrTokenNotFound, connect.CodeUnauthenticated, "unauthenticated", []string{bearerAPI}},
		{"invalid_credentials", "", security.ErrInvalidCredentials, connect.CodeUnauthenticated, "unauthenticated", []string{bearerAPI}},
		{"client_secret_mismatch", "", security.ErrClientSecretMismatch, connect.CodeUnauthenticated, "unauthenticated", []string{bearerAPI}},
		{"authenticator_refused", "", refused(security.ErrInvalidCredentials), connect.CodeUnauthenticated, "unauthenticated", []string{bearerAPI}},
		{"authentication_required", "", security.ErrAuthenticationRequired, connect.CodeUnauthenticated, "unauthenticated", []string{bearerAPI}},
		{"unsupported_credential", "", security.ErrUnsupportedCredential, connect.CodeUnauthenticated, "unauthenticated", []string{bearerAPI}},
		{"access_denied", "", security.ErrAccessDenied, connect.CodePermissionDenied, "permission denied", []string{bearerAPI}},
		{"insufficient_scope", "", security.ErrInsufficientScope, connect.CodePermissionDenied, "permission denied", []string{bearerAPI}},
		{"no_extractor", "", security.ErrNoExtractor, connect.CodeInternal, "internal error", []string{bearerAPI}},
		{"no_sentinel", "", errors.New("boom"), connect.CodeInternal, "internal error", []string{bearerAPI}},
		{"basic", "Basic", security.ErrInvalidCredentials, connect.CodeUnauthenticated, "unauthenticated", []string{basicAPI}},
		{"basic_denied", "Basic", security.ErrAccessDenied, connect.CodePermissionDenied, "permission denied", []string{basicAPI}},
		{"basic_lowercase", "basic", security.ErrAuthenticationRequired, connect.CodeUnauthenticated, "unauthenticated", []string{`basic realm="api", charset="UTF-8"`}},
		{"basic_invalid_request", "Basic", security.ErrInvalidRequest, connect.CodeInvalidArgument, "invalid request", nil},
		{"basic_unavailable", "Basic", security.ErrUnavailable, connect.CodeUnavailable, "authentication unavailable", nil},
		{"basic_no_sentinel", "Basic", errors.New("boom"), connect.CodeInternal, "internal error", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := connectrpcsec.DefaultErrorMapper(tc.scheme, "").Map(context.Background(), tc.err)
			require.Error(t, got)

			var ce *connect.Error
			require.ErrorAs(t, got, &ce)
			assert.Equal(t, tc.code, ce.Code())
			assert.Equal(t, tc.msg, ce.Message(), "the message never says why")
			assert.Equal(t, tc.challenge, ce.Meta().Values("WWW-Authenticate"))
		})
	}
}

func TestDefaultErrorMapperRefusesAnInvalidChallengeConfiguration(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, `connectrpcsec: challenge scheme "Bea rer" is not an RFC 9110 token`,
		func() { connectrpcsec.DefaultErrorMapper("Bea rer", "") })
	assert.PanicsWithValue(t, `connectrpcsec: realm "a\r\nb" is not printable ASCII (RFC 9110 §5.6.4 quoted-string)`,
		func() { connectrpcsec.DefaultErrorMapper("", "a\r\nb") })
	assert.PanicsWithValue(t, `connectrpcsec: realm "café" is not printable ASCII (RFC 9110 §5.6.4 quoted-string)`,
		func() { connectrpcsec.NewAuthenticationInterceptor(newEngine(), connectrpcsec.WithRealm("café")) })

	got := connectrpcsec.DefaultErrorMapper("Bearer", `my "api" \ realm`).Map(context.Background(), security.ErrAuthenticationRequired)

	var ce *connect.Error
	require.ErrorAs(t, got, &ce)
	assert.Equal(t, `Bearer realm="my \"api\" \\ realm"`, ce.Meta().Get("WWW-Authenticate"))
}
