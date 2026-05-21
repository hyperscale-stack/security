// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminADM grants only when the principal holds the ADMIN role.
func adminADM() security.AccessDecisionManager {
	return security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
}

var adminAttrs = []security.Attribute{security.Role("ADMIN")}

// chainUnary composes the authentication and authorization interceptors the
// same way connect.WithInterceptors(authn, authz) would: authn is the
// outermost, so it enriches the context before authz reads it.
func chainUnary(
	authn *connectrpcsec.AuthenticationInterceptor,
	authz *connectrpcsec.AuthorizationInterceptor,
	handler connect.UnaryFunc,
) connect.UnaryFunc {
	return authn.WrapUnary(authz.WrapUnary(handler))
}

func TestUnaryAuthorizeGrantsWhenRolePresent(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := chainUnary(
		connectrpcsec.NewAuthenticationInterceptor(newEngine("ROLE_ADMIN")),
		connectrpcsec.NewAuthorizationInterceptor(adminADM(), adminAttrs),
		spy.fn,
	)

	resp, err := wrapped(context.Background(), unaryReq("letmein"))
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, spy.called)
}

func TestUnaryAuthorizeDeniesWhenRoleMissing(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := chainUnary(
		connectrpcsec.NewAuthenticationInterceptor(newEngine()),
		connectrpcsec.NewAuthorizationInterceptor(adminADM(), adminAttrs),
		spy.fn,
	)

	_, err := wrapped(context.Background(), unaryReq("letmein"))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.False(t, spy.called)
}

func TestUnaryAuthorizeDeniesAnonymous(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	// No authentication in the context: the voter denies the anonymous caller.
	wrapped := connectrpcsec.NewAuthorizationInterceptor(adminADM(), adminAttrs).WrapUnary(spy.fn)

	_, err := wrapped(context.Background(), unaryReq("letmein"))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.False(t, spy.called)
}

func TestUnaryAuthorizeSkipsClientCall(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	wrapped := connectrpcsec.NewAuthorizationInterceptor(adminADM(), adminAttrs).WrapUnary(spy.fn)

	_, err := wrapped(context.Background(), clientRequest{connect.NewRequest(&struct{}{})})
	require.NoError(t, err)
	assert.True(t, spy.called)
}

func TestStreamAuthorizeGrantsWhenRolePresent(t *testing.T) {
	t.Parallel()

	spy := &recordingStream{}
	authn := connectrpcsec.NewAuthenticationInterceptor(newEngine("ROLE_ADMIN"))
	authz := connectrpcsec.NewAuthorizationInterceptor(adminADM(), adminAttrs)
	wrapped := authn.WrapStreamingHandler(authz.WrapStreamingHandler(spy.fn))

	err := wrapped(context.Background(), newStreamConn(bearerHeader("letmein")))
	require.NoError(t, err)
	assert.True(t, spy.called)
}

func TestStreamAuthorizeDeniesWhenRoleMissing(t *testing.T) {
	t.Parallel()

	spy := &recordingStream{}
	authn := connectrpcsec.NewAuthenticationInterceptor(newEngine())
	authz := connectrpcsec.NewAuthorizationInterceptor(adminADM(), adminAttrs)
	wrapped := authn.WrapStreamingHandler(authz.WrapStreamingHandler(spy.fn))

	err := wrapped(context.Background(), newStreamConn(bearerHeader("letmein")))
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	assert.False(t, spy.called)
}

func TestStreamAuthorizeIsPassThroughForClient(t *testing.T) {
	t.Parallel()

	called := false

	next := func(_ context.Context, _ connect.Spec) connect.StreamingClientConn {
		called = true

		return nil
	}

	wrapped := connectrpcsec.NewAuthorizationInterceptor(adminADM(), adminAttrs).WrapStreamingClient(next)
	_ = wrapped(context.Background(), connect.Spec{})

	assert.True(t, called)
}
