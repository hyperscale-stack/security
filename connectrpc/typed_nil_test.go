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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type typedNilEngine struct{}

func (*typedNilEngine) Process(ctx context.Context, _ security.Carrier) (context.Context, security.Authentication, error) {
	return ctx, nil, nil
}

type typedNilADM struct{}

func (*typedNilADM) Decide(context.Context, security.Authentication, []security.Attribute) error {
	return nil
}

type typedNilMapper struct{}

func (*typedNilMapper) Map(context.Context, error) error { return nil }

// Audit I-27 and review m8: typed-nil dependencies were accepted and
// panicked on the first RPC, a typed-nil error mapper on the first refusal.
func TestTypedNilDependencies(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "connectrpcsec: NewAuthenticationInterceptor: nil Engine",
		func() { connectrpcsec.NewAuthenticationInterceptor((*typedNilEngine)(nil)) })
	assert.PanicsWithValue(t, "connectrpcsec: NewAuthorizationInterceptor: nil AccessDecisionManager",
		func() { connectrpcsec.NewAuthorizationInterceptor((*typedNilADM)(nil), nil) })

	mapper := connectrpcsec.WithErrorMapper((*typedNilMapper)(nil))
	engine := security.NewEngine(security.NewManager(tokenAuthenticator{}), tokenExtractor{})

	_, err := connectrpcsec.NewAuthenticationInterceptor(engine, mapper).WrapUnary((&recordingUnary{}).fn)(
		context.Background(), unaryReq(""))

	var ce *connect.Error

	require.ErrorAs(t, err, &ce, "the default mapper answers")
	assert.Equal(t, connect.CodeUnauthenticated, ce.Code())

	authz := connectrpcsec.NewAuthorizationInterceptor(scriptedADM{err: security.ErrAccessDenied}, nil, mapper)
	ctx := security.WithAuthentication(context.Background(), newAuth("alice"))

	_, err = authz.WrapUnary((&recordingUnary{}).fn)(ctx, unaryReq("letmein"))
	require.ErrorAs(t, err, &ce, "the default mapper answers")
	assert.Equal(t, connect.CodePermissionDenied, ce.Code())
}
