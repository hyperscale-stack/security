// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
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

// Audit I-27 and review m8: a typed-nil engine or decision manager was
// accepted and crashed the server on the first RPC — grpc-go recovers no
// panic —, and a typed-nil error mapper on the first refusal, outside the
// panic containment. Constructors refuse the former; the latter counts as
// no mapper.
func TestTypedNilDependencies(t *testing.T) {
	t.Parallel()

	const (
		wantEngine = "grpcsec: nil Engine"
		wantADM    = "grpcsec: nil AccessDecisionManager"
	)

	assert.PanicsWithValue(t, wantEngine, func() { grpcsec.UnaryServerInterceptor((*typedNilEngine)(nil)) })
	assert.PanicsWithValue(t, wantEngine, func() { grpcsec.StreamServerInterceptor((*typedNilEngine)(nil)) })
	assert.PanicsWithValue(t, wantADM, func() { grpcsec.UnaryAuthorize((*typedNilADM)(nil), nil) })
	assert.PanicsWithValue(t, wantADM, func() { grpcsec.StreamAuthorize((*typedNilADM)(nil), nil) })

	mapper := grpcsec.WithErrorMapper((*typedNilMapper)(nil))
	client := dialWithOptions(t, append(grpcsec.ServerOptions(newEngine(), mapper),
		grpcsec.AuthorizeServerOptions(scriptedADM{err: security.ErrAccessDenied}, nil, mapper)...)...)

	_, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "the default mapper answers")

	_, err = client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "the default mapper answers")
}
