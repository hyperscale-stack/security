// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// derefAuth reads a field in every method: a typed nil — (*derefAuth)(nil),
// the classic `var out *T; return out, nil` — satisfies Authentication but
// panics on its first method call.
type derefAuth struct{ name string }

func (a *derefAuth) Principal() security.Principal { return fakePrincipal{sub: a.name} }
func (a *derefAuth) Credentials() any              { return a.name }
func (a *derefAuth) Authorities() []string         { return []string{a.name} }
func (a *derefAuth) IsAuthenticated() bool         { return a.name != "" }
func (a *derefAuth) Name() string                  { return a.name }

// derefAttr is the Attribute counterpart of derefAuth.
type derefAttr struct{ name string }

func (a *derefAttr) String() string { return a.name }

var (
	typedNilAuth security.Authentication = (*derefAuth)(nil)
	typedNilAttr security.Attribute      = (*derefAttr)(nil)
)

// scriptedEngine is a custom Engine returning a fixed authentication, with
// or without a context.
type scriptedEngine struct {
	auth       security.Authentication
	nilContext bool
}

func (e scriptedEngine) Process(ctx context.Context, _ security.Carrier) (context.Context, security.Authentication, error) {
	if e.nilContext {
		return nil, e.auth, nil
	}

	return security.WithAuthentication(ctx, e.auth), e.auth, nil
}

func watchCode(t *testing.T, c healthpb.HealthClient, ctx context.Context) codes.Code {
	t.Helper()

	stream, err := c.Watch(ctx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	_, err = stream.Recv()

	return status.Code(err)
}

func checkCode(c healthpb.HealthClient, ctx context.Context) codes.Code {
	_, err := c.Check(ctx, &healthpb.HealthCheckRequest{})

	return status.Code(err)
}

// Review finding 2 (CORE-I3): a nil engine crashed the server on the first
// RPC — grpc-go recovers no panic.
func TestInterceptorsRefuseANilEngine(t *testing.T) {
	t.Parallel()

	const want = "grpcsec: nil Engine"

	assert.PanicsWithValue(t, want, func() { grpcsec.UnaryServerInterceptor(nil) })
	assert.PanicsWithValue(t, want, func() { grpcsec.StreamServerInterceptor(nil) })
	assert.PanicsWithValue(t, want, func() { grpcsec.ServerOptions(nil) })
}

// Review findings 2 and 3 (mutant R28g): a custom Engine returning a typed
// nil, or no context with an authenticated value, is an internal error.
func TestInterceptorsFailClosedOnAnEngineBreakingItsContract(t *testing.T) {
	t.Parallel()

	for name, engine := range map[string]security.Engine{
		"typed nil authentication":        scriptedEngine{auth: typedNilAuth},
		"no context, authenticated value": scriptedEngine{auth: newAuth("alice"), nilContext: true},
	} {
		for _, fallback := range []bool{false, true} {
			client := dialWithOptions(t, grpcsec.ServerOptions(engine, grpcsec.WithAnonymousFallback(fallback))...)

			assert.Equal(t, codes.Internal, checkCode(client, context.Background()), "%s, fallback=%v", name, fallback)
			assert.Equal(t, codes.Internal, watchCode(t, client, context.Background()), "%s, fallback=%v", name, fallback)
		}
	}
}

// Review finding 2: a nil attribute in the static configuration is refused
// at construction.
func TestAuthorizeRefusesNilAttributes(t *testing.T) {
	t.Parallel()

	const want = "grpcsec: nil Attribute at index 1"

	for _, attrs := range [][]security.Attribute{{security.Role("X"), nil}, {security.Role("X"), typedNilAttr}} {
		assert.PanicsWithValue(t, want, func() { grpcsec.UnaryAuthorize(scriptedADM{}, attrs) })
		assert.PanicsWithValue(t, want, func() { grpcsec.StreamAuthorize(scriptedADM{}, attrs) })
		assert.PanicsWithValue(t, want, func() { grpcsec.AuthorizeServerOptions(scriptedADM{}, attrs) })
	}
}

// Review nit 8: the authorization interceptors kept the caller's slice.
func TestAuthorizeCopiesItsAttributes(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"), voter.HasRole("USER"))
	attrs := []security.Attribute{security.Role("ADMIN")}

	client := dialWithOptions(t, slices.Concat(
		grpcsec.ServerOptions(newEngine("ROLE_USER")),
		grpcsec.AuthorizeServerOptions(adm, attrs),
	)...)

	attrs[0] = security.Role("USER")

	assert.Equal(t, codes.PermissionDenied, checkCode(client, bearer(context.Background(), "letmein")))
	assert.Equal(t, codes.PermissionDenied, watchCode(t, client, bearer(context.Background(), "letmein")))
}

// Review finding 3 (mutant R35): a custom decision manager refusing an
// anonymous caller with ErrInsufficientScope asks it to authenticate.
func TestAuthorizeAsksAnAnonymousCallerToAuthenticateOnInsufficientScope(t *testing.T) {
	t.Parallel()

	adm := scriptedADM{err: fmt.Errorf("policy: %w", security.ErrInsufficientScope)}
	client := dialWithOptions(t, grpcsec.AuthorizeServerOptions(adm, nil)...)

	assert.Equal(t, codes.Unauthenticated, checkCode(client, context.Background()))
	assert.Equal(t, codes.Unauthenticated, watchCode(t, client, context.Background()))
}

// Review finding 3 (mutants R37a, R37b): the options reach the stream
// chains of ServerOptions and AuthorizeServerOptions too.
func TestServerOptionsPassTheirOptionsToBothChains(t *testing.T) {
	t.Parallel()

	fallback := dialWithOptions(t, grpcsec.ServerOptions(newEngine(), grpcsec.WithAnonymousFallback(true))...)

	assert.Equal(t, codes.OK, checkCode(fallback, context.Background()))
	assert.Equal(t, codes.OK, watchCode(t, fallback, context.Background()))

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
	attrs := []security.Attribute{security.Role("ADMIN")}

	own := dialWithOptions(t, slices.Concat(
		grpcsec.ServerOptions(newEngine("ROLE_USER"), grpcsec.WithErrorMapper(fixedMapper{code: codes.Aborted})),
		grpcsec.AuthorizeServerOptions(adm, attrs, grpcsec.WithErrorMapper(fixedMapper{code: codes.DataLoss})),
	)...)

	assert.Equal(t, codes.Aborted, checkCode(own, context.Background()), "authentication mapper")
	assert.Equal(t, codes.Aborted, watchCode(t, own, context.Background()), "authentication mapper")
	assert.Equal(t, codes.DataLoss, checkCode(own, bearer(context.Background(), "letmein")), "authorization mapper")
	assert.Equal(t, codes.DataLoss, watchCode(t, own, bearer(context.Background(), "letmein")), "authorization mapper")
}
