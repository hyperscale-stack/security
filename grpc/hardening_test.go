// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"testing"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// challengeExtractor stages a response header on the carrier, like an
// extractor issuing a challenge, then delegates to tokenExtractor.
type challengeExtractor struct{}

func (challengeExtractor) Extract(ctx context.Context, c security.Carrier) (security.Authentication, error) {
	c.Set("WWW-Authenticate", `Bearer realm="api"`)

	return tokenExtractor{}.Extract(ctx, c)
}

// brokenEngine breaks the Engine contract.
type brokenEngine struct{}

func (brokenEngine) Process(context.Context, security.Carrier) (context.Context, security.Authentication, error) {
	return nil, nil, nil
}

// Audit CORE-I4 (probe TestZZAuditCarrierWritesAreDropped): the carrier
// staged writes the documentation said the interceptor flushed; it never
// did.
func TestUnaryInterceptorSendsStagedHeaders(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(tokenAuthenticator{}), challengeExtractor{})
	client := dialBufconn(t, grpcsec.UnaryServerInterceptor(engine), nil)

	for name, ctx := range map[string]context.Context{
		"refused":  context.Background(),
		"accepted": bearer(context.Background(), "letmein"),
	} {
		var header metadata.MD

		_, _ = client.Check(ctx, &healthpb.HealthCheckRequest{}, grpc.Header(&header))

		assert.Equal(t, []string{`Bearer realm="api"`}, header.Get("www-authenticate"), name)
	}
}

func TestStreamInterceptorSendsStagedHeaders(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(tokenAuthenticator{}), challengeExtractor{})
	client := dialBufconn(t, nil, grpcsec.StreamServerInterceptor(engine))

	for name, ctx := range map[string]context.Context{
		"refused":  context.Background(),
		"accepted": bearer(context.Background(), "letmein"),
	} {
		stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{})
		require.NoError(t, err, name)

		_, _ = stream.Recv()

		header, err := stream.Header()
		if err == nil {
			assert.Equal(t, []string{`Bearer realm="api"`}, header.Get("www-authenticate"), name)
		} else {
			assert.Equal(t, []string{`Bearer realm="api"`}, stream.Trailer().Get("www-authenticate"), name)
		}
	}
}

// Audit CORE-15 (probe TestZZAuditCarrierPrintsCredentials): printing a
// Carrier printed the incoming metadata, bearer token included.
func TestCarrierRedactsItself(t *testing.T) {
	t.Parallel()

	const token = "eyJhbGciOi.secret.token"

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	c := grpcsec.NewCarrier(ctx)
	c.Set("x-staged", "staged-value")

	var printed []string

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
		printed = append(printed, fmt.Sprintf(verb, c), fmt.Sprintf(verb, *c))
	}

	for _, handler := range []func(*bytes.Buffer) slog.Handler{
		func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer

		slog.New(handler(&buf)).Info("rpc", "carrier", c, "value", *c)
		printed = append(printed, buf.String())
	}

	for _, out := range printed {
		assert.NotContains(t, out, token)
		assert.NotContains(t, out, "staged-value")
	}

	assert.Equal(t, "grpcsec.Carrier{Incoming: 1 keys, Staged: 1 keys}", c.String())
}

// The audit's surviving mutant "invalid credentials tolerated under
// anonymous fallback".
func TestInterceptorsRefuseInvalidCredentialsUnderAnonymousFallback(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t,
		grpcsec.UnaryServerInterceptor(newEngine(), grpcsec.WithAnonymousFallback(true)),
		grpcsec.StreamServerInterceptor(newEngine(), grpcsec.WithAnonymousFallback(true)),
	)

	_, err := client.Check(bearer(context.Background(), "wrong"), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	stream, err := client.Watch(bearer(context.Background(), "wrong"), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	_, err = stream.Recv()
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// Audit CORE-I5 (probe TestZZAuditMultipleAuthorizationValues): the first of
// several authorization values silently won.
func TestInterceptorRefusesARepeatedAuthorizationField(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t, grpcsec.UnaryServerInterceptor(newEngine()), nil)

	for _, pair := range [][2]string{{"letmein", "garbage"}, {"garbage", "letmein"}} {
		ctx := metadata.AppendToOutgoingContext(context.Background(),
			"authorization", "Bearer "+pair[0], "authorization", "Bearer "+pair[1])

		_, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", pair)
	}
}

// Audit CORE-I3: a custom Engine breaking its contract must not panic the
// server (gRPC has no recovery interceptor by default).
func TestInterceptorsFailClosedOnABrokenEngine(t *testing.T) {
	t.Parallel()

	client := dialBufconn(t,
		grpcsec.UnaryServerInterceptor(brokenEngine{}),
		grpcsec.StreamServerInterceptor(brokenEngine{}, grpcsec.WithAnonymousFallback(true)),
	)

	_, err := client.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.Internal, status.Code(err))

	stream, err := client.Watch(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	_, err = stream.Recv()
	assert.Equal(t, codes.Internal, status.Code(err))
}

// mapperAnswering is an ErrorMapper mock answering every error with code;
// it must be used.
func mapperAnswering(t *testing.T, code codes.Code) *grpcsec.MockErrorMapper {
	t.Helper()

	m := grpcsec.NewMockErrorMapper(t)
	m.EXPECT().Map(mock.Anything, mock.Anything).Return(status.Error(code, "custom"))

	return m
}

// The authorization interceptors answer with the authentication
// interceptor's mapper unless they were given their own.
func TestAuthorizeUsesTheAuthenticationInterceptorsMapper(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
	attrs := []security.Attribute{security.Role("ADMIN")}
	custom := grpcsec.WithErrorMapper(mapperAnswering(t, codes.Aborted))

	inherited := dialWithOptions(t, slices.Concat(
		grpcsec.ServerOptions(newEngine("ROLE_USER"), custom),
		grpcsec.AuthorizeServerOptions(adm, attrs),
	)...)

	_, err := inherited.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.Aborted, status.Code(err))

	own := dialWithOptions(t, slices.Concat(
		grpcsec.ServerOptions(newEngine("ROLE_USER"), custom),
		grpcsec.AuthorizeServerOptions(adm, attrs, grpcsec.WithErrorMapper(mapperAnswering(t, codes.DataLoss))),
	)...)

	_, err = own.Check(bearer(context.Background(), "letmein"), &healthpb.HealthCheckRequest{})
	assert.Equal(t, codes.DataLoss, status.Code(err))
}

// Audit CORE-05: the documented wiring installed only unary interceptors,
// so streaming RPCs ran unauthenticated. ServerOptions and
// AuthorizeServerOptions cover both RPC kinds.
func TestServerOptionsProtectUnaryAndStreamingRPCs(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasScope("watch"))
	attrs := []security.Attribute{security.Scope("watch")}

	client := func(authorities ...string) healthpb.HealthClient {
		return dialWithOptions(t, slices.Concat(
			grpcsec.ServerOptions(newEngine(authorities...)),
			grpcsec.AuthorizeServerOptions(adm, attrs),
		)...)
	}

	watch := func(c healthpb.HealthClient, ctx context.Context) codes.Code {
		stream, err := c.Watch(ctx, &healthpb.HealthCheckRequest{})
		require.NoError(t, err)

		_, err = stream.Recv()

		return status.Code(err)
	}

	check := func(c healthpb.HealthClient, ctx context.Context) codes.Code {
		_, err := c.Check(ctx, &healthpb.HealthCheckRequest{})

		return status.Code(err)
	}

	granted := client("scope:watch")
	denied := client("scope:other")

	assert.Equal(t, codes.Unauthenticated, check(granted, context.Background()))
	assert.Equal(t, codes.Unauthenticated, watch(granted, context.Background()))
	assert.Equal(t, codes.PermissionDenied, check(denied, bearer(context.Background(), "letmein")))
	assert.Equal(t, codes.PermissionDenied, watch(denied, bearer(context.Background(), "letmein")))
	assert.Equal(t, codes.OK, check(granted, bearer(context.Background(), "letmein")))
	assert.Equal(t, codes.OK, watch(granted, bearer(context.Background(), "letmein")))
}

func TestAuthorizeRefusesANilDecisionManager(t *testing.T) {
	t.Parallel()

	const want = "grpcsec: nil AccessDecisionManager"

	assert.PanicsWithValue(t, want, func() { grpcsec.UnaryAuthorize(nil, nil) })
	assert.PanicsWithValue(t, want, func() { grpcsec.StreamAuthorize(nil, nil) })
	assert.PanicsWithValue(t, want, func() { grpcsec.AuthorizeServerOptions(nil, nil) })
}

func TestAuthorizeKeepsANonAccessErrorOfACustomManager(t *testing.T) {
	t.Parallel()

	outage := scriptedADM{err: fmt.Errorf("policy store: %w", security.ErrUnavailable)}
	bug := scriptedADM{err: errors.New("policy bug")}

	for want, adm := range map[codes.Code]security.AccessDecisionManager{codes.Unavailable: outage, codes.Internal: bug} {
		client := dialBufconn(t, grpcsec.UnaryAuthorize(adm, nil), nil)

		_, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{})
		assert.Equal(t, want, status.Code(err))
	}
}

// scriptedADM forces a decision error.
type scriptedADM struct{ err error }

func (s scriptedADM) Decide(context.Context, security.Authentication, []security.Attribute) error {
	return s.err
}
