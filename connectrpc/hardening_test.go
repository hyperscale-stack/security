// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	invalidToken   = `Bearer realm="api", error="invalid_token", error_description="The access token is invalid or has expired."`
	insufficient   = `Bearer realm="api", error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token."`
	invalidRequest = `Bearer realm="api", error="invalid_request", error_description="The request is malformed."`
)

// brokenEngine breaks the Engine contract.
type brokenEngine struct{}

func (brokenEngine) Process(context.Context, security.Carrier) (context.Context, security.Authentication, error) {
	return nil, nil, nil
}

func connectError(t *testing.T, err error) *connect.Error {
	t.Helper()

	var ce *connect.Error
	require.ErrorAs(t, err, &ce)

	return ce
}

func requestWith(authorization ...string) connect.AnyRequest {
	req := connect.NewRequest(&struct{}{})
	for _, v := range authorization {
		req.Header().Add("Authorization", v)
	}

	return req
}

// Audit CORE-10: the RFC 6750 codes ride on the challenge of a request that
// carried a bearer token, and only then.
func TestWrapUnaryChallenges(t *testing.T) {
	t.Parallel()

	spy := &recordingUnary{}
	authn := connectrpcsec.NewAuthenticationInterceptor(newEngine())

	cases := []struct {
		name      string
		req       connect.AnyRequest
		code      connect.Code
		challenge []string
	}{
		{"no token", requestWith(), connect.CodeUnauthenticated, []string{bearerAPI}},
		{"bad token", requestWith("Bearer wrong"), connect.CodeUnauthenticated, []string{invalidToken}},
		{"repeated authorization", requestWith("Bearer letmein", "Bearer wrong"), connect.CodeInvalidArgument, []string{invalidRequest}},
		{"another scheme", requestWith("Basic dTpw"), connect.CodeUnauthenticated, []string{bearerAPI}},
	}

	for _, c := range cases {
		_, err := authn.WrapUnary(spy.fn)(context.Background(), c.req)

		ce := connectError(t, err)
		assert.Equal(t, c.code, ce.Code(), c.name)
		assert.Equal(t, c.challenge, ce.Meta().Values("WWW-Authenticate"), c.name)
	}

	assert.False(t, spy.called)
}

func TestAuthorizationChallenges(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
	attrs := []security.Attribute{security.Role("ADMIN")}

	// Authenticated USER with a bearer token: 403 insufficient_scope.
	spy := &recordingUnary{}
	_, err := chainUnary(
		connectrpcsec.NewAuthenticationInterceptor(newEngine("ROLE_USER")),
		connectrpcsec.NewAuthorizationInterceptor(adm, attrs),
		spy.fn,
	)(context.Background(), unaryReq("letmein"))

	ce := connectError(t, err)
	assert.Equal(t, connect.CodePermissionDenied, ce.Code())
	assert.Equal(t, []string{insufficient}, ce.Meta().Values("WWW-Authenticate"))

	// Anonymous (fallback): asked to authenticate, with the authentication
	// interceptor's challenge.
	_, err = chainUnary(
		connectrpcsec.NewAuthenticationInterceptor(newEngine(), connectrpcsec.WithAnonymousFallback(true),
			connectrpcsec.WithChallengeScheme("Basic")),
		connectrpcsec.NewAuthorizationInterceptor(adm, attrs),
		spy.fn,
	)(context.Background(), unaryReq(""))

	ce = connectError(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, ce.Code())
	assert.Equal(t, []string{basicAPI}, ce.Meta().Values("WWW-Authenticate"))

	// Streaming refusal carries the challenge too.
	stream := &recordingStream{}
	err = connectrpcsec.NewAuthenticationInterceptor(newEngine()).WrapStreamingHandler(stream.fn)(
		context.Background(), newStreamConn(bearerHeader("wrong")))

	ce = connectError(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, ce.Code())
	assert.Equal(t, []string{invalidToken}, ce.Meta().Values("WWW-Authenticate"))
	assert.False(t, spy.called)
	assert.False(t, stream.called)
}

// Staged carrier writes reach the client on a refusal too (they were
// dropped), and on a handler error.
func TestWrapUnaryFlushesStagedHeadersOnRefusalAndHandlerError(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(tokenAuthenticator{}), writingExtractor{})
	interceptor := connectrpcsec.NewAuthenticationInterceptor(engine)

	_, err := interceptor.WrapUnary((&recordingUnary{}).fn)(context.Background(), unaryReq("wrong"))
	assert.Equal(t, "applied", connectError(t, err).Meta().Get("X-Authn-Trace"))

	failing := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, connect.NewError(connect.CodeAborted, errors.New("handler failed"))
	}

	_, err = interceptor.WrapUnary(failing)(context.Background(), unaryReq("letmein"))
	assert.Equal(t, "applied", connectError(t, err).Meta().Get("X-Authn-Trace"))

	conn := newStreamConn(bearerHeader("wrong"))
	err = interceptor.WrapStreamingHandler((&recordingStream{}).fn)(context.Background(), conn)
	require.Error(t, err)
	assert.Equal(t, "applied", conn.ResponseHeader().Get("X-Authn-Trace"))
}

// Audit CORE-15: printing a Carrier printed the incoming headers, the
// bearer token included.
func TestCarrierRedactsItself(t *testing.T) {
	t.Parallel()

	const token = "eyJhbGciOi.secret.token"

	c := connectrpcsec.NewCarrier(http.Header{"Authorization": {"Bearer " + token}})
	c.Set("X-Staged", "staged-value")

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

	assert.Equal(t, "connectrpcsec.Carrier{Incoming: 1 keys, Staged: 1 keys}", c.String())
}

// The audit's surviving mutant "invalid credentials tolerated under
// anonymous fallback".
func TestInterceptorRefusesInvalidCredentialsUnderAnonymousFallback(t *testing.T) {
	t.Parallel()

	interceptor := connectrpcsec.NewAuthenticationInterceptor(newEngine(), connectrpcsec.WithAnonymousFallback(true))

	_, err := interceptor.WrapUnary((&recordingUnary{}).fn)(context.Background(), unaryReq("wrong"))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))

	err = interceptor.WrapStreamingHandler((&recordingStream{}).fn)(context.Background(), newStreamConn(bearerHeader("wrong")))
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// Audit CORE-I3.
func TestInterceptorFailsClosedOnABrokenEngine(t *testing.T) {
	t.Parallel()

	interceptor := connectrpcsec.NewAuthenticationInterceptor(brokenEngine{}, connectrpcsec.WithAnonymousFallback(true))

	var err error

	require.NotPanics(t, func() {
		_, err = interceptor.WrapUnary((&recordingUnary{}).fn)(context.Background(), unaryReq("letmein"))
	})
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))

	require.NotPanics(t, func() {
		err = interceptor.WrapStreamingHandler((&recordingStream{}).fn)(context.Background(), newStreamConn(nil))
	})
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}

type fixedMapper struct{ code connect.Code }

func (m fixedMapper) Map(context.Context, error) error {
	return connect.NewError(m.code, errors.New("custom"))
}

func TestAuthorizationUsesTheAuthenticationInterceptorsMapper(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
	attrs := []security.Attribute{security.Role("ADMIN")}
	authn := connectrpcsec.NewAuthenticationInterceptor(newEngine("ROLE_USER"),
		connectrpcsec.WithErrorMapper(fixedMapper{code: connect.CodeAborted}))

	_, err := chainUnary(authn, connectrpcsec.NewAuthorizationInterceptor(adm, attrs), (&recordingUnary{}).fn)(
		context.Background(), unaryReq("letmein"))
	assert.Equal(t, connect.CodeAborted, connect.CodeOf(err))

	own := connectrpcsec.NewAuthorizationInterceptor(adm, attrs, connectrpcsec.WithErrorMapper(fixedMapper{code: connect.CodeDataLoss}))
	_, err = chainUnary(authn, own, (&recordingUnary{}).fn)(context.Background(), unaryReq("letmein"))
	assert.Equal(t, connect.CodeDataLoss, connect.CodeOf(err))
}

func TestAuthorizationRefusesANilDecisionManager(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "connectrpcsec: NewAuthorizationInterceptor: nil AccessDecisionManager",
		func() { connectrpcsec.NewAuthorizationInterceptor(nil, nil) })
}

func TestAuthorizationKeepsANonAccessErrorOfACustomManager(t *testing.T) {
	t.Parallel()

	for want, err := range map[connect.Code]error{
		connect.CodeUnavailable: fmt.Errorf("policy store: %w", security.ErrUnavailable),
		connect.CodeInternal:    errors.New("policy bug"),
	} {
		authz := connectrpcsec.NewAuthorizationInterceptor(scriptedADM{err: err}, nil)

		_, got := authz.WrapUnary((&recordingUnary{}).fn)(context.Background(), unaryReq(""))
		assert.Equal(t, want, connect.CodeOf(got))
	}
}

type scriptedADM struct{ err error }

func (s scriptedADM) Decide(context.Context, security.Authentication, []security.Attribute) error {
	return s.err
}
