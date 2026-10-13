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
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Review finding 2 (CORE-I3): a nil engine panicked on the first RPC.
func TestAuthenticationInterceptorRefusesANilEngine(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "connectrpcsec: NewAuthenticationInterceptor: nil Engine",
		func() { connectrpcsec.NewAuthenticationInterceptor(nil) })
}

// Review findings 2 and 3 (mutant R28c): a custom Engine returning a typed
// nil, or no context with an authenticated value, is an internal error.
func TestInterceptorFailsClosedOnAnEngineBreakingItsContract(t *testing.T) {
	t.Parallel()

	for name, engine := range map[string]security.Engine{
		"typed nil authentication":        scriptedEngine{auth: typedNilAuth},
		"no context, authenticated value": scriptedEngine{auth: newAuth("alice"), nilContext: true},
	} {
		for _, fallback := range []bool{false, true} {
			interceptor := connectrpcsec.NewAuthenticationInterceptor(engine, connectrpcsec.WithAnonymousFallback(fallback))

			var err error

			require.NotPanics(t, func() {
				_, err = interceptor.WrapUnary((&recordingUnary{}).fn)(context.Background(), unaryReq("letmein"))
			}, "%s, fallback=%v", name, fallback)
			assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "%s, fallback=%v", name, fallback)

			require.NotPanics(t, func() {
				err = interceptor.WrapStreamingHandler((&recordingStream{}).fn)(context.Background(), newStreamConn(nil))
			}, "%s, fallback=%v", name, fallback)
			assert.Equal(t, connect.CodeInternal, connect.CodeOf(err), "%s, fallback=%v", name, fallback)
		}
	}
}

// Review finding 2: a nil attribute in the static configuration is refused
// at construction.
func TestAuthorizationRefusesNilAttributes(t *testing.T) {
	t.Parallel()

	const want = "connectrpcsec: NewAuthorizationInterceptor: nil Attribute at index 1"

	for _, attrs := range [][]security.Attribute{{security.Role("X"), nil}, {security.Role("X"), typedNilAttr}} {
		assert.PanicsWithValue(t, want, func() { connectrpcsec.NewAuthorizationInterceptor(scriptedADM{}, attrs) })
	}
}

// Review nit 8: the authorization interceptor kept the caller's slice.
func TestAuthorizationCopiesItsAttributes(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"), voter.HasRole("USER"))
	attrs := []security.Attribute{security.Role("ADMIN")}
	authz := connectrpcsec.NewAuthorizationInterceptor(adm, attrs)

	attrs[0] = security.Role("USER")

	_, err := chainUnary(connectrpcsec.NewAuthenticationInterceptor(newEngine("ROLE_USER")), authz, (&recordingUnary{}).fn)(
		context.Background(), unaryReq("letmein"))

	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

// Review finding 3 (mutant R39): a custom decision manager refusing an
// anonymous caller with ErrInsufficientScope asks it to authenticate.
func TestAuthorizationAsksAnAnonymousCallerToAuthenticateOnInsufficientScope(t *testing.T) {
	t.Parallel()

	authz := connectrpcsec.NewAuthorizationInterceptor(scriptedADM{err: fmt.Errorf("policy: %w", security.ErrInsufficientScope)}, nil)

	_, err := authz.WrapUnary((&recordingUnary{}).fn)(context.Background(), unaryReq(""))

	ce := connectError(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, ce.Code())
	assert.Equal(t, []string{bearerAPI}, ce.Meta().Values("WWW-Authenticate"))
}

// Review finding 5 (RFC 6750 §3) and nit 12 (mutants R54, R55): a Bearer
// resource refusing a malformed request challenges it — with the
// invalid_request code when an Authorization field carried a bearer token,
// whatever its position and the case of its scheme.
func TestWrapUnaryChallengesAMalformedRequest(t *testing.T) {
	t.Parallel()

	authn := connectrpcsec.NewAuthenticationInterceptor(newEngine())

	for name, c := range map[string]struct {
		fields []string
		want   string
	}{
		"two Basic fields":      {[]string{"Basic dTpw", "Basic dTpx"}, bearerAPI},
		"Basic then Bearer":     {[]string{"Basic dTpw", "Bearer letmein"}, invalidRequest},
		"lowercase bearer ×2":   {[]string{"bearer a", "bearer b"}, invalidRequest},
		"Bearer then Basic":     {[]string{"Bearer letmein", "Basic dTpw"}, invalidRequest},
		"uppercase BEARER ×2":   {[]string{"BEARER a", "BEARER b"}, invalidRequest},
		"Digest then lowercase": {[]string{"Digest x", "bearer b"}, invalidRequest},
	} {
		_, err := authn.WrapUnary((&recordingUnary{}).fn)(context.Background(), requestWith(c.fields...))

		ce := connectError(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, ce.Code(), name)
		assert.Equal(t, []string{c.want}, ce.Meta().Values("WWW-Authenticate"), name)
	}
}

// Review nit 12 (mutant R42): the authorization interceptor's streaming
// refusal of a bearer request carries insufficient_scope.
func TestStreamAuthorizationChallengesABearerRequest(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
	authn := connectrpcsec.NewAuthenticationInterceptor(newEngine("ROLE_USER"))
	authz := connectrpcsec.NewAuthorizationInterceptor(adm, []security.Attribute{security.Role("ADMIN")})
	stream := &recordingStream{}

	err := authn.WrapStreamingHandler(authz.WrapStreamingHandler(stream.fn))(context.Background(), newStreamConn(bearerHeader("letmein")))

	ce := connectError(t, err)
	assert.Equal(t, connect.CodePermissionDenied, ce.Code())
	assert.Equal(t, []string{insufficient}, ce.Meta().Values("WWW-Authenticate"))
	assert.False(t, stream.called)
}

// Re-review nit (mutant N6): a bearer request answered with a class that
// has no RFC 6750 code — authentication required, an outage, an internal
// error — gets the bare challenge, never an empty error="".
func TestWrapUnaryChallengesABearerRequestWithoutACode(t *testing.T) {
	t.Parallel()

	failing := func(err error) security.Engine {
		return security.NewEngine(security.NewManager(security.AuthenticatorFunc(
			func(context.Context, security.Authentication) (security.Authentication, error) { return nil, err })),
			tokenExtractor{})
	}

	for name, c := range map[string]struct {
		engine        security.Engine
		authorization string
		code          connect.Code
	}{
		"bearer scheme without a token": {newEngine(), "Bearer", connect.CodeUnauthenticated},
		"outage":                        {failing(fmt.Errorf("jwks: %w", security.ErrUnavailable)), "Bearer letmein", connect.CodeUnavailable},
		"internal error":                {failing(errors.New("verifier bug")), "Bearer letmein", connect.CodeInternal},
	} {
		_, err := connectrpcsec.NewAuthenticationInterceptor(c.engine).WrapUnary((&recordingUnary{}).fn)(
			context.Background(), requestWith(c.authorization))

		ce := connectError(t, err)
		assert.Equal(t, c.code, ce.Code(), name)
		assert.Equal(t, []string{bearerAPI}, ce.Meta().Values("WWW-Authenticate"), name)
	}
}
