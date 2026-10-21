// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
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

// Review finding 2 (CORE-I3): a nil engine panicked on the first request.
func TestMiddlewareRefusesANilEngine(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "httpsec: Middleware: nil Engine", func() { httpsec.Middleware(nil) })
}

// Review findings 2 and 3 (mutant R28): a custom Engine returning a typed
// nil, or no context with an authenticated value, is an internal error —
// never a panic, never a pass.
func TestMiddlewareFailsClosedOnAnEngineBreakingItsContract(t *testing.T) {
	t.Parallel()

	for name, engine := range map[string]security.Engine{
		"typed nil authentication":        scriptedEngine{auth: typedNilAuth},
		"no context, authenticated value": scriptedEngine{auth: newAuth("alice").verified(), nilContext: true},
		"no context, typed nil":           scriptedEngine{auth: typedNilAuth, nilContext: true},
	} {
		for _, fallback := range []bool{false, true} {
			var rec *httptest.ResponseRecorder

			h := httpsec.Middleware(engine, httpsec.WithAnonymousFallback(fallback))(next204())

			require.NotPanics(t, func() { rec = serve(h, bearerRequest()) }, "%s, fallback=%v", name, fallback)
			assert.Equal(t, http.StatusInternalServerError, rec.Code, "%s, fallback=%v", name, fallback)
		}
	}
}

// Review finding 2: a nil attribute in a route's static configuration is
// refused at construction instead of denying every request.
func TestAuthorizeRefusesNilAttributes(t *testing.T) {
	t.Parallel()

	const want = "httpsec: Authorize: nil Attribute at index 1"

	assert.PanicsWithValue(t, want, func() { httpsec.Authorize(scriptedADM{}, fakeAttr("x"), nil) })
	assert.PanicsWithValue(t, want, func() { httpsec.Authorize(scriptedADM{}, fakeAttr("x"), typedNilAttr) })
	assert.PanicsWithValue(t, want, func() { httpsec.AuthorizeWith(scriptedADM{}, nil, fakeAttr("x"), nil) })
}

// Review nit 8: Authorize kept the caller's slice, so reusing it for the
// next route rewrote the first route's policy.
func TestAuthorizeCopiesItsAttributes(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"), voter.HasRole("USER"))
	attrs := []security.Attribute{security.Role("ADMIN")}

	handlers := []http.Handler{
		httpsec.Authorize(adm, attrs...)(next204()),
		httpsec.AuthorizeWith(adm, nil, attrs...)(next204()),
	}

	attrs[0] = security.Role("USER")

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req = req.WithContext(security.WithAuthentication(req.Context(), newAuth("alice", "ROLE_USER").verified()))

	for _, h := range handlers {
		assert.Equal(t, http.StatusForbidden, serve(h, req).Code)
	}
}

// Review finding 3 (mutant R31): a custom decision manager refusing an
// anonymous caller with ErrInsufficientScope asks it to authenticate.
func TestAuthorizeAsksAnAnonymousCallerToAuthenticateOnInsufficientScope(t *testing.T) {
	t.Parallel()

	h := httpsec.Authorize(scriptedADM{err: fmt.Errorf("policy: %w", security.ErrInsufficientScope)}, fakeAttr("x"))(next204())

	rec := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{bearerAPI}, rec.Header().Values("WWW-Authenticate"))
}

// Review finding 5 (RFC 6750 §3) and nit 12 (mutant R22): a Bearer resource
// refusing a malformed request challenges it — with the invalid_request
// code when one of the Authorization fields carried a bearer token.
func TestMiddlewareChallengesAMalformedRequest(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(&scriptedAuthn{name: "x", result: newAuth("alice").verified()}), singleValueExtractor{})

	for name, c := range map[string]struct {
		fields []string
		want   string
	}{
		"two Basic fields":       {[]string{"Basic dTpw", "Basic dTpx"}, bearerAPI},
		"Basic then Bearer":      {[]string{"Basic dTpw", "Bearer some-token"}, invalidRequest},
		"Bearer then lowercased": {[]string{"Bearer a", "bearer b"}, invalidRequest},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, f := range c.fields {
			req.Header.Add("Authorization", f)
		}

		rec := serve(httpsec.Middleware(engine)(next204()), req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, name)
		assert.Equal(t, []string{c.want}, rec.Header().Values("WWW-Authenticate"), name)
	}
}

// typedNilEngine is an Engine implemented on a pointer.
type typedNilEngine struct{}

func (*typedNilEngine) Process(ctx context.Context, _ security.Carrier) (context.Context, security.Authentication, error) {
	return ctx, nil, nil
}

// typedNilADM is an AccessDecisionManager implemented on a pointer.
type typedNilADM struct{}

func (*typedNilADM) Decide(context.Context, security.Authentication, []security.Attribute) error {
	return nil
}

// typedNilMapper is an ErrorMapper implemented on a pointer.
type typedNilMapper struct{}

func (*typedNilMapper) Map(http.ResponseWriter, *http.Request, error) {}

// Audit I-27 and review m8: typed-nil dependencies were accepted and
// panicked on the first request; a typed-nil error mapper panicked on the
// first refusal. Constructors refuse the former; the latter counts as no
// mapper.
func TestTypedNilDependencies(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "httpsec: Middleware: nil Engine", func() { httpsec.Middleware((*typedNilEngine)(nil)) })
	assert.PanicsWithValue(t, "httpsec: Authorize: nil AccessDecisionManager", func() { httpsec.Authorize((*typedNilADM)(nil)) })

	engine := security.NewEngine(security.NewManager(&scriptedAuthn{name: "x", err: security.ErrInvalidCredentials}),
		scriptedExtractor{auth: newAuth("alice")})

	rec := serve(httpsec.Middleware(engine, httpsec.WithErrorMapper((*typedNilMapper)(nil)))(next204()), bearerRequest())
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "the default mapper answers")

	adm := scriptedADM{err: security.ErrAccessDenied}
	req := bearerRequest().WithContext(security.WithAuthentication(context.Background(), newAuth("alice").verified()))
	rec = serve(httpsec.AuthorizeWith(adm, (*typedNilMapper)(nil))(next204()), req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "the default mapper answers")
}
