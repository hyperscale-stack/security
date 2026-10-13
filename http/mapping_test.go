// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"context"
	"errors"
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

// singleValueExtractor reads Authorization the way the basic and bearer
// extractors do.
type singleValueExtractor struct{}

func (singleValueExtractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	v, err := security.SingleValue(c, "Authorization")
	if err != nil || v == "" {
		return nil, err
	}

	return newAuth("pending"), nil
}

// bailOut supports everything and bails out at runtime.
type bailOut struct{}

func (bailOut) Supports(security.Authentication) bool { return true }

func (bailOut) Authenticate(_ context.Context, _ security.Authentication) (security.Authentication, error) {
	return nil, fmt.Errorf("out of scope: %w", security.ErrUnsupportedCredential)
}

// brokenEngine breaks the Engine contract.
type brokenEngine struct{}

func (brokenEngine) Process(context.Context, security.Carrier) (context.Context, security.Authentication, error) {
	return nil, nil, nil
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func next204() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

func bearerRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	return req
}

// Audit CORE-10 (probe TestZZAuditChallenges).
func TestMiddlewareChallengesCarryARealm(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(), scriptedExtractor{})

	rec := serve(httpsec.Middleware(engine)(next204()), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{bearerAPI}, rec.Header().Values("WWW-Authenticate"))

	rec = serve(httpsec.Middleware(engine, httpsec.WithChallengeScheme("Basic"))(next204()), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{basicAPI}, rec.Header().Values("WWW-Authenticate"))
}

// The audit's surviving mutant "invalid credentials tolerated under
// anonymous fallback": the fallback admits requests without credentials,
// never requests with bad ones.
func TestMiddlewareInvalidCredentialsUnderAnonymousFallbackAre401(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "x", err: security.ErrInvalidCredentials}),
		scriptedExtractor{auth: newAuth("alice")},
	)

	rec := serve(httpsec.Middleware(engine, httpsec.WithAnonymousFallback(true))(next204()), bearerRequest())

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{invalidToken}, rec.Header().Values("WWW-Authenticate"))
}

// Audit CORE-10 (probe TestZZAuditJoinedErrorClassification): an
// authenticator bailing out at runtime turned a wrong password into a 400
// without challenge.
func TestMiddlewareCredentialFailureWinsOverABailOut(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(
		security.NewManager(bailOut{}, &scriptedAuthn{name: "x", err: security.ErrInvalidCredentials}),
		scriptedExtractor{auth: newAuth("alice")},
	)

	rec := serve(httpsec.Middleware(engine, httpsec.WithChallengeScheme("Basic"))(next204()), httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{basicAPI}, rec.Header().Values("WWW-Authenticate"))
}

// RFC 6750 §3.1: a request "attempted using an unsupported authentication
// method" lacks authentication information — 401 without error code.
func TestMiddlewareUnsupportedCredentialIs401WithoutErrorCode(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(), scriptedExtractor{auth: newAuth("alice")})

	rec := serve(httpsec.Middleware(engine)(next204()), bearerRequest())

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{bearerAPI}, rec.Header().Values("WWW-Authenticate"))
}

// Audit CORE-I6 / user decision: an outage is 503, a broken contract 500 —
// never a verdict on the credentials.
func TestMiddlewareAnswersOutagesAndBrokenContracts(t *testing.T) {
	t.Parallel()

	extract := scriptedExtractor{auth: newAuth("alice")}

	cases := map[string]struct {
		handler http.Handler
		status  int
	}{
		"unavailable": {httpsec.Middleware(security.NewEngine(security.NewManager(
			&scriptedAuthn{name: "x", err: fmt.Errorf("jwks: %w", security.ErrUnavailable)}), extract))(next204()), http.StatusServiceUnavailable},
		"no sentinel": {httpsec.Middleware(security.NewEngine(security.NewManager(
			&scriptedAuthn{name: "x", err: errors.New("boom")}), extract))(next204()), http.StatusInternalServerError},
		"broken engine": {httpsec.Middleware(brokenEngine{})(next204()), http.StatusInternalServerError},
		"broken engine with fallback": {httpsec.Middleware(brokenEngine{}, httpsec.WithAnonymousFallback(true))(next204()),
			http.StatusInternalServerError},
	}

	for name, c := range cases {
		var rec *httptest.ResponseRecorder

		require.NotPanics(t, func() { rec = serve(c.handler, bearerRequest()) }, name)
		assert.Equal(t, c.status, rec.Code, name)
		assert.Equal(t, []string{bearerAPI}, rec.Header().Values("WWW-Authenticate"), "RFC 6750 §3: %s", name)
	}
}

// Audit CORE-I5 (probe TestZZAuditMultipleAuthorizationHeaders): the first of
// several Authorization fields silently won.
func TestMiddlewareRefusesARepeatedAuthorizationField(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "x", result: newAuth("alice").verified()}),
		singleValueExtractor{},
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("Authorization", "Bearer good")
	req.Header.Add("Authorization", "Bearer other")

	rec := serve(httpsec.Middleware(engine)(next204()), req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, []string{invalidRequest}, rec.Header().Values("WWW-Authenticate"))
}

// Audit CORE-10 (probe TestZZAuditChallenges): Authorize answered an
// anonymous caller 403 with a hard-coded "Bearer" challenge, ignoring the
// middleware's scheme and realm.
func TestAuthorizeAsksAnAnonymousCallerToAuthenticate(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(), scriptedExtractor{})
	adm := security.NewAffirmativeDecisionManager(voter.Authenticated())

	h := httpsec.Middleware(engine, httpsec.WithAnonymousFallback(true), httpsec.WithChallengeScheme("Basic"), httpsec.WithRealm("api"))(
		httpsec.Authorize(adm, security.IsAuthenticated)(next204()))

	rec := serve(h, httptest.NewRequest(http.MethodGet, "/private", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{basicAPI}, rec.Header().Values("WWW-Authenticate"))
}

func TestAuthorizeWithoutMiddlewareUsesTheDefaultChallenge(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))

	rec := serve(httpsec.Authorize(adm, security.Role("ADMIN"))(next204()), httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{bearerAPI}, rec.Header().Values("WWW-Authenticate"))
}

// The audit called TestAuthorizeInsufficientScopeIncludesOAuthErrorParam
// vacuous: it scripted an error the real decision manager never returned.
func TestAuthorizeAuthenticatedDenialIs403(t *testing.T) {
	t.Parallel()

	adm := security.NewAffirmativeDecisionManager(voter.HasScope("reports:read"))
	h := httpsec.Authorize(adm, security.Scope("reports:read"))(next204())

	withToken := bearerRequest()
	withToken = withToken.WithContext(security.WithAuthentication(withToken.Context(), newAuth("svc", "scope:other").verified()))

	rec := serve(h, withToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, []string{insufficient}, rec.Header().Values("WWW-Authenticate"))

	session := httptest.NewRequest(http.MethodGet, "/", nil)
	session = session.WithContext(security.WithAuthentication(session.Context(), newAuth("alice", "scope:other").verified()))

	rec = serve(h, session)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, []string{bearerAPI}, rec.Header().Values("WWW-Authenticate"), "no bearer token, no RFC 6750 error code")
}

func TestAuthorizeKeepsANonAccessErrorOfACustomManager(t *testing.T) {
	t.Parallel()

	h := httpsec.Authorize(scriptedADM{err: fmt.Errorf("policy store: %w", security.ErrUnavailable)}, fakeAttr("x"))(next204())

	rec := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "an outage stays an outage for an anonymous caller")

	broken := httpsec.Authorize(scriptedADM{err: errors.New("policy bug")}, fakeAttr("x"))(next204())

	rec = serve(broken, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code, "only an access denial asks an anonymous caller to authenticate")
}

func TestAuthorizeWithUsesItsExplicitMapper(t *testing.T) {
	t.Parallel()

	custom := &customMapper{}
	h := httpsec.Middleware(security.NewEngine(security.NewManager(), scriptedExtractor{}), httpsec.WithAnonymousFallback(true))(
		httpsec.AuthorizeWith(scriptedADM{err: security.ErrAccessDenied}, custom, fakeAttr("x"))(next204()))

	rec := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.True(t, custom.invoked.Load())
	assert.Equal(t, http.StatusTeapot, rec.Code)
}

func TestAuthorizeRefusesANilDecisionManager(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "httpsec: Authorize: nil AccessDecisionManager", func() { httpsec.Authorize(nil) })
	assert.PanicsWithValue(t, "httpsec: Authorize: nil AccessDecisionManager", func() { httpsec.AuthorizeWith(nil, nil) })
}

// RFC 6750 §3.1: a request that "lacks any authentication information" gets
// no error code, even when its Authorization field names the Bearer scheme
// without a token.
func TestMiddlewareWithoutCredentialsSendsNoErrorCode(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(), scriptedExtractor{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer")

	rec := serve(httpsec.Middleware(engine)(next204()), req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{bearerAPI}, rec.Header().Values("WWW-Authenticate"))
}

// An engine without any extractor is a misconfiguration (500), tolerated
// only under the anonymous fallback.
func TestMiddlewareEngineWithoutExtractor(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager())

	rec := serve(httpsec.Middleware(engine)(next204()), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, []string{bearerAPI}, rec.Header().Values("WWW-Authenticate"))

	rec = serve(httpsec.Middleware(engine, httpsec.WithAnonymousFallback(true))(next204()), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}
