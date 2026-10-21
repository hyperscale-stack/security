// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// issuerCase is an issuer identifier and whether the server accepts it,
// without and with ServerConfig.AllowInsecureLoopbackIssuer.
type issuerCase struct {
	issuer               string
	strict, withLoopback bool
}

// issuerCases pins RFC 8414 §2 ("a URL that uses the "https" scheme and has
// no query or fragment components") and RFC 9207 §2: an https URL with a
// host, no user info, query or fragment, a valid port if any, in canonical
// form — issuers are compared exactly —, and http only on a loopback host,
// on explicit opt-in.
func issuerCases() []issuerCase {
	return []issuerCase{
		{"https://as.example", true, true},
		{"https://as.example/", true, true},
		{"https://as.example:8443/tenant/a", true, true},
		{"https://as.example/tenant-a&b=c/", true, true},
		{"https://[2001:db8::1]/realm", true, true},
		{"http://localhost:8080", false, true},
		{"http://localhost", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"http://127.9.9.9", false, true},
		{"http://[::1]", false, true},
		{"http://[::1]:8080/realm", false, true},
		{"", false, false},
		{"http://as.example", false, false},
		{"http://10.0.0.1", false, false},
		{"http://localhost.example", false, false},
		{"http://127.0.0.1.nip.io", false, false},
		{"https://as.example?tenant=a", false, false},
		{"https://as.example/?", false, false},
		{"https://as.example#frag", false, false},
		{"https://as.example/#", false, false},
		{"https://as.example/?q=1#f", false, false},
		{"https://user@as.example", false, false},
		{"https:///no-host", false, false},
		{"https:as.example", false, false},
		{"HTTPS://as.example", false, false},
		{"https://as.example/a b", false, false},
		{"https://as.example/%zz", false, false},
		{"as.example", false, false},
		{"ftp://as.example", false, false},
		{"https://as.example:", false, false},
		{"https://as.example:0", false, false},
		{"https://as.example:99999", false, false},
		{"http://localhost:", false, false},
	}
}

// issuerServerConfig is a minimal server configuration behind resolver.
func issuerServerConfig(resolver oauth2.IssuerResolver, loopback bool) oauth2.ServerConfig {
	return oauth2.ServerConfig{
		Storage: memory.New(), ClientStore: &staticClientStore{}, IssuerResolver: resolver,
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic()}, AllowInsecureLoopbackIssuer: loopback,
	}
}

// TestNewServerValidatesTheStaticIssuer: NewServer refuses a StaticIssuer
// the server could not publish, wrapping ErrInvalidIssuer — with a reason
// that never echoes the value.
func TestNewServerValidatesTheStaticIssuer(t *testing.T) {
	t.Parallel()

	for _, tc := range issuerCases() {
		for _, loopback := range []bool{false, true} {
			_, err := oauth2.NewServer(issuerServerConfig(oauth2.StaticIssuer(tc.issuer, "api"), loopback))

			want := tc.strict
			if loopback {
				want = tc.withLoopback
			}

			if want {
				assert.NoError(t, err, "%q (loopback opt-in %v)", tc.issuer, loopback)

				continue
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidIssuer, "%q (loopback opt-in %v)", tc.issuer, loopback)

			if tc.issuer != "" {
				assert.NotContains(t, err.Error(), tc.issuer, "the reason never echoes the issuer")
			}
		}
	}
}

// resolverReturning is a mock IssuerResolver answering every request with
// (issuer, audience, err).
func resolverReturning(t *testing.T, issuer, audience string, err error) *oauth2.MockIssuerResolver {
	t.Helper()

	r := oauth2.NewMockIssuerResolver(t)
	r.EXPECT().Resolve(mock.Anything, mock.Anything).Return(issuer, audience, err).Maybe()

	return r
}

// outageEnv is a Profile20 server — the implicit flow can be enabled —
// behind resolver, whose ClientStore is a mock expecting no call: a
// request answered before any client is loaded leaves it untouched.
type outageEnv struct {
	srv   *oauth2.Server
	store *writeCountingStore
	sink  *errorSink
}

func newOutageEnv(t *testing.T, resolver oauth2.IssuerResolver, loopback bool) *outageEnv {
	t.Helper()

	env := &outageEnv{store: &writeCountingStore{Store: memory.New()}, sink: &errorSink{}}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:                     oauth2.Profile20,
		Storage:                     env.store,
		ClientStore:                 oauth2.NewMockClientStore(t),
		IssuerResolver:              resolver,
		ClientAuth:                  []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		OnError:                     env.sink.hook,
		AllowInsecureLoopbackIssuer: loopback,
	})
	require.NoError(t, err)

	env.srv = srv

	return env
}

// authorizeOutage runs q through the /authorize handler of env — the
// implicit flow enabled, TrustedRedirect recording its calls — and fails
// the test if the ConsentFunc or the hook runs.
func (env *outageEnv) authorizeOutage(t *testing.T, q url.Values, trusted bool) *httptest.ResponseRecorder {
	t.Helper()

	cfg := oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}
	if !trusted {
		cfg.TrustedRedirect = func(context.Context, oauth2.Client, string) bool {
			t.Error("TrustedRedirect is never asked")

			return false
		}
	}

	return runAuthorizeCfg(env.srv, cfg, q, func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		t.Error("the ConsentFunc never runs")

		return nil, nil
	})
}

// assertBare500 checks the answer of an /authorize request whose issuer is
// unknown: a bare 500 — no redirect, the state not echoed, nothing saved —
// reported once as a server_error whose cause is cause.
func assertBare500(t *testing.T, env *outageEnv, rec *httptest.ResponseRecorder, cause error) {
	t.Helper()

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "oauth2: server error\n", rec.Body.String())
	assert.Empty(t, rec.Header().Get("Location"), "never redirected")
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"), "the protective headers are set")
	assert.Zero(t, env.store.writes.Load())
	assert.Equal(t, []string{oauth2.CodeServerError}, env.sink.codes())
	assert.True(t, env.sink.matches(cause), "the cause reaches the hook")
}

// TestAuthorizeIssuerResolverFailureIsABare500 pins RFC 9207 §2 — every
// authorization response, error responses included, names the issuer — and
// the issuer binding (IssuerBoundClient): when the IssuerResolver fails, no
// answer could name an issuer nor any client be checked against it, so the
// request is an outage — a bare 500, never redirected, whatever the flow,
// the client's trust or the values the resolver returned with its error.
func TestAuthorizeIssuerResolverFailureIsABare500(t *testing.T) {
	t.Parallel()

	errTenantDown := errors.New("tenant directory down")

	resolvers := map[string]func(t *testing.T) oauth2.IssuerResolver{
		"error only": func(t *testing.T) oauth2.IssuerResolver {
			return resolverReturning(t, "", "", errTenantDown)
		},
		"issuer and error": func(t *testing.T) oauth2.IssuerResolver {
			return resolverReturning(t, testIssuer, "api", errTenantDown)
		},
	}

	for name, resolver := range resolvers {
		for flow, q := range map[string]url.Values{"code": boundsQuery(), "implicit": implicitQuery()} {
			for _, trusted := range []bool{true, false} {
				t.Run(name+"/"+flow, func(t *testing.T) {
					t.Parallel()

					env := newOutageEnv(t, resolver(t), false)

					rec := env.authorizeOutage(t, q, trusted)
					assertBare500(t, env, rec, errTenantDown)
					assert.NotContains(t, rec.Body.String(), q.Get("state"))
				})
			}
		}
	}
}

// invalidIssuers are values an IssuerResolver may return that the server
// cannot use (RFC 8414 §2, RFC 9207 §2).
var invalidIssuers = []string{"", "http://as.example", "https://as.example/?q=1#f", "https://u@as.example", "HTTPS://as.example"}

// TestInvalidResolvedIssuerIsAnOutage: an issuer the resolver returns is
// validated on every request, like a StaticIssuer at construction — an
// invalid one is answered as a resolver failure at every endpoint, its
// cause ErrInvalidIssuer: a bare 500 at /authorize, server_error at /token,
// /introspect and the metadata, 503 at /revoke (RFC 7009 §2.2.1).
func TestInvalidResolvedIssuerIsAnOutage(t *testing.T) {
	t.Parallel()

	for _, issuer := range invalidIssuers {
		t.Run(issuer, func(t *testing.T) {
			t.Parallel()

			env := newOutageEnv(t, resolverReturning(t, issuer, "api", nil), true)
			assertBare500(t, env, env.authorizeOutage(t, boundsQuery(), false), oauth2.ErrInvalidIssuer)

			meta := serve(env.srv.MetadataHandler(), httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
			assert.Equal(t, http.StatusInternalServerError, meta.Code)
			assert.Equal(t, oauth2.CodeServerError, jsonBody(t, meta)["error"])
			assert.NotContains(t, meta.Body.String(), `"issuer"`)

			endpoints := map[string]struct {
				h      http.Handler
				status int
			}{
				"/oauth2/token":      {env.srv.TokenHandler(), http.StatusInternalServerError},
				"/oauth2/introspect": {env.srv.IntrospectHandler(), http.StatusInternalServerError},
				"/oauth2/revoke":     {env.srv.RevokeHandler(), http.StatusServiceUnavailable},
			}

			for path, ep := range endpoints {
				form := url.Values{"grant_type": {"client_credentials"}, "token": {"ghost"}}
				rec := serve(ep.h, boundsPost(path, strings.NewReader(form.Encode())))
				assert.Equal(t, ep.status, rec.Code, "%s: %s", path, rec.Body.String())
			}

			for _, err := range env.sink.collected() {
				assert.ErrorIs(t, err, oauth2.ErrInvalidIssuer)
			}

			assert.Len(t, env.sink.collected(), 5, "every refusal reaches the hook")
		})
	}
}

// switchingResolver resolves to whatever issuer it holds.
type switchingResolver struct{ issuer atomic.Value }

func (s *switchingResolver) Resolve(context.Context, *http.Request) (string, string, error) {
	return s.issuer.Load().(string), "api", nil //nolint:forcetypeassert // test double, always a string
}

// TestInvalidIssuerAtTokenConsumesNothing: a /token request refused for an
// invalid issuer has no side effect — the code it carried is redeemed once
// the issuer is valid again. A hand-written resolver: the issuer it returns
// changes during the test.
func TestInvalidIssuerAtTokenConsumesNothing(t *testing.T) {
	t.Parallel()

	resolver := &switchingResolver{}
	resolver.issuer.Store(testIssuer)

	env := newBoundsEnv(t, 0, resolver, nil)
	code := mustLocation(t, authorizeTo(env, redirectURI, "code")).Query().Get("code")
	require.NotEmpty(t, code)

	exchange := func() *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}

		return serve(env.srv.TokenHandler(), boundsPost("/oauth2/token", strings.NewReader(form.Encode())))
	}

	resolver.issuer.Store("http://auth.example")
	refused := exchange()
	require.Equal(t, http.StatusInternalServerError, refused.Code, refused.Body.String())
	assert.True(t, env.sink.matches(oauth2.ErrInvalidIssuer))

	resolver.issuer.Store(testIssuer)
	assert.Equal(t, http.StatusOK, exchange().Code, "the code was not consumed")
}

// TestLoopbackIssuerOptIn: with AllowInsecureLoopbackIssuer, an http issuer
// on a loopback host is resolved, named in the authorization response and
// published as the metadata issuer (RFC 9207 §2.3: identical); without it,
// the same issuer is an outage.
func TestLoopbackIssuerOptIn(t *testing.T) {
	t.Parallel()

	const issuer = "http://127.0.0.1:8080"

	env := newBoundsEnv(t, 0, resolverReturning(t, issuer, "api", nil), nil)
	assert.Equal(t, http.StatusInternalServerError, authorizeTo(env, redirectURI, "code").Code, "without the opt-in")

	cfg := env.srv.Config()
	cfg.AllowInsecureLoopbackIssuer = true
	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	rec := runAuthorizeCfg(srv, oauth2.AuthorizeConfig{}, boundsQuery(), approve)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.Equal(t, issuer, mustLocation(t, rec).Query().Get("iss"))
	assert.Equal(t, issuer, metadataIssuer(t, srv))
}

// metadataIssuer returns the issuer the RFC 8414 document of srv publishes.
func metadataIssuer(t *testing.T, srv *oauth2.Server) string {
	t.Helper()

	rec := serve(srv.MetadataHandler(), httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var doc struct {
		Issuer string `json:"issuer"`
	}

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))

	return doc.Issuer
}

// TestAuthorizationResponsesNameTheMetadataIssuer pins RFC 9207 §2.3: the
// iss of every authorization response — a code, a redirected error, an
// implicit token — is identical to the issuer the metadata publishes.
func TestAuthorizationResponsesNameTheMetadataIssuer(t *testing.T) {
	t.Parallel()

	env := newBoundsEnv(t, 0, nil, nil)
	published := metadataIssuer(t, env.srv)
	require.Equal(t, testIssuer, published)

	scope := boundsQuery()
	scope.Set("scope", "admin")

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"code":     serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+boundsQuery().Encode(), nil)),
		"error":    serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+scope.Encode(), nil)),
		"implicit": authorizeTo(env, redirectURI, "token"),
	} {
		params := redirectParams(t, rec, name == "implicit")
		assert.Equal(t, published, params.Get("iss"), name)
	}
}
