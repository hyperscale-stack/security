// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// authorizePath is the path the bounds tests mount /authorize at.
const authorizePath = "/oauth2/authorize"

// boundsEnv is a Profile20 server — the implicit flow is enabled — whose
// requests are bounded to MaxRequestBytes, over a counting store, reporting
// to sink. Its ClientStore, lookups, is a mock recording the lookups and
// answering them from the registry clients, which serves the confidential
// client "machine" (secret "machine-secret") declaring the
// authorization_code, implicit, client_credentials and refresh_token grants
// and the scopes read and write.
type boundsEnv struct {
	srv     *oauth2.Server
	store   *writeCountingStore
	clients *staticClientStore
	lookups *oauth2.MockClientStore
	sink    *errorSink
}

// newBoundsEnv builds a boundsEnv bounding requests to maxBytes, behind
// resolver (a static issuer when nil) and ext (none when nil).
func newBoundsEnv(t *testing.T, maxBytes int64, resolver oauth2.IssuerResolver, ext oauth2.Extension) *boundsEnv {
	t.Helper()

	if resolver == nil {
		resolver = oauth2.StaticIssuer("https://auth.example", "api")
	}

	env := &boundsEnv{store: &writeCountingStore{Store: memory.New()}, sink: &errorSink{}}
	env.clients = &staticClientStore{clients: map[string]oauth2.Client{
		"machine": confidentialClient([]string{
			oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeImplicit,
			oauth2.GrantTypeClientCredentials, oauth2.GrantTypeRefreshToken,
		}, []string{"read", "write"}),
	}}
	env.lookups = oauth2.NewMockClientStore(t)
	env.lookups.EXPECT().LoadClient(mock.Anything, mock.Anything).RunAndReturn(env.clients.LoadClient).Maybe()

	gcfg := grant.Config{
		Storage:       env.store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		OnError:       env.sink.hook,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20,
		Storage:        env.store,
		ClientStore:    env.lookups,
		IssuerResolver: resolver,
		Grants: []oauth2.Grant{
			grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg), grant.NewClientCredentials(gcfg),
		},
		ClientAuth:      []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
		OnError:         env.sink.hook,
		MaxRequestBytes: maxBytes,
		Extension:       ext,
	})
	require.NoError(t, err)

	env.srv = srv

	return env
}

// authorizeHandler is the server's /authorize handler, the implicit flow
// enabled, deciding through consent.
func (env *boundsEnv) authorizeHandler(consent oauth2.ConsentFunc) http.Handler {
	return env.srv.AuthorizeHandler(oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}, consent)
}

// boundsQuery is a valid authorization request of "machine" (no PKCE: a
// confidential client under Profile20).
func boundsQuery() url.Values {
	return url.Values{
		"response_type": {"code"},
		"client_id":     {"machine"},
		"redirect_uri":  {redirectURI},
		"scope":         {"read"},
		"state":         {"bounds-state"},
	}
}

// padTo returns form, encoded, padded with an unrecognized parameter to
// exactly size bytes.
func padTo(t *testing.T, form url.Values, size int) string {
	t.Helper()

	body := form.Encode() + "&pad="
	require.Less(t, len(body), size, "the form leaves room for the padding")

	return body + strings.Repeat("x", size-len(body))
}

// boundsPost builds a POST of body to path — with the Basic credentials of
// "machine" unless path is /authorize.
func boundsPost(path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if path != authorizePath {
		req.SetBasicAuth("machine", "machine-secret")
	}

	return req
}

// boundedEndpoint is an endpoint of boundsEnv with a valid form and the
// check of its normal answer.
type boundedEndpoint struct {
	name    string
	path    string
	form    url.Values
	handler func(env *boundsEnv) http.Handler
	ok      func(t *testing.T, rec *httptest.ResponseRecorder)
}

// boundedEndpoints lists /authorize (POST), /token, /revoke and
// /introspect.
func boundedEndpoints() []boundedEndpoint {
	return []boundedEndpoint{
		{
			name:    "authorize",
			path:    authorizePath,
			form:    boundsQuery(),
			handler: func(env *boundsEnv) http.Handler { return env.authorizeHandler(approve) },
			ok: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, rec.Code, rec.Body.String())
				assert.NotEmpty(t, mustLocation(t, rec).Query().Get("code"))
			},
		},
		{
			name:    "token",
			path:    "/oauth2/token",
			form:    url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}},
			handler: func(env *boundsEnv) http.Handler { return env.srv.TokenHandler() },
			ok: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				assert.NotEmpty(t, jsonBody(t, rec)["access_token"])
			},
		},
		{
			name:    "revoke",
			path:    "/oauth2/revoke",
			form:    url.Values{"token": {"ghost"}},
			handler: func(env *boundsEnv) http.Handler { return env.srv.RevokeHandler() },
			ok: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			},
		},
		{
			name:    "introspect",
			path:    "/oauth2/introspect",
			form:    url.Values{"token": {"ghost"}},
			handler: func(env *boundsEnv) http.Handler { return env.srv.IntrospectHandler() },
			ok: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				assert.JSONEq(t, `{"active":false}`, rec.Body.String())
			},
		},
	}
}

// requireTooLarge asserts the refusal of an oversized request at the
// endpoint behind path — a bare 400 at /authorize, an invalid_request
// envelope elsewhere — reported to the hook, before any client was looked
// up or anything written.
func requireTooLarge(t *testing.T, env *boundsEnv, path string, rec *httptest.ResponseRecorder) {
	t.Helper()

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Empty(t, rec.Header().Get("Location"), "never redirected")

	if path == authorizePath {
		assert.Equal(t, "oauth2: authorization request too large\n", rec.Body.String())
	} else {
		assert.JSONEq(t, `{"error":"invalid_request","error_description":"request too large"}`, rec.Body.String())
	}

	env.lookups.AssertNotCalled(t, "LoadClient", mock.Anything, mock.Anything)
	assert.Zero(t, env.store.writes.Load(), "nothing written")

	var oe *oauth2.Error

	reported := env.sink.collected()
	require.Len(t, reported, 1)
	require.ErrorAs(t, reported[0], &oe)
	assert.Equal(t, oauth2.CodeInvalidRequest, oe.Code)
	assert.Equal(t, "request too large", oe.Description)
}

// TestRequestBodyIsBounded pins the request-size bound of every endpoint:
// a body of exactly MaxRequestBytes is served, one byte more is refused
// before anything is parsed — known in advance from Content-Length, or found
// while reading a body of unknown length.
func TestRequestBodyIsBounded(t *testing.T) {
	t.Parallel()

	const limit = 1024

	for _, ep := range boundedEndpoints() {
		t.Run(ep.name+"/at the bound", func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, limit, nil, nil)
			rec := serve(ep.handler(env), boundsPost(ep.path, strings.NewReader(padTo(t, ep.form, limit))))
			ep.ok(t, rec)
		})

		t.Run(ep.name+"/declared over the bound", func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, limit, nil, nil)
			body := &readSpy{Reader: strings.NewReader(padTo(t, ep.form, limit+1))}
			req := boundsPost(ep.path, body)
			req.ContentLength = limit + 1

			requireTooLarge(t, env, ep.path, serve(ep.handler(env), req))
			assert.False(t, body.read.Load(), "refused before the body is read")
		})

		t.Run(ep.name+"/chunked over the bound", func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, limit, nil, nil)
			req := boundsPost(ep.path, io.MultiReader(strings.NewReader(padTo(t, ep.form, limit+1))))
			require.Equal(t, int64(-1), req.ContentLength, "a body of unknown length")

			requireTooLarge(t, env, ep.path, serve(ep.handler(env), req))

			var tooLarge *http.MaxBytesError

			assert.True(t, errors.As(env.sink.collected()[0], &tooLarge), "the cause is the body limit")
		})

		t.Run(ep.name+"/query over the bound", func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, limit, nil, nil)
			req := boundsPost(ep.path+"?pad="+strings.Repeat("x", limit), strings.NewReader(ep.form.Encode()))

			requireTooLarge(t, env, ep.path, serve(ep.handler(env), req))
		})
	}
}

// readSpy records whether its body was read.
type readSpy struct {
	io.Reader

	read atomic.Bool
}

func (r *readSpy) Read(p []byte) (int, error) {
	r.read.Store(true)

	return r.Reader.Read(p) //nolint:wrapcheck // test double
}

// TestAuthorizeQueryIsBounded pins the bound on the query of a GET
// authorization request: exactly MaxRequestBytes is served, one byte more
// is a bare 400.
func TestAuthorizeQueryIsBounded(t *testing.T) {
	t.Parallel()

	const limit = 1024

	env := newBoundsEnv(t, limit, nil, nil)
	h := env.authorizeHandler(approve)

	rec := serve(h, httptest.NewRequest(http.MethodGet, authorizePath+"?"+padTo(t, boundsQuery(), limit), nil))
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	assert.NotEmpty(t, mustLocation(t, rec).Query().Get("code"))

	env = newBoundsEnv(t, limit, nil, nil)
	h = env.authorizeHandler(approve)

	rec = serve(h, httptest.NewRequest(http.MethodGet, authorizePath+"?"+padTo(t, boundsQuery(), limit+1), nil))
	requireTooLarge(t, env, authorizePath, rec)
}

// TestDefaultMaxRequestBytes pins the 64 KiB default a zero or negative
// MaxRequestBytes selects — and refuses the 9 MB body the net/http form
// limit (10 MB) let through.
func TestDefaultMaxRequestBytes(t *testing.T) {
	t.Parallel()

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}

	for _, limit := range []int64{0, -1} {
		env := newBoundsEnv(t, limit, nil, nil)

		rec := serve(env.srv.TokenHandler(), boundsPost("/oauth2/token", strings.NewReader(padTo(t, form, oauth2.DefaultMaxRequestBytes))))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		for _, size := range []int{oauth2.DefaultMaxRequestBytes + 1, 9 << 20} {
			env = newBoundsEnv(t, limit, nil, nil)
			rec = serve(env.srv.TokenHandler(), boundsPost("/oauth2/token", strings.NewReader(padTo(t, form, size))))
			requireTooLarge(t, env, "/oauth2/token", rec)
		}
	}

	assert.Equal(t, 64<<10, oauth2.DefaultMaxRequestBytes)
}

// savedCodes is a store recording the codes it saves.
type savedCodes struct {
	*writeCountingStore

	codes chan oauth2.AuthorizationCode
}

func (s *savedCodes) SaveAuthorizationCode(ctx context.Context, code *oauth2.AuthorizationCode) error {
	s.codes <- *code

	return s.writeCountingStore.SaveAuthorizationCode(ctx, code)
}

// TestAuthorizeBoundsTheNonce pins the nonce bound of every authorization
// request — code or implicit, with or without an extension: at most
// MaxNonceLength bytes of valid UTF-8 without NUL, the rule oidc/provider
// applies to OpenID requests, so that no store is ever handed more. A valid
// nonce is recorded as sent; an invalid one is refused with a redirected
// invalid_request before the extension and the ConsentFunc run, nothing
// stored.
func TestAuthorizeBoundsTheNonce(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, nonce string
		ok          bool
	}{
		{"512 bytes", strings.Repeat("n", oauth2.MaxNonceLength), true},
		{"control characters", "a\tb\x01c\x7f", true},
		{"non-ASCII", "nonce-é-🔑", true},
		{"513 bytes", strings.Repeat("n", oauth2.MaxNonceLength+1), false},
		{"NUL", "a\x00b", false},
		{"invalid UTF-8", "a\xffb", false},
	}

	for _, flow := range []string{"code", "token"} {
		for _, tc := range cases {
			t.Run(flow+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				ext := &fakeExtension{}
				env := newBoundsEnv(t, 0, nil, ext)

				var seen *oauth2.AuthorizeRequest

				consent := func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
					seen = ar

					return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
				}

				q := boundsQuery()
				q.Set("response_type", flow)
				q.Set("nonce", tc.nonce)

				rec := serve(env.authorizeHandler(consent), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
				params := redirectParams(t, rec, flow == "token")

				if tc.ok {
					require.NotNil(t, seen, "the ConsentFunc ran")
					assert.Equal(t, tc.nonce, seen.Nonce, "recorded as sent")
					assert.Empty(t, params.Get("error"))

					return
				}

				assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))
				assert.Equal(t, "the nonce is too long or not valid UTF-8", params.Get("error_description"))
				assert.Equal(t, "bounds-state", params.Get("state"))
				assert.Equal(t, "https://auth.example", params.Get("iss"))
				assert.Nil(t, seen, "the ConsentFunc never ran")

				validated, _, _ := ext.calls()
				assert.Zero(t, validated, "the extension never ran")
				assert.Zero(t, env.store.writes.Load(), "nothing stored")
			})
		}
	}
}

// TestAuthorizeStoresTheNonceAsSent pins that a code records the nonce
// byte-exact.
func TestAuthorizeStoresTheNonceAsSent(t *testing.T) {
	t.Parallel()

	store := &savedCodes{writeCountingStore: &writeCountingStore{Store: memory.New()}, codes: make(chan oauth2.AuthorizationCode, 1)}
	srv := newAuthorizeServerWith(t, oauth2.Profile20BCP, store)

	q := authorizeQuery()
	q.Set("nonce", "nonce-é-🔑\x7f")

	rec := runAuthorize(srv, q, approve)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

	saved := <-store.codes
	assert.Equal(t, "nonce-é-🔑\x7f", saved.Nonce)
}

// TestAuthorizeBoundsTheState pins the state rule (RFC 6749 Appendix A.5,
// §10.14): at most MaxStateLength bytes of VSCHAR (%x20-7E), echoed exactly.
// Anything else is refused with a redirected invalid_request that does not
// carry the state — echoing it would defeat the bound.
func TestAuthorizeBoundsTheState(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, state string
		ok          bool
	}{
		{"4096 bytes", strings.Repeat("S", oauth2.MaxStateLength), true},
		{"space and tilde", "a b~c", true},
		{"every VSCHAR boundary", " !~", true},
		{"4097 bytes", strings.Repeat("S", oauth2.MaxStateLength+1), false},
		{"a control character", "a\x1fb", false},
		{"DEL", "a\x7fb", false},
		{"non-ASCII", "état", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, 0, nil, nil)
			consentCalled := false
			consent := func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
				consentCalled = true

				return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
			}

			q := boundsQuery()
			q.Set("state", tc.state)

			rec := serve(env.authorizeHandler(consent), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
			params := redirectParams(t, rec, false)

			if tc.ok {
				assert.Equal(t, tc.state, params.Get("state"), "echoed exactly")
				assert.NotEmpty(t, params.Get("code"))

				return
			}

			assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))
			assert.Equal(t, "the state is too long or malformed", params.Get("error_description"))
			assert.NotContains(t, params, "state", "an invalid state is not echoed")
			assert.Equal(t, "https://auth.example", params.Get("iss"))
			assert.False(t, consentCalled)
			assert.Zero(t, env.store.writes.Load())
		})
	}
}

// TestAuthorizeIgnoresPKCEOfImplicitRequests: PKCE belongs to the code flow
// (RFC 7636): the PKCE parameters of an implicit request are not recorded,
// whatever they hold.
func TestAuthorizeIgnoresPKCEOfImplicitRequests(t *testing.T) {
	t.Parallel()

	env := newBoundsEnv(t, 0, nil, nil)

	var seen *oauth2.AuthorizeRequest

	consent := func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		seen = ar

		return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
	}

	q := boundsQuery()
	q.Set("response_type", "token")
	q.Set("code_challenge", strings.Repeat("c", 2000))
	q.Set("code_challenge_method", strings.Repeat("m", 2000))

	rec := serve(env.authorizeHandler(consent), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
	assert.NotEmpty(t, redirectParams(t, rec, true).Get("access_token"))
	require.NotNil(t, seen)
	assert.Empty(t, seen.CodeChallenge)
	assert.Empty(t, seen.CodeChallengeMethod)
}

// TestAuthorizeRecordsNoMethodWithoutChallenge: a code_challenge_method
// means something only with a code_challenge (RFC 7636 §4.3) — under
// Profile20 a confidential client may omit PKCE, and its code then records
// no method, whatever the request held.
func TestAuthorizeRecordsNoMethodWithoutChallenge(t *testing.T) {
	t.Parallel()

	store := &savedCodes{writeCountingStore: &writeCountingStore{Store: memory.New()}, codes: make(chan oauth2.AuthorizationCode, 1)}
	srv := newAuthorizeServerWith(t, oauth2.Profile20, store)

	q := authorizeQuery()
	q.Del("code_challenge")
	q.Set("code_challenge_method", strings.Repeat("m", 2000))

	rec := runAuthorize(srv, q, approve)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

	saved := <-store.codes
	assert.Empty(t, saved.CodeChallenge)
	assert.Empty(t, saved.CodeChallengeMethod)
}

// TestOverlongClientIDIsUnknown pins the client-identifier bound (RFC 6749
// §2.2: the server documents the size of the identifiers it issues): a
// client_id over MaxClientIDLength bytes is an unknown client, refused
// without a store lookup — at /authorize whether or not the issuer resolved,
// and by every client-authentication method.
func TestOverlongClientIDIsUnknown(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("c", oauth2.MaxClientIDLength+1)

	for name, resolver := range map[string]oauth2.IssuerResolver{"resolved issuer": nil, "failing resolver": failingIssuer{}} {
		t.Run("authorize/"+name, func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, 0, resolver, nil)
			q := boundsQuery()
			q.Set("client_id", long)

			rec := serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, "oauth2: unknown or invalid client\n", rec.Body.String())
			env.lookups.AssertNotCalled(t, "LoadClient", mock.Anything, mock.Anything)
		})
	}

	t.Run("authorize/at the bound", func(t *testing.T) {
		t.Parallel()

		env := newBoundsEnv(t, 0, nil, nil)
		q := boundsQuery()
		q.Set("client_id", long[1:])

		rec := serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		env.lookups.AssertNumberOfCalls(t, "LoadClient", 1)
	})

	methods := map[string]func() *http.Request{
		"client_secret_basic": func() *http.Request {
			req := boundsPost("/oauth2/introspect", strings.NewReader("token=ghost"))
			req.SetBasicAuth(long, "secret")

			return req
		},
		"client_secret_post": func() *http.Request {
			return boundsPost(authorizePath, strings.NewReader(url.Values{
				"token": {"ghost"}, "client_id": {long}, "client_secret": {"secret"},
			}.Encode()))
		},
		"none": func() *http.Request {
			return boundsPost(authorizePath, strings.NewReader(url.Values{"token": {"ghost"}, "client_id": {long}}.Encode()))
		},
	}

	for name, req := range methods {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, 0, nil, nil)

			rec := serve(env.srv.IntrospectHandler(), req())
			assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
			env.lookups.AssertNotCalled(t, "LoadClient", mock.Anything, mock.Anything)
		})
	}
}

// TestFailingResolverChecksNoIssuerBinding pins what IssuerBoundClient
// documents when the IssuerResolver fails: the binding cannot be checked, so
// a bound client is not hidden — the request fails with a redirected
// server_error, without iss — while an over-long client_id stays unknown.
func TestFailingResolverChecksNoIssuerBinding(t *testing.T) {
	t.Parallel()

	env := newBoundsEnv(t, 0, failingIssuer{}, nil)
	bound := confidentialClient([]string{oauth2.GrantTypeAuthorizationCode}, []string{"read"})
	bound.IssuerValues = []string{"https://auth.example"}
	env.clients.clients["machine"] = bound

	rec := serve(env.authorizeHandler(approve), httptest.NewRequest(http.MethodGet, authorizePath+"?"+boundsQuery().Encode(), nil))
	params := redirectParams(t, rec, false)
	assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
	assert.NotContains(t, params, "iss", "no issuer is known")
	env.lookups.AssertNumberOfCalls(t, "LoadClient", 1)
}

// TestMalformedFormIsRefused: a body that is no valid form encoding is
// refused as malformed — not as too large — with a bare 400 at /authorize
// and invalid_request elsewhere.
func TestMalformedFormIsRefused(t *testing.T) {
	t.Parallel()

	for _, ep := range boundedEndpoints() {
		t.Run(ep.name, func(t *testing.T) {
			t.Parallel()

			env := newBoundsEnv(t, 0, nil, nil)
			rec := serve(ep.handler(env), boundsPost(ep.path, strings.NewReader(ep.form.Encode()+"&bad=%zz")))

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

			if ep.path == authorizePath {
				assert.Equal(t, "oauth2: malformed authorization request\n", rec.Body.String())
			} else {
				assert.JSONEq(t, `{"error":"invalid_request","error_description":"the request is malformed"}`, rec.Body.String())
			}

			env.lookups.AssertNotCalled(t, "LoadClient", mock.Anything, mock.Anything)
			assert.Equal(t, []string{oauth2.CodeInvalidRequest}, env.sink.codes())
		})
	}
}
