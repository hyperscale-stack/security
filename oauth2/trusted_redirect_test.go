// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustHook is a TrustedRedirect answering trusted, counting its calls.
type trustHook struct {
	trusted bool
	calls   atomic.Int32
}

func (h *trustHook) decide(context.Context, oauth2.Client, string) bool {
	h.calls.Add(1)

	return h.trusted
}

// trustEnv is a boundsEnv also serving "implicitonly" (confidential, the
// implicit grant only) and "spa" (public, authorization_code).
func trustEnv(t *testing.T, resolver oauth2.IssuerResolver, ext oauth2.Extension) *boundsEnv {
	t.Helper()

	env := newBoundsEnv(t, 0, resolver, ext)

	implicitOnly := confidentialClient([]string{oauth2.GrantTypeImplicit}, []string{"read"})
	implicitOnly.IDValue = "implicitonly"
	env.clients.clients["implicitonly"] = implicitOnly
	env.clients.clients["spa"] = &oauth2.DefaultClient{
		IDValue: "spa", TypeValue: oauth2.ClientPublic, RedirectURIValues: []string{redirectURI},
		GrantTypeValues: []string{oauth2.GrantTypeAuthorizationCode}, ScopeValues: []string{"read"},
	}

	return env
}

// authorizeTrusting runs GET /authorize?q on env, the implicit flow
// enabled, trust deciding the redirects of errors before authentication.
func authorizeTrusting(env *boundsEnv, hook func(context.Context, oauth2.Client, string) bool, consent oauth2.ConsentFunc, q url.Values) *httptest.ResponseRecorder {
	cfg := oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens(), TrustedRedirect: hook}

	return serve(env.srv.AuthorizeHandler(cfg, consent), httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil))
}

// preAuthenticationFailure is a request failing before the resource owner
// authenticated, with the code and the status of its bare page.
type preAuthenticationFailure struct {
	name     string
	resolver oauth2.IssuerResolver
	ext      oauth2.Extension
	consent  oauth2.ConsentFunc
	query    func() url.Values
	code     string
	status   int
}

func preAuthenticationFailures() []preAuthenticationFailure {
	with := func(pairs ...string) func() url.Values {
		return func() url.Values {
			q := boundsQuery()
			for i := 0; i < len(pairs); i += 2 {
				q.Set(pairs[i], pairs[i+1])
			}

			return q
		}
	}

	return []preAuthenticationFailure{
		{name: "failing issuer resolver", resolver: failingIssuer{}, query: boundsQuery, code: oauth2.CodeServerError, status: http.StatusInternalServerError},
		{name: "invalid state", query: with("state", "a\x01b"), code: oauth2.CodeInvalidRequest, status: http.StatusBadRequest},
		{name: "unsupported response type", query: with("response_type", "magic"), code: oauth2.CodeUnsupportedResponseType, status: http.StatusBadRequest},
		{name: "repeated parameter", query: func() url.Values {
			q := boundsQuery()
			q["scope"] = []string{"read", "write"}

			return q
		}, code: oauth2.CodeInvalidRequest, status: http.StatusBadRequest},
		{name: "grant type not declared", query: with("client_id", "implicitonly"), code: oauth2.CodeUnauthorizedClient, status: http.StatusBadRequest},
		{name: "scope outside the registration", query: with("scope", "admin"), code: oauth2.CodeInvalidScope, status: http.StatusBadRequest},
		{name: "public client without PKCE", query: with("client_id", "spa"), code: oauth2.CodeInvalidRequest, status: http.StatusBadRequest},
		{name: "nonce too long", query: with("nonce", strings.Repeat("n", oauth2.MaxNonceLength+1)), code: oauth2.CodeInvalidRequest, status: http.StatusBadRequest},
		{name: "extension refusal", ext: &fakeExtension{validate: func(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error) {
			return nil, oauth2.ErrInvalidRequest.WithDescription("bad prompt")
		}}, query: boundsQuery, code: oauth2.CodeInvalidRequest, status: http.StatusBadRequest},
		{name: "extension modifying the request", ext: &fakeExtension{validate: func(_ context.Context, _ *http.Request, ar *oauth2.AuthorizeRequest) (any, error) {
			ar.Scope = "write"

			return nil, nil
		}}, query: boundsQuery, code: oauth2.CodeServerError, status: http.StatusInternalServerError},
		{name: "ConsentFunc failure", consent: consentWith(nil, errors.New("session store down")), query: boundsQuery, code: oauth2.CodeServerError, status: http.StatusInternalServerError},
	}
}

// TestUntrustedClientErrorsAreNotRedirected pins decision 12 and RFC 9700
// §4.11.2 ("The authorization server MUST always authenticate the user
// first … before redirecting the user"): for a client TrustedRedirect does
// not trust, an error detected before the resource owner authenticated is a
// bare page — the status of its code — never a redirect; without the hook,
// or for a trusted client, it is redirected as RFC 6749 §4.1.2.1 says.
func TestUntrustedClientErrorsAreNotRedirected(t *testing.T) {
	t.Parallel()

	for _, tc := range preAuthenticationFailures() {
		t.Run(tc.name+"/untrusted", func(t *testing.T) {
			t.Parallel()

			env := trustEnv(t, tc.resolver, tc.ext)
			hook := &trustHook{}

			consented := false
			consent := func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
				consented = true

				if tc.consent != nil {
					return tc.consent(w, r, ar)
				}

				return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
			}

			rec := authorizeTrusting(env, hook.decide, consent, tc.query())

			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			assert.Empty(t, rec.Header().Get("Location"), "never redirected")
			assert.Equal(t, "oauth2: authorization request refused: "+tc.code+"\n", rec.Body.String())
			requireProtectiveHeaders(t, rec)
			assert.Equal(t, int32(1), hook.calls.Load(), "the hook is asked once")
			assert.Equal(t, []string{tc.code}, env.sink.codes(), "the envelope reaches the hook")
			assert.Equal(t, tc.consent != nil, consented, "the ConsentFunc runs only for its own failure")
			assert.Zero(t, env.store.writes.Load(), "nothing stored")
		})

		for name, hook := range map[string]func(context.Context, oauth2.Client, string) bool{
			"no hook": nil, "trusted": (&trustHook{trusted: true}).decide,
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				t.Parallel()

				env := trustEnv(t, tc.resolver, tc.ext)
				consent := tc.consent
				if consent == nil {
					consent = approve
				}

				rec := authorizeTrusting(env, hook, consent, tc.query())
				require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
				assert.Equal(t, tc.code, redirectParams(t, rec, false).Get("error"))
			})
		}
	}
}

// TestUntrustedClientInteractionRefusalsAreNotRedirected: a ConsentFunc
// refusing because the request cannot complete without showing a user
// interface — the OpenID Connect Core §3.1.2.6 codes prompt=none answers
// with — has authenticated nobody, so an untrusted client gets the bare page
// (RFC 9700 §4.11.2, attack 3); a trusted one the redirect.
func TestUntrustedClientInteractionRefusalsAreNotRedirected(t *testing.T) {
	t.Parallel()

	for _, refusal := range []*oauth2.Error{
		oauth2.ErrLoginRequired, oauth2.ErrInteractionRequired, oauth2.ErrAccountSelectionRequired, oauth2.ErrConsentRequired,
	} {
		t.Run(refusal.Code, func(t *testing.T) {
			t.Parallel()

			consent := consentWith(&oauth2.Consent{Refusal: refusal}, nil)

			env := trustEnv(t, nil, nil)
			rec := authorizeTrusting(env, (&trustHook{}).decide, consent, boundsQuery())
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Empty(t, rec.Header().Get("Location"))
			assert.Equal(t, "oauth2: authorization request refused: "+refusal.Code+"\n", rec.Body.String())

			env = trustEnv(t, nil, nil)
			rec = authorizeTrusting(env, (&trustHook{trusted: true}).decide, consent, boundsQuery())
			require.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, refusal.Code, redirectParams(t, rec, false).Get("error"))
		})
	}
}

// TestUntrustedClientIsRedirectedOnceAuthenticated: once the ConsentFunc
// decided — the resource owner authenticated — every answer is redirected,
// to an untrusted client too: the code, a denial, another refusal, a later
// failure.
func TestUntrustedClientIsRedirectedOnceAuthenticated(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		consent oauth2.ConsentFunc
		want    string // the redirected error, "" for a code
	}{
		{name: "an approval", consent: approve},
		{name: "a denial", consent: consentWith(&oauth2.Consent{}, nil), want: oauth2.CodeAccessDenied},
		{name: "another refusal", consent: consentWith(&oauth2.Consent{Refusal: oauth2.ErrInvalidScope}, nil), want: oauth2.CodeInvalidScope},
		{name: "an approval the server cannot honor", consent: consentWith(&oauth2.Consent{
			Approved: true, Subject: strings.Repeat("s", 256),
		}, nil), want: oauth2.CodeServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := trustEnv(t, nil, nil)
			hook := &trustHook{}
			rec := authorizeTrusting(env, hook.decide, tc.consent, boundsQuery())
			require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

			params := redirectParams(t, rec, false)
			assert.Equal(t, tc.want, params.Get("error"))

			if tc.want == "" {
				assert.NotEmpty(t, params.Get("code"))
			}

			assert.Zero(t, hook.calls.Load(), "the hook is never asked after authentication")
		})
	}
}

// trustContextKey carries a request-scoped value a middleware sets.
type trustContextKey struct{}

// TestTrustedRedirectArguments: the hook gets the request context, the
// client and the redirect URI the request resolved to — a loopback URI with
// the port the request set — and runs only when a request fails before
// authentication.
func TestTrustedRedirectArguments(t *testing.T) {
	t.Parallel()

	env := trustEnv(t, nil, nil)
	env.clients.clients["machine"].(*oauth2.DefaultClient).RedirectURIValues = []string{"http://127.0.0.1/cb"}

	var (
		calls       atomic.Int32
		gotValue    any
		gotClient   string
		gotRedirect string
	)

	hook := func(ctx context.Context, c oauth2.Client, redirectURI string) bool {
		calls.Add(1)

		gotValue, gotClient, gotRedirect = ctx.Value(trustContextKey{}), c.ID(), redirectURI

		return true
	}

	cfg := oauth2.AuthorizeConfig{TrustedRedirect: hook}
	h := env.srv.AuthorizeHandler(cfg, approve)
	run := func(q url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil)

		return serve(h, req.WithContext(context.WithValue(req.Context(), trustContextKey{}, "tenant-a")))
	}

	q := boundsQuery()
	q.Set("redirect_uri", "http://127.0.0.1:51004/cb")

	require.Equal(t, http.StatusFound, run(q).Code)
	assert.Zero(t, calls.Load(), "not asked for a request that succeeds")

	q.Set("scope", "admin")
	require.Equal(t, http.StatusFound, run(q).Code)
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, "tenant-a", gotValue)
	assert.Equal(t, "machine", gotClient)
	assert.Equal(t, "http://127.0.0.1:51004/cb", gotRedirect)
}
