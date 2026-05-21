// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	redirectURI = "https://app.example/cb"
	// RFC 7636 Appendix B sample PKCE pair.
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// newAuthorizeServer builds a server with the authorization_code grant and a
// client registered with a redirect URI and two scopes.
func newAuthorizeServer(t *testing.T, profile oauth2.Profile) *oauth2.Server {
	t.Helper()

	store := memory.New()
	clients := &staticClientStore{clients: map[string]oauth2.Client{
		testClientID: &oauth2.DefaultClient{
			IDValue:           testClientID,
			Secret:            testClientSecret,
			TypeValue:         oauth2.ClientConfidential,
			RedirectURIValues: []string{redirectURI},
			ScopeValues:       []string{"read", "write"},
		},
	}}

	cfg := grant.Config{
		Storage:       store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        profile,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(cfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.NoError(t, err)

	return srv
}

// authorizeQuery is the canonical valid /authorize query (S256 PKCE).
func authorizeQuery() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"read"},
		"state":                 {"xyz-state"},
		"code_challenge":        {pkceChallenge},
		"code_challenge_method": {"S256"},
	}
}

// implicitQuery is a valid /authorize query for the implicit flow.
func implicitQuery() url.Values {
	return url.Values{
		"response_type": {"token"},
		"client_id":     {testClientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"read"},
		"state":         {"impl-state"},
	}
}

// implicitTokens is an OpaqueTokenGenerator for the implicit-flow tests.
func implicitTokens() oauth2.OpaqueTokenGenerator {
	return token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)}
}

// runAuthorizeCfg drives the /authorize handler with an explicit config.
func runAuthorizeCfg(
	srv *oauth2.Server,
	cfg oauth2.AuthorizeConfig,
	q url.Values,
	consent oauth2.ConsentFunc,
) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	srv.AuthorizeHandler(cfg, consent).ServeHTTP(rec, req)

	return rec
}

// runAuthorize drives the /authorize handler with the default config.
func runAuthorize(srv *oauth2.Server, q url.Values, consent oauth2.ConsentFunc) *httptest.ResponseRecorder {
	return runAuthorizeCfg(srv, oauth2.AuthorizeConfig{}, q, consent)
}

// approve is a ConsentFunc that always grants, as alice.
func approve(_ http.ResponseWriter, _ *http.Request, _ *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
	return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
}

func TestAuthorizeHandlerPanicsOnNilConsent(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)
	assert.Panics(t, func() { srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, nil) })
}

func TestAuthorizeCodeHappyPath(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	var seen *oauth2.AuthorizeRequest
	rec := runAuthorize(srv, authorizeQuery(),
		func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			seen = ar

			return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
		})

	require.Equal(t, http.StatusFound, rec.Code)

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://app.example/cb", loc.Scheme+"://"+loc.Host+loc.Path)
	assert.NotEmpty(t, loc.Query().Get("code"))
	assert.Equal(t, "xyz-state", loc.Query().Get("state"))
	assert.Empty(t, loc.Query().Get("error"))

	// The ConsentFunc saw the validated request.
	require.NotNil(t, seen)
	assert.Equal(t, "code", seen.ResponseType)
	assert.Equal(t, redirectURI, seen.RedirectURI)
	assert.Equal(t, "read", seen.Scope)
	assert.Equal(t, pkceChallenge, seen.CodeChallenge)
}

func TestAuthorizeConsentRendersOwnPage(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	rec := runAuthorize(srv, authorizeQuery(),
		func(w http.ResponseWriter, _ *http.Request, _ *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<consent form>"))

			return nil, nil // "I rendered the page myself"
		})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "<consent form>", rec.Body.String())
	assert.Empty(t, rec.Header().Get("Location"))
}

func TestAuthorizeConsentDenied(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	rec := runAuthorize(srv, authorizeQuery(),
		func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			return &oauth2.Consent{Approved: false}, nil
		})

	require.Equal(t, http.StatusFound, rec.Code)

	loc, _ := url.Parse(rec.Header().Get("Location"))
	assert.Equal(t, oauth2.CodeAccessDenied, loc.Query().Get("error"))
	assert.Equal(t, "xyz-state", loc.Query().Get("state"))
}

func TestAuthorizeRejectsBadClientWithoutRedirect(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	t.Run("unknown client", func(t *testing.T) {
		t.Parallel()

		q := authorizeQuery()
		q.Set("client_id", "ghost")

		rec := runAuthorize(srv, q, approve)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Empty(t, rec.Header().Get("Location"), "an open redirect MUST NOT happen")
	})

	t.Run("unregistered redirect_uri", func(t *testing.T) {
		t.Parallel()

		q := authorizeQuery()
		q.Set("redirect_uri", "https://attacker.example/steal")

		rec := runAuthorize(srv, q, approve)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Empty(t, rec.Header().Get("Location"))
	})
}

func TestAuthorizeRedirectsProtocolErrors(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	cases := []struct {
		name      string
		mutate    func(url.Values)
		wantError string
	}{
		{"unsupported response_type", func(q url.Values) { q.Set("response_type", "token") }, oauth2.CodeUnsupportedResponseType},
		{"invalid scope", func(q url.Values) { q.Set("scope", "admin") }, oauth2.CodeInvalidScope},
		{"missing PKCE under BCP", func(q url.Values) {
			q.Del("code_challenge")
			q.Del("code_challenge_method")
		}, oauth2.CodeInvalidRequest},
		{"plain PKCE under BCP", func(q url.Values) { q.Set("code_challenge_method", "plain") }, oauth2.CodeInvalidRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			q := authorizeQuery()
			tc.mutate(q)

			rec := runAuthorize(srv, q, approve)
			require.Equal(t, http.StatusFound, rec.Code)

			loc, _ := url.Parse(rec.Header().Get("Location"))
			assert.Equal(t, "https://app.example/cb", loc.Scheme+"://"+loc.Host+loc.Path)
			assert.Equal(t, tc.wantError, loc.Query().Get("error"))
		})
	}
}

func TestAuthorizeProfile20AllowsNoPKCEAndPlain(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20)

	t.Run("no PKCE", func(t *testing.T) {
		t.Parallel()

		q := authorizeQuery()
		q.Del("code_challenge")
		q.Del("code_challenge_method")

		rec := runAuthorize(srv, q, approve)
		require.Equal(t, http.StatusFound, rec.Code)

		loc, _ := url.Parse(rec.Header().Get("Location"))
		assert.NotEmpty(t, loc.Query().Get("code"))
		assert.Empty(t, loc.Query().Get("error"))
	})

	t.Run("plain PKCE", func(t *testing.T) {
		t.Parallel()

		q := authorizeQuery()
		q.Set("code_challenge", "a-plain-verifier")
		q.Set("code_challenge_method", "plain")

		rec := runAuthorize(srv, q, approve)
		require.Equal(t, http.StatusFound, rec.Code)

		loc, _ := url.Parse(rec.Header().Get("Location"))
		assert.NotEmpty(t, loc.Query().Get("code"))
	})
}

func TestAuthorizeRejectsNonGetPost(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/authorize", nil)
	srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, approve).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAuthorizeConsentNarrowsScope(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	q := authorizeQuery()
	q.Set("scope", "read write")

	// The consent grants only "read" of the requested "read write".
	rec := runAuthorize(srv, q,
		func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			return &oauth2.Consent{Approved: true, Subject: "alice", Scope: "read"}, nil
		})
	require.Equal(t, http.StatusFound, rec.Code)
	assert.NotEmpty(t, mustLocation(t, rec).Query().Get("code"))

	// Broadening beyond the request is refused.
	rec = runAuthorize(srv, authorizeQuery(),
		func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			return &oauth2.Consent{Approved: true, Subject: "alice", Scope: "read write"}, nil
		})
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidScope, mustLocation(t, rec).Query().Get("error"))
}

// TestAuthorizeCodeFlowEndToEnd runs the full flow: /authorize mints a code,
// /token exchanges it (authorization_code + PKCE) for an access token.
func TestAuthorizeCodeFlowEndToEnd(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	rec := runAuthorize(srv, authorizeQuery(), approve)
	require.Equal(t, http.StatusFound, rec.Code)

	code := mustLocation(t, rec).Query().Get("code")
	require.NotEmpty(t, code)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {pkceVerifier},
	}

	tokenRec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(tokenRec, formRequest("/oauth2/token", form, true))

	require.Equal(t, http.StatusOK, tokenRec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(tokenRec.Body.Bytes(), &body))
	assert.NotEmpty(t, body["access_token"])
	assert.Equal(t, "Bearer", body["token_type"])

	// The code is single-use: a replay is refused.
	replay := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(replay, formRequest("/oauth2/token", form, true))
	assert.Equal(t, http.StatusBadRequest, replay.Code)
}

func TestAuthorizeConsentError(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	rec := runAuthorize(srv, authorizeQuery(),
		func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			return nil, assertAnError
		})
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, oauth2.CodeServerError, mustLocation(t, rec).Query().Get("error"))
}

func TestAuthorizeOmittedRedirectURIUsesTheRegisteredOne(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	q := authorizeQuery()
	q.Del("redirect_uri") // the client has exactly one registered URI

	rec := runAuthorize(srv, q, approve)
	require.Equal(t, http.StatusFound, rec.Code)

	loc := mustLocation(t, rec)
	assert.Equal(t, "https://app.example/cb", loc.Scheme+"://"+loc.Host+loc.Path)
	assert.NotEmpty(t, loc.Query().Get("code"))
}

func TestAuthorizeRejectsUnknownPKCEMethod(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	q := authorizeQuery()
	q.Set("code_challenge_method", "S512") // not S256 / plain

	rec := runAuthorize(srv, q, approve)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidRequest, mustLocation(t, rec).Query().Get("error"))
}

// assertAnError is a throwaway error for the consent-failure test.
var assertAnError = errAuthorizeTest("consent backend down")

type errAuthorizeTest string

func (e errAuthorizeTest) Error() string { return string(e) }

// --- implicit flow (legacy, opt-in) -------------------------------------

func TestAuthorizeHandlerPanicsOnImplicitMisconfig(t *testing.T) {
	t.Parallel()

	t.Run("implicit on a non-Profile20 server", func(t *testing.T) {
		t.Parallel()

		bcp := newAuthorizeServer(t, oauth2.Profile20BCP)
		assert.Panics(t, func() {
			bcp.AuthorizeHandler(
				oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}, approve)
		})
	})

	t.Run("implicit without a token generator", func(t *testing.T) {
		t.Parallel()

		p20 := newAuthorizeServer(t, oauth2.Profile20)
		assert.Panics(t, func() {
			p20.AuthorizeHandler(oauth2.AuthorizeConfig{AllowImplicit: true}, approve)
		})
	})
}

func TestAuthorizeImplicitHappyPath(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20)
	cfg := oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}

	rec := runAuthorizeCfg(srv, cfg, implicitQuery(), approve)
	require.Equal(t, http.StatusFound, rec.Code)

	loc := mustLocation(t, rec)
	assert.Empty(t, loc.RawQuery, "the implicit response uses the fragment, not the query")

	frag, err := url.ParseQuery(loc.Fragment)
	require.NoError(t, err)
	assert.NotEmpty(t, frag.Get("access_token"))
	assert.Equal(t, "Bearer", frag.Get("token_type"))
	assert.NotEmpty(t, frag.Get("expires_in"))
	assert.Equal(t, "read", frag.Get("scope"))
	assert.Equal(t, "impl-state", frag.Get("state"))
}

func TestAuthorizeImplicitRefusedWhenNotEnabled(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20)

	// The default config leaves AllowImplicit false.
	rec := runAuthorize(srv, implicitQuery(), approve)
	require.Equal(t, http.StatusFound, rec.Code)

	loc := mustLocation(t, rec)
	assert.Equal(t, oauth2.CodeUnsupportedResponseType, loc.Query().Get("error"))
	assert.Empty(t, loc.Fragment)
}

func TestAuthorizeImplicitConsentDenied(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20)
	cfg := oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}

	rec := runAuthorizeCfg(srv, cfg, implicitQuery(),
		func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			return &oauth2.Consent{Approved: false}, nil
		})
	require.Equal(t, http.StatusFound, rec.Code)

	// Implicit errors also travel in the fragment (RFC 6749 §4.2.2.1).
	frag, err := url.ParseQuery(mustLocation(t, rec).Fragment)
	require.NoError(t, err)
	assert.Equal(t, oauth2.CodeAccessDenied, frag.Get("error"))
}

func TestAuthorizeImplicitRejectsBroadenedScope(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20)
	cfg := oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}

	// implicitQuery requests "read"; the consent tries to grant "read write".
	rec := runAuthorizeCfg(srv, cfg, implicitQuery(),
		func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			return &oauth2.Consent{Approved: true, Subject: "alice", Scope: "read write"}, nil
		})
	require.Equal(t, http.StatusFound, rec.Code)

	frag, err := url.ParseQuery(mustLocation(t, rec).Fragment)
	require.NoError(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, frag.Get("error"))
}

// mustLocation parses the Location header of a redirect response.
func mustLocation(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)

	return loc
}
