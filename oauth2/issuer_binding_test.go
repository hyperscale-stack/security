// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
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

// hostIssuer is the IssuerResolver of a multi-realm deployment: the issuer,
// and the audience with it, follow the request's Host.
type hostIssuer struct{}

func (hostIssuer) Resolve(_ context.Context, r *http.Request) (string, string, error) {
	return "https://" + r.Host, "api." + r.Host, nil
}

// newRealmServer is newAuthorizeServer behind a hostIssuer, with the
// refresh_token grant and, under Profile20, the implicit flow available.
func newRealmServer(t *testing.T, resolver oauth2.IssuerResolver) (*oauth2.Server, *memory.Store) {
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
		Profile:        oauth2.Profile20,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: resolver,
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(cfg), grant.NewRefreshToken(cfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.NoError(t, err)

	return srv, store
}

// authorizeAt runs /authorize on host with the implicit flow enabled.
func authorizeAt(srv *oauth2.Server, host string, q url.Values, consent oauth2.ConsentFunc) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	req.Host = host

	cfg := oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}
	srv.AuthorizeHandler(cfg, consent).ServeHTTP(rec, req)

	return rec
}

// tokenAt posts form to /token on host, authenticated as the test client.
func tokenAt(srv *oauth2.Server, host string, form url.Values) *httptest.ResponseRecorder {
	req := formRequest("/oauth2/token", form, true)
	req.Host = host

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)

	return rec
}

// codeAt runs the code flow on host and returns the issued code.
func codeAt(t *testing.T, srv *oauth2.Server, host string) string {
	t.Helper()

	rec := authorizeAt(srv, host, authorizeQuery(), approve)
	require.Equal(t, http.StatusFound, rec.Code)

	code := mustLocation(t, rec).Query().Get("code")
	require.NotEmpty(t, code)

	return code
}

// codeForm is the /token form redeeming code.
func codeExchangeForm(code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {pkceVerifier},
	}
}

// TestAuthorizeBindsTheCodeToTheResolvedIssuer: the ConsentFunc sees the
// issuer the resolver returned for the request, and the code records it.
func TestAuthorizeBindsTheCodeToTheResolvedIssuer(t *testing.T) {
	t.Parallel()

	srv, store := newRealmServer(t, hostIssuer{})

	var seen string

	rec := authorizeAt(srv, "a.example", authorizeQuery(),
		func(_ http.ResponseWriter, _ *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			seen = ar.Issuer

			return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
		})
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "https://a.example", seen)

	code := mustLocation(t, rec).Query().Get("code")
	record, err := store.ConsumeAuthorizationCode(t.Context(), oauth2.HashToken(nil, code))
	require.NoError(t, err)
	assert.Equal(t, "https://a.example", record.Issuer)
}

// TestImplicitTokenRecordsTheResolvedIssuer: an implicit access token is
// bound to the issuer, and gets the audience, of the request's realm.
func TestImplicitTokenRecordsTheResolvedIssuer(t *testing.T) {
	t.Parallel()

	srv, store := newRealmServer(t, hostIssuer{})

	rec := authorizeAt(srv, "a.example", implicitQuery(), approve)
	require.Equal(t, http.StatusFound, rec.Code)

	fragment, err := url.ParseQuery(mustLocation(t, rec).Fragment)
	require.NoError(t, err)

	at, err := store.LookupAccessToken(t.Context(), oauth2.HashToken(nil, fragment.Get("access_token")))
	require.NoError(t, err)
	assert.Equal(t, "https://a.example", at.Issuer)
	assert.Equal(t, "api.a.example", at.Audience)
}

// TestAuthorizeIssuerFailureAnswersBeforeConsent: a resolver failure is a
// server_error redirected — in the query for the code flow, in the fragment
// for the implicit one — before the ConsentFunc runs, and nothing is saved.
func TestAuthorizeIssuerFailureAnswersBeforeConsent(t *testing.T) {
	t.Parallel()

	for name, q := range map[string]url.Values{"code": authorizeQuery(), "implicit": implicitQuery()} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sink := &errorSink{}
			srv, err := oauth2.NewServer(oauth2.ServerConfig{
				Profile: oauth2.Profile20, Storage: memory.New(), IssuerResolver: failingIssuer{},
				ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
					testClientID: &oauth2.DefaultClient{
						IDValue: testClientID, RedirectURIValues: []string{redirectURI}, ScopeValues: []string{"read"},
					},
				}},
				ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic()},
				OnError:    sink.hook,
			})
			require.NoError(t, err)

			consented := false
			rec := authorizeAt(srv, "a.example", q,
				func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
					consented = true

					return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
				})
			require.Equal(t, http.StatusFound, rec.Code)
			assert.False(t, consented, "the ConsentFunc never runs")

			loc := mustLocation(t, rec)
			params := loc.Query()

			if name == "implicit" {
				params, err = url.ParseQuery(loc.Fragment)
				require.NoError(t, err)
			}

			assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
			assert.Equal(t, q.Get("state"), params.Get("state"))
			assert.False(t, params.Has("code"))
			assert.False(t, params.Has("access_token"))
			assert.Equal(t, []string{oauth2.CodeServerError}, sink.codes())
		})
	}
}

// TestCodeRedeemedAtAnotherIssuerIsRefused issues a code on realm a and
// redeems it on realm b: invalid_grant, and the code is burned.
func TestCodeRedeemedAtAnotherIssuerIsRefused(t *testing.T) {
	t.Parallel()

	srv, _ := newRealmServer(t, hostIssuer{})
	code := codeAt(t, srv, "a.example")

	rec := tokenAt(srv, "b.example", codeExchangeForm(code))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	errCode, desc := tokenError(t, rec)
	assert.Equal(t, oauth2.CodeInvalidGrant, errCode)
	assert.Equal(t, "authorization code issued by another issuer", desc)

	rec = tokenAt(srv, "a.example", codeExchangeForm(code))
	require.Equal(t, http.StatusBadRequest, rec.Code, "the code is single-use, even after a refused exchange")
}

// TestRefreshAtAnotherIssuerIsRefused refreshes a realm-a token on realm b:
// invalid_grant, and the token still refreshes on realm a.
func TestRefreshAtAnotherIssuerIsRefused(t *testing.T) {
	t.Parallel()

	srv, _ := newRealmServer(t, hostIssuer{})

	rec := tokenAt(srv, "a.example", codeExchangeForm(codeAt(t, srv, "a.example")))
	require.Equal(t, http.StatusOK, rec.Code)

	var issued struct {
		RefreshToken string `json:"refresh_token"` //nolint:gosec // test fixture
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issued))

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}

	rec = tokenAt(srv, "b.example", form)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	errCode, desc := tokenError(t, rec)
	assert.Equal(t, oauth2.CodeInvalidGrant, errCode)
	assert.Equal(t, "refresh_token issued by another issuer", desc)

	rec = tokenAt(srv, "a.example", form)
	assert.Equal(t, http.StatusOK, rec.Code, "the refused refresh consumed nothing")
}
