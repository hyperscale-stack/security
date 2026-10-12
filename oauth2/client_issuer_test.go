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

// Two realms behind one ClientStore (hostIssuer): tenant-a's clients are
// registered at https://a.example only; testClientID, without the
// capability, at every issuer.
const (
	realmA         = "a.example"
	realmB         = "b.example"
	issuerA        = "https://a.example"
	boundClientID  = "tenant-a-app"
	boundPublicID  = "tenant-a-spa"
	unknownClient  = "nobody"
	boundSecret    = "tenant-a-secret"
	wrongSecret    = "not-the-secret"
	boundScopeRead = "read"
)

// newTenantServer is an authorization server for realms a.example and
// b.example sharing one ClientStore.
func newTenantServer(t *testing.T, sink *errorSink, auth ...oauth2.ClientAuthenticator) *oauth2.Server {
	t.Helper()

	store := memory.New()
	grants := []string{"authorization_code", "refresh_token", "client_credentials"}
	clients := &staticClientStore{clients: map[string]oauth2.Client{
		testClientID: &oauth2.DefaultClient{
			GrantTypeValues: allGrantTypes,
			IDValue:         testClientID, Secret: testClientSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{redirectURI}, ScopeValues: []string{"read", "write"},
		},
		boundClientID: &oauth2.DefaultClient{
			IDValue: boundClientID, Secret: boundSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{redirectURI}, ScopeValues: []string{boundScopeRead}, GrantTypeValues: grants,
			IssuerValues: []string{issuerA},
		},
		boundPublicID: &oauth2.DefaultClient{
			IDValue: boundPublicID, TypeValue: oauth2.ClientPublic, AuthMethodValues: []string{"none"},
			RedirectURIValues: []string{redirectURI}, ScopeValues: []string{boundScopeRead}, GrantTypeValues: grants,
			IssuerValues: []string{issuerA},
		},
	}}

	cfg := grant.Config{
		Storage:       store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
	}

	if len(auth) == 0 {
		auth = []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()}
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20, // authorizeAt enables the implicit flow
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: hostIssuer{},
		Grants: []oauth2.Grant{
			grant.NewAuthorizationCode(cfg), grant.NewRefreshToken(cfg), grant.NewClientCredentials(cfg),
		},
		ClientAuth: auth,
		OnError:    sink.hook,
	})
	require.NoError(t, err)

	return srv
}

// queryOf is authorizeQuery for clientID.
func queryOf(clientID string) url.Values {
	q := authorizeQuery()
	q.Set("client_id", clientID)

	return q
}

// basicAt posts form to path on host, authenticated with Basic as id.
func basicAt(h http.Handler, host, path, id, secret string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	req.Host = host

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

// sameResponse asserts two responses are the same bytes on the wire: a
// client bound elsewhere reads exactly as one that exists nowhere.
func sameResponse(t *testing.T, want, got *httptest.ResponseRecorder) {
	t.Helper()

	assert.Equal(t, want.Code, got.Code)
	assert.Equal(t, want.Header(), got.Header())
	assert.Equal(t, want.Body.String(), got.Body.String())
}

// TestBoundClientIsUnknownAtAnotherIssuer pins the cross-tenant attack at
// /authorize: tenant A's client cannot send a tenant B end-user to B's
// login and consent — B answers as for a client_id that exists nowhere
// (RFC 6749 §4.1.2.1: an invalid client is never redirected), whatever
// else the request gets wrong, and never runs the ConsentFunc.
func TestBoundClientIsUnknownAtAnotherIssuer(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	srv := newTenantServer(t, sink)

	consented := false
	consent := func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		consented = true

		return &oauth2.Consent{Approved: true, Subject: "victim"}, nil
	}

	variants := map[string]func(url.Values){
		"valid request":         func(url.Values) {},
		"unregistered redirect": func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"unsupported mode":      func(q url.Values) { q.Set("response_mode", "form_post") },
		"scope not allowed":     func(q url.Values) { q.Set("scope", "admin") },
		"unsupported type":      func(q url.Values) { q.Set("response_type", "token") },
	}

	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			bound, unknown := queryOf(boundClientID), queryOf(unknownClient)
			mutate(bound)
			mutate(unknown)

			got := authorizeAt(srv, realmB, bound, consent)
			require.Equal(t, http.StatusBadRequest, got.Code)
			assert.Empty(t, got.Header().Get("Location"), "never redirected")
			sameResponse(t, authorizeAt(srv, realmB, unknown, consent), got)
		})
	}

	assert.False(t, consented, "no login or consent page for a client of another realm")
	assert.True(t, sink.matches(oauth2.ErrClientNotAtIssuer), "the cause reaches the hook")

	rec := authorizeAt(srv, realmA, queryOf(boundClientID), approve)
	require.Equal(t, http.StatusFound, rec.Code, "its own realm serves it")
	assert.NotEmpty(t, mustLocation(t, rec).Query().Get("code"))
}

// TestBoundClientCannotAuthenticateAtAnotherIssuer: at /token, /revoke and
// /introspect, a client of another realm fails client authentication
// exactly as an unknown client does (RFC 6749 §5.2 invalid_client) —
// with its right secret or a wrong one, through every method — so B
// cannot be used to enumerate A's clients or check their secrets.
func TestBoundClientCannotAuthenticateAtAnotherIssuer(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	srv := newTenantServer(t, sink)

	endpoints := map[string]struct {
		handler http.Handler
		path    string
		form    url.Values
	}{
		"token":      {srv.TokenHandler(), "/oauth2/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}},
		"revoke":     {srv.RevokeHandler(), "/oauth2/revoke", url.Values{"token": {"some-token"}}},
		"introspect": {srv.IntrospectHandler(), "/oauth2/introspect", url.Values{"token": {"some-token"}}},
	}

	for name, ep := range endpoints {
		t.Run(name, func(t *testing.T) {
			unknown := basicAt(ep.handler, realmB, ep.path, unknownClient, wrongSecret, ep.form)
			require.Equal(t, http.StatusUnauthorized, unknown.Code)

			sameResponse(t, unknown, basicAt(ep.handler, realmB, ep.path, boundClientID, boundSecret, ep.form))
			sameResponse(t, unknown, basicAt(ep.handler, realmB, ep.path, boundClientID, wrongSecret, ep.form))

			post := url.Values{"client_id": {boundClientID}, "client_secret": {boundSecret}}
			for k, v := range ep.form {
				post[k] = v
			}

			sameResponse(t, unknown, formAt(ep.handler, realmB, ep.path, post))

			own := basicAt(ep.handler, realmA, ep.path, boundClientID, boundSecret, ep.form)
			assert.Equal(t, http.StatusOK, own.Code, own.Body.String())
		})
	}

	t.Run("public client", func(t *testing.T) {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {boundPublicID}}
		unknown := url.Values{"grant_type": {"client_credentials"}, "client_id": {unknownClient}}

		sameResponse(t, formAt(srv.TokenHandler(), realmB, "/oauth2/token", unknown),
			formAt(srv.TokenHandler(), realmB, "/oauth2/token", form))
	})

	assert.True(t, sink.matches(oauth2.ErrClientNotAtIssuer))
}

// TestCrossTenantCodeExchangeFails pins the attack at /token: a code tenant
// A issued to its client cannot be redeemed at B — the client is unknown
// there, the code is left untouched and stays redeemable at A.
func TestCrossTenantCodeExchangeFails(t *testing.T) {
	t.Parallel()

	srv := newTenantServer(t, &errorSink{})

	rec := authorizeAt(srv, realmA, queryOf(boundClientID), approve)
	require.Equal(t, http.StatusFound, rec.Code)

	code := mustLocation(t, rec).Query().Get("code")

	atB := basicAt(srv.TokenHandler(), realmB, "/oauth2/token", boundClientID, boundSecret, codeExchangeForm(code))
	assert.Equal(t, http.StatusUnauthorized, atB.Code)
	assert.Equal(t, oauth2.CodeInvalidClient, decodeError(t, atB))

	atA := basicAt(srv.TokenHandler(), realmA, "/oauth2/token", boundClientID, boundSecret, codeExchangeForm(code))
	assert.Equal(t, http.StatusOK, atA.Code, atA.Body.String())
}

// TestUnboundClientsServeEveryIssuer: a client without the capability keeps
// the behaviour of a shared ClientStore — known at every issuer.
func TestUnboundClientsServeEveryIssuer(t *testing.T) {
	t.Parallel()

	srv := newTenantServer(t, &errorSink{})

	for _, host := range []string{realmA, realmB} {
		code := codeAt(t, srv, host)
		rec := tokenAt(srv, host, codeExchangeForm(code))
		assert.Equal(t, http.StatusOK, rec.Code, host)
	}
}

// TestClientBindingSurvivesCustomAuthenticators: an authenticator that
// does not load the client through the store it is handed still cannot
// authenticate a client of another realm.
func TestClientBindingSurvivesCustomAuthenticators(t *testing.T) {
	t.Parallel()

	bound := &oauth2.DefaultClient{GrantTypeValues: allGrantTypes, IDValue: boundClientID, TypeValue: oauth2.ClientConfidential, IssuerValues: []string{issuerA}}
	sink := &errorSink{}
	srv := newTenantServer(t, sink, fixedAuthenticator{client: bound})

	form := url.Values{"grant_type": {"client_credentials"}}
	rec := basicAt(srv.TokenHandler(), realmB, "/oauth2/token", boundClientID, boundSecret, form)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidClient, decodeError(t, rec))
	assert.True(t, sink.matches(oauth2.ErrClientNotAtIssuer))
}

// TestClientAuthenticatorFailureIsAServerError: an authenticator failing
// with an error that is no protocol error answers server_error.
func TestClientAuthenticatorFailureIsAServerError(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	srv := newTenantServer(t, sink, failingAuthenticator{})

	rec := basicAt(srv.TokenHandler(), realmA, "/oauth2/token", boundClientID, boundSecret,
		url.Values{"grant_type": {"client_credentials"}})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, oauth2.CodeServerError, decodeError(t, rec))
	assert.Equal(t, []string{oauth2.CodeServerError}, sink.codes())
}

// failingAuthenticator fails every authentication with a backend error.
type failingAuthenticator struct{}

func (failingAuthenticator) Method() string { return "client_secret_basic" }

func (failingAuthenticator) Match(*http.Request) bool { return true }

func (failingAuthenticator) Authenticate(context.Context, *http.Request, oauth2.ClientStore) (oauth2.Client, error) {
	return nil, errors.New("client directory down")
}

// fixedAuthenticator authenticates every request as client, without the
// store.
type fixedAuthenticator struct{ client oauth2.Client }

func (fixedAuthenticator) Method() string { return "client_secret_basic" }

func (fixedAuthenticator) Match(*http.Request) bool { return true }

func (a fixedAuthenticator) Authenticate(context.Context, *http.Request, oauth2.ClientStore) (oauth2.Client, error) {
	return a.client, nil
}

// TestClientAllowsIssuer pins the capability's semantics.
func TestClientAllowsIssuer(t *testing.T) {
	t.Parallel()

	anywhere := &oauth2.DefaultClient{GrantTypeValues: allGrantTypes, IDValue: "c"}
	bound := &oauth2.DefaultClient{GrantTypeValues: allGrantTypes, IDValue: "c", IssuerValues: []string{issuerA, "https://a.example/t1"}}

	assert.True(t, oauth2.ClientAllowsIssuer(anywhere, "https://b.example"), "no issuers listed: every issuer")
	assert.True(t, oauth2.ClientAllowsIssuer(bound, issuerA))
	assert.True(t, oauth2.ClientAllowsIssuer(bound, "https://a.example/t1"))
	assert.False(t, oauth2.ClientAllowsIssuer(bound, "https://b.example"))
	assert.False(t, oauth2.ClientAllowsIssuer(bound, issuerA+"/"), "issuers are compared exactly")
	assert.False(t, oauth2.ClientAllowsIssuer(bound, ""))
	assert.True(t, oauth2.ClientAllowsIssuer(plainClient{}, "https://b.example"), "a client without the capability")
}

// plainClient is a Client without the IssuerBoundClient capability.
type plainClient struct{ oauth2.Client }

// formAt posts form, unauthenticated by headers, to path on host.
func formAt(h http.Handler, host, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = host

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

// matches reports whether some hooked error matches target.
func (s *errorSink) matches(target error) bool {
	for _, err := range s.collected() {
		if errors.Is(err, target) {
			return true
		}
	}

	return false
}
