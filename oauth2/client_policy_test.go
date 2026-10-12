// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
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
	"github.com/stretchr/testify/require"
)

// policyEnv is a server with every shipped grant but the legacy password
// one and every client-authentication method, over a counting memory store,
// reporting to sink.
type policyEnv struct {
	srv   *oauth2.Server
	store *writeCountingStore
	sink  *errorSink
}

// newPolicyEnv builds a policyEnv under profile, serving clients.
func newPolicyEnv(t *testing.T, profile oauth2.Profile, clients ...oauth2.Client) *policyEnv {
	t.Helper()

	env := &policyEnv{store: &writeCountingStore{Store: memory.New()}, sink: &errorSink{}}

	registry := make(map[string]oauth2.Client, len(clients))
	for _, c := range clients {
		registry[c.ID()] = c
	}

	gcfg := grant.Config{
		Storage:       env.store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		OnError:       env.sink.hook,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        profile,
		Storage:        env.store,
		ClientStore:    &staticClientStore{clients: registry},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants: []oauth2.Grant{
			grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg), grant.NewClientCredentials(gcfg),
		},
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
		OnError:    env.sink.hook,
	})
	require.NoError(t, err)

	env.srv = srv

	return env
}

// token posts form to /token, with HTTP Basic credentials when secret is
// set (client_secret_basic), the form alone otherwise.
func (env *policyEnv) token(form url.Values, id, secret string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if secret != "" {
		req.SetBasicAuth(id, secret)
	}

	rec := httptest.NewRecorder()
	env.srv.TokenHandler().ServeHTTP(rec, req)

	return rec
}

// consenting is a ConsentFunc approving as alice with scope as
// Consent.Scope.
func consenting(scope string) oauth2.ConsentFunc {
	return func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		return &oauth2.Consent{Approved: true, Subject: "alice", Scope: scope}, nil
	}
}

// TestConsentCannotBroadenTheRequest pins the Consent.Scope contract and RFC
// 6749 §3.3: the consent step narrows the requested scope, never broadens
// it — not even a request without scope, whose grant it could otherwise
// fill with any scope, registered for the client or not. The request is
// already a subset of the client's registration, so a grant never exceeds
// request ∩ registration. A consent naming no scope — empty, or SPs only —
// grants exactly what was requested.
func TestConsentCannotBroadenTheRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, requested, consented string
		want                       string // the granted scope; "" with refused
		refused                    bool
	}{
		{"empty request, scopes outside the registration", "", "admin delete-everything", "", true},
		{"empty request, a registered scope", "", "read", "", true},
		{"a scope outside the request", "read", "read write", "", true},
		{"a malformed consent scope", "read write", "read\twrite", "", true},
		{"narrowed", "read write", "read", "read", false},
		{"narrowed, repetitions dropped", "read write", "write  write", "write", false},
		{"no consent scope", "read write", "", "read write", false},
		{"a blank consent scope", "read write", "   ", "read write", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &writeCountingStore{Store: memory.New()}
			env := newExtensionEnv(t, &fakeExtension{}, withStore(store))

			q := authorizeQuery()
			q.Set("scope", tc.requested)

			rec := env.authorize(q, consenting(tc.consented))
			require.Equal(t, http.StatusFound, rec.Code)

			params := mustLocation(t, rec).Query()
			if tc.refused {
				assert.Equal(t, oauth2.CodeInvalidScope, params.Get("error"))
				assert.Empty(t, params.Get("code"))
				assert.Zero(t, store.writes.Load(), "nothing persisted")

				return
			}

			tokens := env.exchange(params.Get("code"))
			require.Equal(t, http.StatusOK, tokens.Code, tokens.Body.String())
			assert.Equal(t, tc.want, jsonBody(t, tokens)["scope"])
		})
	}
}

// TestImplicitConsentCannotBroadenTheRequest: the implicit flow applies the
// same rule; its refusal travels in the fragment.
func TestImplicitConsentCannotBroadenTheRequest(t *testing.T) {
	t.Parallel()

	store := &writeCountingStore{Store: memory.New()}
	env := newExtensionEnv(t, &fakeExtension{}, withStore(store), withProfile(oauth2.Profile20))

	q := implicitQuery()
	q.Del("scope")

	rec := runAuthorizeCfg(env.srv, oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()},
		q, consenting("admin"))
	require.Equal(t, http.StatusFound, rec.Code)

	frag, err := url.ParseQuery(mustLocation(t, rec).Fragment)
	require.NoError(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, frag.Get("error"))
	assert.Empty(t, frag.Get("access_token"))
	assert.Zero(t, store.writes.Load(), "nothing persisted")
}

// TestClientCredentialsRequiresAConfidentialClient pins RFC 6749 §4.4: "The
// client credentials grant type MUST only be used by confidential clients".
// A public client — whose client_id is no credential, RFC 6749 §2.3 — and an
// untyped one, which the server cannot know to be confidential, are refused
// with unauthorized_client (§5.2) whatever they declare and however they
// authenticate; nothing is issued. The "none" method itself never
// authenticates a confidential or untyped client.
func TestClientCredentialsRequiresAConfidentialClient(t *testing.T) {
	t.Parallel()

	grants := []string{oauth2.GrantTypeClientCredentials}
	scopes := []string{"admin", "superuser"}
	clients := []oauth2.Client{
		&oauth2.DefaultClient{
			IDValue: "spa", TypeValue: oauth2.ClientPublic, RedirectURIValues: []string{redirectURI},
			GrantTypeValues: grants, ScopeValues: scopes,
		},
		&oauth2.DefaultClient{IDValue: "untyped", Secret: "untyped-secret", GrantTypeValues: grants, ScopeValues: scopes},
		&oauth2.DefaultClient{
			IDValue: "machine", Secret: "machine-secret", TypeValue: oauth2.ClientConfidential,
			GrantTypeValues: grants, ScopeValues: scopes,
		},
	}

	form := func(extra ...string) url.Values {
		f := url.Values{"grant_type": {oauth2.GrantTypeClientCredentials}, "scope": {"admin superuser"}}
		for i := 0; i+1 < len(extra); i += 2 {
			f.Set(extra[i], extra[i+1])
		}

		return f
	}

	cases := []struct {
		name       string
		form       url.Values
		id, secret string
		status     int
		code       string
	}{
		{"public client via none", form("client_id", "spa"), "", "", http.StatusBadRequest, oauth2.CodeUnauthorizedClient},
		{"untyped client via client_secret_basic", form(), "untyped", "untyped-secret", http.StatusBadRequest, oauth2.CodeUnauthorizedClient},
		{
			"untyped client via client_secret_post", form("client_id", "untyped", "client_secret", "untyped-secret"), "", "",
			http.StatusBadRequest, oauth2.CodeUnauthorizedClient,
		},
		{"untyped client via none", form("client_id", "untyped"), "", "", http.StatusUnauthorized, oauth2.CodeInvalidClient},
		{"confidential client via none", form("client_id", "machine"), "", "", http.StatusUnauthorized, oauth2.CodeInvalidClient},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newPolicyEnv(t, oauth2.Profile20BCP, clients...)

			rec := env.token(tc.form, tc.id, tc.secret)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			assert.Equal(t, tc.code, jsonBody(t, rec)["error"])
			assert.NotContains(t, rec.Body.String(), "access_token")
			assert.Zero(t, env.store.writes.Load(), "nothing issued")
		})
	}

	t.Run("confidential client via client_secret_basic", func(t *testing.T) {
		t.Parallel()

		env := newPolicyEnv(t, oauth2.Profile20BCP, clients...)

		rec := env.token(form(), "machine", "machine-secret")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, "admin superuser", jsonBody(t, rec)["scope"])
	})
}

// confidentialClient returns the confidential client "machine" (secret
// "machine-secret", the canonical redirect URI) declaring grants and scopes.
func confidentialClient(grants, scopes []string) *oauth2.DefaultClient {
	return &oauth2.DefaultClient{
		IDValue: "machine", Secret: "machine-secret", TypeValue: oauth2.ClientConfidential,
		RedirectURIValues: []string{redirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
	}
}

// machineQuery is the canonical /authorize query of the client "machine".
func machineQuery() url.Values {
	q := authorizeQuery()
	q.Set("client_id", "machine")

	return q
}

// seedGrants stores, behind env's counter, a code ("seeded-code", S256 PKCE)
// and a refresh token ("seeded-rt") of the client "machine" with scope, as
// an earlier registration of the client could have issued them.
func seedGrants(t *testing.T, env *policyEnv, scope string) {
	t.Helper()

	now := time.Now()
	require.NoError(t, env.store.Store.SaveAuthorizationCode(t.Context(), &oauth2.AuthorizationCode{
		Code: "seeded-code", CodeHash: oauth2.HashToken(nil, "seeded-code"), ClientID: "machine", Subject: "alice",
		RedirectURI: redirectURI, Scope: scope, CodeChallenge: pkceChallenge, CodeChallengeMethod: "S256",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute), Issuer: "https://auth.example",
	}))
	require.NoError(t, env.store.Store.SaveTokenPair(t.Context(), &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			TokenHash: "seeded-at", ClientID: "machine", Subject: "alice", Scope: scope, FamilyID: "fam-seeded",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "https://auth.example",
		},
		Refresh: &oauth2.RefreshToken{
			TokenHash: oauth2.HashToken(nil, "seeded-rt"), ClientID: "machine", Subject: "alice", Scope: scope,
			FamilyID: "fam-seeded", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "https://auth.example",
		},
	}))
}

func TestClientAllowsGrantType(t *testing.T) {
	t.Parallel()

	declared := &oauth2.DefaultClient{GrantTypeValues: []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken}}
	assert.True(t, oauth2.ClientAllowsGrantType(declared, oauth2.GrantTypeAuthorizationCode))
	assert.True(t, oauth2.ClientAllowsGrantType(declared, oauth2.GrantTypeRefreshToken))
	assert.False(t, oauth2.ClientAllowsGrantType(declared, oauth2.GrantTypeClientCredentials))
	assert.False(t, oauth2.ClientAllowsGrantType(declared, "Authorization_Code"), "compared exactly")

	assert.False(t, oauth2.ClientAllowsGrantType(&oauth2.DefaultClient{}, oauth2.GrantTypeAuthorizationCode),
		"a client declaring no grant type may use none")
}

// TestEmptyGrantTypesAllowNoGrant pins the fail-closed client policy at
// /token: a client may only use the grant types it declares — none when it
// declares none (RFC 6749 §5.2 unauthorized_client). The server refuses
// before the grant runs, so a code or a refresh token the client presents
// stays untouched, and OnError gets ErrNoGrantTypesDeclared, the diagnosis
// of a registration that declares nothing.
func TestEmptyGrantTypesAllowNoGrant(t *testing.T) {
	t.Parallel()

	env := newPolicyEnv(t, oauth2.Profile20BCP, confidentialClient(nil, []string{"read"}))
	seedGrants(t, env, "read")

	forms := map[string]url.Values{
		"client_credentials": {"grant_type": {oauth2.GrantTypeClientCredentials}},
		"authorization_code": codeExchangeForm("seeded-code"),
		"refresh_token":      {"grant_type": {oauth2.GrantTypeRefreshToken}, "refresh_token": {"seeded-rt"}},
	}

	for name, form := range forms {
		rec := env.token(form, "machine", "machine-secret")
		require.Equal(t, http.StatusBadRequest, rec.Code, name)
		assert.Equal(t, oauth2.CodeUnauthorizedClient, jsonBody(t, rec)["error"], name)
		assert.NotContains(t, rec.Body.String(), "access_token", name)
	}

	assert.Zero(t, env.store.writes.Load(), "nothing issued")
	assert.True(t, env.sink.matches(oauth2.ErrNoGrantTypesDeclared))

	_, err := env.store.ConsumeAuthorizationCode(t.Context(), oauth2.HashToken(nil, "seeded-code"))
	require.NoError(t, err, "the code was not consumed")

	rt, err := env.store.LookupRefreshToken(t.Context(), oauth2.HashToken(nil, "seeded-rt"))
	require.NoError(t, err)
	assert.False(t, rt.Consumed, "the refresh token was not consumed")
}

// TestGrantTypesAreComparedExactly: a declaration lists grant types by their
// exact RFC 7591 §2 value; another grant type, or a case variant, is not
// declared — and the refusal does not read as an empty declaration.
func TestGrantTypesAreComparedExactly(t *testing.T) {
	t.Parallel()

	for name, grants := range map[string][]string{
		"another grant type": {oauth2.GrantTypeAuthorizationCode},
		"a case variant":     {"Client_Credentials"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newPolicyEnv(t, oauth2.Profile20BCP, confidentialClient(grants, []string{"read"}))

			rec := env.token(url.Values{"grant_type": {oauth2.GrantTypeClientCredentials}}, "machine", "machine-secret")
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, oauth2.CodeUnauthorizedClient, jsonBody(t, rec)["error"])
			assert.False(t, env.sink.matches(oauth2.ErrNoGrantTypesDeclared))
		})
	}
}

// stubGrant is a custom grant counting its calls.
type stubGrant struct {
	typ   string
	calls atomic.Int32
}

func (g *stubGrant) Type() string { return g.typ }

func (g *stubGrant) Handle(_ context.Context, req oauth2.GrantRequest) (*oauth2.GrantResponse, error) {
	g.calls.Add(1)

	return &oauth2.GrantResponse{
		Pair:      oauth2.TokenPair{Access: oauth2.AccessToken{Token: "custom", TokenHash: "custom", ExpiresAt: req.Now.Add(time.Hour)}},
		TokenType: oauth2.TokenTypeBearer,
	}, nil
}

// TestCustomGrantsAreGatedByTheClientDeclaration: the server checks the
// client's declaration for every grant type, custom ones included, before
// the grant runs — a custom grant cannot forget the policy.
func TestCustomGrantsAreGatedByTheClientDeclaration(t *testing.T) {
	t.Parallel()

	const custom = "urn:example:params:oauth:grant-type:custom"

	stub := &stubGrant{typ: custom}
	clients := map[string]oauth2.Client{
		"declares": &oauth2.DefaultClient{IDValue: "declares", Secret: "s1", TypeValue: oauth2.ClientConfidential, GrantTypeValues: []string{custom}},
		"nothing":  &oauth2.DefaultClient{IDValue: "nothing", Secret: "s2", TypeValue: oauth2.ClientConfidential},
		"other": &oauth2.DefaultClient{
			IDValue: "other", Secret: "s3", TypeValue: oauth2.ClientConfidential,
			GrantTypeValues: []string{oauth2.GrantTypeClientCredentials},
		},
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Storage: memory.New(), ClientStore: &staticClientStore{clients: clients},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{stub},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.NoError(t, err)

	call := func(id, secret string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(url.Values{"grant_type": {custom}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(id, secret)

		rec := httptest.NewRecorder()
		srv.TokenHandler().ServeHTTP(rec, req)

		return rec
	}

	for id, secret := range map[string]string{"nothing": "s2", "other": "s3"} {
		rec := call(id, secret)
		require.Equal(t, http.StatusBadRequest, rec.Code, id)
		assert.Equal(t, oauth2.CodeUnauthorizedClient, jsonBody(t, rec)["error"], id)
	}

	assert.Zero(t, stub.calls.Load(), "the grant never ran for a client not declaring it")

	rec := call("declares", "s1")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, int32(1), stub.calls.Load())
}

// TestEmptyScopesAllowNoScope pins the fail-closed client policy on scopes: a
// client may request only the scopes it declares — none when it declares
// none. A request carrying a scope is invalid_scope (OnError gets
// ErrNoScopesDeclared); one without scope gets the empty scope, the
// server's default (RFC 6749 §3.3).
func TestEmptyScopesAllowNoScope(t *testing.T) {
	t.Parallel()

	grants := []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeClientCredentials}

	t.Run("token endpoint", func(t *testing.T) {
		t.Parallel()

		env := newPolicyEnv(t, oauth2.Profile20BCP, confidentialClient(grants, nil))

		rec := env.token(url.Values{"grant_type": {oauth2.GrantTypeClientCredentials}, "scope": {"admin superuser"}}, "machine", "machine-secret")
		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, oauth2.CodeInvalidScope, jsonBody(t, rec)["error"])
		assert.True(t, env.sink.matches(oauth2.ErrNoScopesDeclared))

		rec = env.token(url.Values{"grant_type": {oauth2.GrantTypeClientCredentials}}, "machine", "machine-secret")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotContains(t, jsonBody(t, rec), "scope")
	})

	t.Run("authorization endpoint", func(t *testing.T) {
		t.Parallel()

		env := newPolicyEnv(t, oauth2.Profile20BCP, confidentialClient(grants, nil))

		consented := false
		consent := func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			consented = true

			return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
		}

		q := machineQuery()
		q.Set("scope", "read")

		rec := runAuthorize(env.srv, q, consent)
		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, oauth2.CodeInvalidScope, mustLocation(t, rec).Query().Get("error"))
		assert.False(t, consented, "the ConsentFunc never runs")
		assert.True(t, env.sink.matches(oauth2.ErrNoScopesDeclared))

		q.Del("scope")

		rec = runAuthorize(env.srv, q, approve)
		require.Equal(t, http.StatusFound, rec.Code)

		code := mustLocation(t, rec).Query().Get("code")
		require.NotEmpty(t, code)

		rec = env.token(codeExchangeForm(code), "machine", "machine-secret")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.NotContains(t, jsonBody(t, rec), "scope")
	})
}

// TestRefreshTokenOnlyForClientsAllowedTheRefreshGrant pins RFC 9700
// §4.14.2 ("Authorization servers MUST determine, based on a risk
// assessment, whether to issue refresh tokens to a certain client"): a code
// exchange issues a refresh token only to a client declaring refresh_token.
func TestRefreshTokenOnlyForClientsAllowedTheRefreshGrant(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		grants  []string
		refresh bool
	}{
		"without refresh_token": {[]string{oauth2.GrantTypeAuthorizationCode}, false},
		"with refresh_token":    {[]string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken}, true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newPolicyEnv(t, oauth2.Profile20BCP, confidentialClient(tc.grants, []string{"read"}))

			rec := runAuthorize(env.srv, machineQuery(), approve)
			require.Equal(t, http.StatusFound, rec.Code)

			rec = env.token(codeExchangeForm(mustLocation(t, rec).Query().Get("code")), "machine", "machine-secret")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, tc.refresh, jsonBody(t, rec)["refresh_token"] != nil)
		})
	}
}

// TestRefreshRechecksTheScopeRegistration pins RFC 9700 §4.14.2 (refresh
// tokens bound to the scope as consented) with the fail-closed policy: a
// refresh issues an access token only within the client's current scope
// registration. A refresh token minted before a registration shrank — or
// before empty registrations stopped meaning "any scope" — stops
// refreshing beyond it (invalid_scope, nothing consumed), while a narrowing
// inside the registration still refreshes.
func TestRefreshRechecksTheScopeRegistration(t *testing.T) {
	t.Parallel()

	client := confidentialClient(
		[]string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken}, []string{"read", "write"})
	env := newPolicyEnv(t, oauth2.Profile20BCP, client)

	q := machineQuery()
	q.Set("scope", "read write")

	rec := runAuthorize(env.srv, q, approve)
	require.Equal(t, http.StatusFound, rec.Code)

	rec = env.token(codeExchangeForm(mustLocation(t, rec).Query().Get("code")), "machine", "machine-secret")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rt, _ := jsonBody(t, rec)["refresh_token"].(string)
	require.NotEmpty(t, rt)

	refresh := func(rt string, scope ...string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {oauth2.GrantTypeRefreshToken}, "refresh_token": {rt}}
		if len(scope) > 0 {
			form.Set("scope", scope[0])
		}

		return env.token(form, "machine", "machine-secret")
	}

	client.ScopeValues = []string{"read"} // the registration shrinks

	rec = refresh(rt)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidScope, jsonBody(t, rec)["error"])

	rec = refresh(rt, "read write")
	require.Equal(t, http.StatusBadRequest, rec.Code, "narrowing that still exceeds the registration")
	assert.Equal(t, oauth2.CodeInvalidScope, jsonBody(t, rec)["error"])

	// The refusals consumed nothing: a narrowing inside the registration
	// still refreshes, and the replacement keeps the original scope (RFC
	// 6749 §6).
	rec = refresh(rt, "read")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "read", jsonBody(t, rec)["scope"])

	next, _ := jsonBody(t, rec)["refresh_token"].(string)
	require.NotEmpty(t, next)

	client.ScopeValues = nil // the client now declares no scope

	rec = refresh(next, "read")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidScope, jsonBody(t, rec)["error"])
	assert.True(t, env.sink.matches(oauth2.ErrNoScopesDeclared))
}

// withClients makes an extensionEnv serve clients.
func withClients(clients ...oauth2.Client) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config) {
		registry := make(map[string]oauth2.Client, len(clients))
		for _, c := range clients {
			registry[c.ID()] = c
		}

		s.ClientStore = &staticClientStore{clients: registry}
	}
}

// TestAuthorizeChecksTheClientGrantTypes pins RFC 6749 §4.1.2.1 / §4.2.2.1
// with RFC 7591 §2.1: response_type=code needs the authorization_code grant,
// response_type=token the implicit one. A client not declaring it is
// answered unauthorized_client in the flow's response mode — before the
// extension or the ConsentFunc runs, nothing persisted.
func TestAuthorizeChecksTheClientGrantTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		grants   []string
		implicit bool
		allowed  bool
	}{
		{"client_credentials only, token", []string{oauth2.GrantTypeClientCredentials}, true, false},
		{"client_credentials only, code", []string{oauth2.GrantTypeClientCredentials}, false, false},
		{"implicit only, code", []string{oauth2.GrantTypeImplicit}, false, false},
		{"implicit only, token", []string{oauth2.GrantTypeImplicit}, true, true},
		{"authorization_code only, token", []string{oauth2.GrantTypeAuthorizationCode}, true, false},
		{"authorization_code only, code", []string{oauth2.GrantTypeAuthorizationCode}, false, true},
		{"nothing declared, code", nil, false, false},
		{"nothing declared, token", nil, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := &oauth2.DefaultClient{
				IDValue: testClientID, Secret: testClientSecret, TypeValue: oauth2.ClientConfidential,
				RedirectURIValues: []string{redirectURI}, ScopeValues: []string{"read"}, GrantTypeValues: tc.grants,
			}
			ext := &fakeExtension{}
			store := &writeCountingStore{Store: memory.New()}
			env := newExtensionEnv(t, ext, withProfile(oauth2.Profile20), withStore(store), withClients(client))

			q, cfg := authorizeQuery(), oauth2.AuthorizeConfig{}
			if tc.implicit {
				q, cfg = implicitQuery(), oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}
			}

			consented := false
			rec := runAuthorizeCfg(env.srv, cfg, q, func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
				consented = true

				return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
			})
			require.Equal(t, http.StatusFound, rec.Code)

			loc := mustLocation(t, rec)

			params := loc.Query()
			if tc.implicit {
				var err error

				params, err = url.ParseQuery(loc.Fragment)
				require.NoError(t, err)
			}

			if tc.allowed {
				assert.Empty(t, params.Get("error"))
				assert.True(t, consented)

				return
			}

			assert.Equal(t, oauth2.CodeUnauthorizedClient, params.Get("error"))
			assert.Equal(t, "https://auth.example", params.Get("iss"))
			assert.Equal(t, q.Get("state"), params.Get("state"))
			assert.Empty(t, params.Get("code"))
			assert.Empty(t, params.Get("access_token"))
			assert.False(t, consented, "the ConsentFunc never runs")

			validated, _, _ := ext.calls()
			assert.Zero(t, validated, "the extension never runs")
			assert.Zero(t, store.writes.Load(), "nothing persisted")
			assert.Equal(t, tc.grants == nil, env.sink.matches(oauth2.ErrNoGrantTypesDeclared))
		})
	}

	t.Run("an implicit flow the server does not enable", func(t *testing.T) {
		t.Parallel()

		env := newExtensionEnv(t, &fakeExtension{}, withClients(&oauth2.DefaultClient{
			IDValue: testClientID, TypeValue: oauth2.ClientConfidential, RedirectURIValues: []string{redirectURI},
			ScopeValues: []string{"read"}, GrantTypeValues: []string{oauth2.GrantTypeImplicit},
		}))

		rec := env.authorize(implicitQuery(), approve)
		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, oauth2.CodeUnsupportedResponseType, mustLocation(t, rec).Query().Get("error"),
			"unsupported_response_type keeps precedence")
	})
}
