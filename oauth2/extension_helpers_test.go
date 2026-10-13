// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/require"
)

// testClock is an injectable server clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// completion records one Extension.CompleteAuthorization call.
type completion struct {
	ar      oauth2.AuthorizeRequest
	consent oauth2.Consent
	now     time.Time
}

// fakeExtension is an oauth2.Extension whose behavior each test scripts;
// it records every call. A nil func answers the zero value.
type fakeExtension struct {
	validate func(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error)
	complete func(context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time) (oauth2.ExtensionGrant, error)
	extend   func(context.Context, oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error)

	mu        sync.Mutex
	validated []oauth2.AuthorizeRequest
	completed []completion
	issuances []oauth2.TokenIssuance
}

func (f *fakeExtension) ValidateAuthorizeRequest(ctx context.Context, r *http.Request, ar *oauth2.AuthorizeRequest) (any, error) {
	f.mu.Lock()
	f.validated = append(f.validated, *ar)
	f.mu.Unlock()

	if f.validate == nil {
		return nil, nil
	}

	return f.validate(ctx, r, ar)
}

func (f *fakeExtension) CompleteAuthorization(
	ctx context.Context, ar *oauth2.AuthorizeRequest, consent oauth2.Consent, now time.Time,
) (oauth2.ExtensionGrant, error) {
	f.mu.Lock()
	f.completed = append(f.completed, completion{ar: *ar, consent: consent, now: now})
	f.mu.Unlock()

	if f.complete == nil {
		return oauth2.ExtensionGrant{}, nil
	}

	return f.complete(ctx, ar, consent, now)
}

func (f *fakeExtension) ExtendTokenResponse(ctx context.Context, ti oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	f.mu.Lock()
	f.issuances = append(f.issuances, ti)
	f.mu.Unlock()

	if f.extend == nil {
		return oauth2.TokenResponseExtension{}, nil
	}

	return f.extend(ctx, ti)
}

// calls returns how many times each hook ran.
func (f *fakeExtension) calls() (validated, completed, extended int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.validated), len(f.completed), len(f.issuances)
}

// --- a toy OpenID Connect provider ------------------------------------------

// toyRequest is the toy provider's view of an authentication request.
type toyRequest struct{ MaxAge time.Duration }

// toyAuthentication is the trusted result the application attests.
type toyAuthentication struct {
	AuthTime time.Time
	ACR      string
}

// toyContext is the grant context the toy provider records (JSON).
type toyContext struct {
	AuthTime int64  `json:"auth_time"`
	ACR      string `json:"acr"`
	Note     string `json:"note"`
}

// toyIDToken is the unsigned "ID Token" the toy provider returns: the JSON
// claims, base64url-encoded — the oauth2 tests never import JOSE.
type toyIDToken struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Nonce    string `json:"nonce,omitempty"`
	AuthTime int64  `json:"auth_time"`
	ACR      string `json:"acr,omitempty"`
	Iat      int64  `json:"iat"`
	AtHash   string `json:"at_hash"`
}

// errNoAuthentication is the toy provider's answer to an OpenID Connect
// request approved without the trusted authentication it needs.
var errNoAuthentication = errors.New("toy: approval without authentication")

// toyOIDC is a test extension in the shape of an OpenID Connect provider:
// it validates max_age, refuses a stale authentication with login_required,
// records the attested authentication in the grant context, and adds an
// "id_token" to every response whose access token carries openid.
type toyOIDC struct{}

func isOIDC(scope string) bool { return slices.Contains(strings.Fields(scope), "openid") }

func (toyOIDC) ValidateAuthorizeRequest(_ context.Context, r *http.Request, ar *oauth2.AuthorizeRequest) (any, error) {
	if !isOIDC(ar.Scope) {
		return nil, nil
	}

	req := &toyRequest{}

	if raw := r.FormValue("max_age"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < 0 {
			return nil, oauth2.ErrInvalidRequest.WithDescription("max_age is not a non-negative integer")
		}

		req.MaxAge = time.Duration(seconds) * time.Second
	}

	return req, nil
}

func (toyOIDC) CompleteAuthorization(
	_ context.Context, ar *oauth2.AuthorizeRequest, consent oauth2.Consent, now time.Time,
) (oauth2.ExtensionGrant, error) {
	if !isOIDC(consent.Scope) {
		return oauth2.ExtensionGrant{}, nil
	}

	auth, ok := consent.ExtensionResult.(*toyAuthentication)
	if !ok {
		return oauth2.ExtensionGrant{}, errNoAuthentication
	}

	if req, _ := ar.ExtensionRequest.(*toyRequest); req != nil && req.MaxAge > 0 && now.Sub(auth.AuthTime) > req.MaxAge {
		return oauth2.ExtensionGrant{}, oauth2.ErrLoginRequired
	}

	data, err := json.Marshal(toyContext{AuthTime: auth.AuthTime.Unix(), ACR: auth.ACR, Note: `"\/<é>`})
	if err != nil {
		return oauth2.ExtensionGrant{}, err //nolint:wrapcheck // test double
	}

	return oauth2.ExtensionGrant{Data: string(data)}, nil
}

func (toyOIDC) ExtendTokenResponse(_ context.Context, ti oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	if !isOIDC(ti.Access.Scope) {
		return oauth2.TokenResponseExtension{}, nil
	}

	var grantCtx toyContext
	if err := json.Unmarshal([]byte(ti.Access.ExtensionData), &grantCtx); err != nil {
		return oauth2.TokenResponseExtension{}, oauth2.ErrInvalidGrant.WithDescription("grant without an authentication")
	}

	claims, err := json.Marshal(toyIDToken{
		Iss: ti.Access.Issuer, Sub: ti.Access.Subject, Aud: ti.Client.ID(), Nonce: ti.Nonce,
		AuthTime: grantCtx.AuthTime, ACR: grantCtx.ACR, Iat: ti.Access.IssuedAt.Unix(),
		AtHash: atHash(ti.Access.Token),
	})
	if err != nil {
		return oauth2.TokenResponseExtension{}, err //nolint:wrapcheck // test double
	}

	return oauth2.TokenResponseExtension{IDToken: base64.RawURLEncoding.EncodeToString(claims)}, nil
}

// atHash is the OIDC Core §3.1.3.6 at_hash of an access token for a
// SHA-256 based algorithm: the left half of its hash, base64url.
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// decodeToyIDToken decodes the toy provider's id_token.
func decodeToyIDToken(t *testing.T, raw string) toyIDToken {
	t.Helper()

	claims, err := base64.RawURLEncoding.DecodeString(raw)
	require.NoError(t, err)

	var tok toyIDToken
	require.NoError(t, json.Unmarshal(claims, &tok))

	return tok
}

// --- the extension test server -----------------------------------------------

// extensionEnv is a server wired with an extension.
type extensionEnv struct {
	srv   *oauth2.Server
	store oauth2.Storage
	sink  *errorSink
	clock *testClock
}

// envOption customizes the configuration of an extensionEnv.
type envOption func(*oauth2.ServerConfig, *grant.Config)

// withStore makes the server and its grants use store.
func withStore(store oauth2.Storage) envOption {
	return func(s *oauth2.ServerConfig, g *grant.Config) { s.Storage, g.Storage = store, store }
}

// withResolver makes the server resolve issuers through resolver.
func withResolver(resolver oauth2.IssuerResolver) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config) { s.IssuerResolver = resolver }
}

// withProfile selects the server profile.
func withProfile(p oauth2.Profile) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config) { s.Profile = p }
}

// newExtensionEnv builds a server — authorization_code, refresh_token and
// client_credentials over a memory store, a confidential client allowed
// "openid read write", StaticIssuer("https://auth.example", "api"), a
// fixed clock — with ext as its extension.
func newExtensionEnv(t *testing.T, ext oauth2.Extension, opts ...envOption) *extensionEnv {
	t.Helper()

	env := &extensionEnv{sink: &errorSink{}, clock: newTestClock()}
	store := memory.New()

	gcfg := grant.Config{
		Storage:       store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		OnError:       env.sink.hook,
	}
	scfg := oauth2.ServerConfig{
		Storage: store,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			testClientID: &oauth2.DefaultClient{
				GrantTypeValues: allGrantTypes,
				IDValue:         testClientID, Secret: testClientSecret, TypeValue: oauth2.ClientConfidential,
				RedirectURIValues: []string{redirectURI}, ScopeValues: []string{"openid", "read", "write"},
			},
		}},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		Now:            env.clock.Now,
		OnError:        env.sink.hook,
		Extension:      ext,
	}

	for _, o := range opts {
		o(&scfg, &gcfg)
	}

	scfg.Grants = []oauth2.Grant{
		grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg), grant.NewClientCredentials(gcfg),
	}

	srv, err := oauth2.NewServer(scfg)
	require.NoError(t, err)

	env.srv, env.store = srv, scfg.Storage

	return env
}

// oidcQuery is a valid OpenID Connect code-flow request (S256 PKCE).
func oidcQuery() url.Values {
	q := authorizeQuery()
	q.Set("scope", "openid read")
	q.Set("nonce", "n-0S6_WzA2Mj")

	return q
}

// authorize runs /authorize on env with q and consent.
func (env *extensionEnv) authorize(q url.Values, consent oauth2.ConsentFunc) *httptest.ResponseRecorder {
	return runAuthorizeCfg(env.srv, oauth2.AuthorizeConfig{}, q, consent)
}

// code runs /authorize on env with q and consent and returns the code.
func (env *extensionEnv) code(t *testing.T, q url.Values, consent oauth2.ConsentFunc) string {
	t.Helper()

	rec := env.authorize(q, consent)
	require.Equal(t, http.StatusFound, rec.Code, rec.Header().Get("Location"))

	code := mustLocation(t, rec).Query().Get("code")
	require.NotEmpty(t, code, rec.Header().Get("Location"))

	return code
}

// token posts form to /token as the test client.
func (env *extensionEnv) token(form url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	env.srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token", form, true))

	return rec
}

// exchange redeems code with the canonical PKCE verifier.
func (env *extensionEnv) exchange(code string) *httptest.ResponseRecorder {
	return env.token(codeExchangeForm(code))
}

// refresh exchanges a refresh token.
func (env *extensionEnv) refresh(rt string) *httptest.ResponseRecorder {
	return env.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
}

// jsonBody decodes a JSON body into its members.
func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())

	return body
}

// keys returns the sorted member names of body.
func keys(body map[string]any) []string {
	out := make([]string, 0, len(body))
	for k := range body {
		out = append(out, k)
	}

	slices.Sort(out)

	return out
}

// authenticated is a ConsentFunc approving as alice, authenticated at
// authTime.
func authenticated(authTime time.Time) oauth2.ConsentFunc {
	return func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		return &oauth2.Consent{
			Approved: true, Subject: "alice",
			ExtensionResult: &toyAuthentication{AuthTime: authTime, ACR: "urn:example:loa:2"},
		}, nil
	}
}
