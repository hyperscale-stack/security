// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oidcop_test checks oidc/provider against an independent relying
// party — github.com/coreos/go-oidc/v3 and golang.org/x/oauth2 — over TLS,
// in process. The module holds tests only: it is not part of the public
// API, and its dependencies never reach another module.
package oidcop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"
)

// The registered clients. The client_secret_basic one holds every
// character the form-urlencoding of RFC 6749 §2.3.1 transforms: its ID
// stays within VSCHAR (Appendix A.1), its secret adds non-ASCII (Appendix
// B: UTF-8 first).
const (
	basicClientID     = "rp client%+:/="
	basicClientSecret = "s3cr%t +:/=é"
	postClientID      = "rp-post"
	postClientSecret  = "post-secret"
	publicClientID    = "rp-public"
	signingSecret     = "signing-secret"
	redirectURI       = "https://rp.example/callback"
	tenantA           = "/tenant-a"
	tenantB           = "/tenant-b"
	endUser           = "alice"
)

// clientSpec describes how a relying party authenticates at /token.
type clientSpec struct {
	id, secret string
	style      xoauth2.AuthStyle
}

var (
	basicClient  = clientSpec{basicClientID, basicClientSecret, xoauth2.AuthStyleInHeader}
	postClient   = clientSpec{postClientID, postClientSecret, xoauth2.AuthStyleInParams}
	publicClient = clientSpec{publicClientID, "", xoauth2.AuthStyleInParams}
)

// The keys are generated once: RSA-2048 is slow to generate.
var (
	rsaKeys = sync.OnceValue(func() []*rsa.PrivateKey {
		keys := make([]*rsa.PrivateKey, 7)

		for i := range keys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}

			keys[i] = k
		}

		return keys
	})
	ecKeys = sync.OnceValue(func() []*ecdsa.PrivateKey {
		keys := make([]*ecdsa.PrivateKey, 0, 2)

		for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
			k, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				panic(err)
			}

			keys = append(keys, k)
		}

		return keys
	})
)

// signingKey returns RS256 signing key i of rsaKeys under kid.
func signingKey(i int, kid string) jwtsec.PrivateKey {
	return jwtsec.PrivateKey{KeyID: kid, Algorithm: jwtsec.RS256, Key: rsaKeys()[i]}
}

// algorithmRing signs with RS256 and with every algorithm of
// signingAlgorithms: one key per algorithm (RFC 8725 §3.1).
func algorithmRing() oidcprovider.KeyRing {
	return oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{
		signingKey(0, "root-1"),
		{KeyID: "root-ps256", Algorithm: jwtsec.PS256, Key: rsaKeys()[4]},
		{KeyID: "root-rs512", Algorithm: jwtsec.RS512, Key: rsaKeys()[5]},
		{KeyID: "root-es256", Algorithm: jwtsec.ES256, Key: ecKeys()[0]},
		{KeyID: "root-es384", Algorithm: jwtsec.ES384, Key: ecKeys()[1]},
	}}
}

// signingAlgorithms are the ID Token algorithms clients register besides
// RS256 (Registration §2 id_token_signed_response_alg); client
// "rp-<alg>" registers alg.
var signingAlgorithms = []jwtsec.Algorithm{jwtsec.PS256, jwtsec.RS512, jwtsec.ES256, jwtsec.ES384}

// accessTokenKey signs the RFC 9068 access tokens of withJWTAccessTokens.
func accessTokenKey() jwtsec.PrivateKey {
	return jwtsec.PrivateKey{KeyID: "access-tokens", Algorithm: jwtsec.RS256, Key: rsaKeys()[6]}
}

// op is an OpenID Provider on a TLS test server: the root issuer (the
// server URL) and two path issuers, each with its own keys. Its clock runs
// ahead of the wall clock by offset (nanoseconds).
type op struct {
	srv    *httptest.Server
	issuer string
	keys   *issuerKeys
	login  *autoLogin
	offset atomic.Int64
}

// now is the provider's clock.
func (o *op) now() time.Time { return time.Now().Add(time.Duration(o.offset.Load())) }

// advance moves the provider's clock forward by d.
func (o *op) advance(d time.Duration) { o.offset.Add(int64(d)) }

// opOption changes the provider newOP builds.
type opOption func(t *testing.T, o *op, gcfg *grant.Config)

// withJWTAccessTokens issues RFC 9068 JWT access tokens, signed by a key
// the root issuer publishes in its JWK Set.
func withJWTAccessTokens() opOption {
	return func(t *testing.T, o *op, gcfg *grant.Config) {
		t.Helper()

		signer, err := jwtsec.NewOAuth2AccessTokenSigner(accessTokenKey())
		require.NoError(t, err)

		gcfg.AccessTokens = token.NewJWTAccessTokenGenerator(signer)

		pub, err := accessTokenKey().Public()
		require.NoError(t, err)

		ring, err := o.keys.Keys(t.Context(), o.issuer)
		require.NoError(t, err)

		ring.Published = append(ring.Published, pub)
		o.keys.set(o.issuer, ring)
	}
}

func newOP(t *testing.T, opts ...opOption) *op {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	o := &op{srv: srv, issuer: srv.URL, keys: &issuerKeys{rings: map[string]oidcprovider.KeyRing{}}}
	o.login = &autoLogin{now: o.now, authTime: o.now()}
	o.keys.set(o.issuer, oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingKey(0, "root-1")}})
	o.keys.set(o.issuer+tenantA, oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingKey(2, "tenant-a")}})
	o.keys.set(o.issuer+tenantB, oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingKey(3, "tenant-b")}})

	store := memory.New()
	gcfg := grant.Config{
		Storage:           store,
		AccessTokens:      token.NewOpaque(32),
		RefreshTokens:     token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:         time.Hour,
		RefreshTTL:        24 * time.Hour,
		RefreshTokenScope: oidcprovider.ScopeOfflineAccess,
	}

	for _, opt := range opts {
		opt(t, o, &gcfg)
	}

	provider, err := oidcprovider.New(oauth2.ServerConfig{
		Storage:        store,
		ClientStore:    clients(),
		IssuerResolver: pathIssuers{base: srv.URL},
		Now:            o.now,
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg)},
	}, oidcprovider.Config{Keys: o.keys, Claims: claimsOf{}, Interaction: o.login})
	require.NoError(t, err)

	for _, issuer := range []string{o.issuer, o.issuer + tenantA, o.issuer + tenantB} {
		mount(t, mux, provider, issuer)
	}

	return o
}

// mount mounts every endpoint of issuer where Paths says.
func mount(t *testing.T, mux *http.ServeMux, p *oidcprovider.Provider, issuer string) {
	t.Helper()

	paths, err := p.Paths(issuer)
	require.NoError(t, err)

	srv := p.Server()
	authorize := p.AuthorizeHandler(oauth2.AuthorizeConfig{})

	mux.Handle("GET "+paths.Authorize, authorize)
	mux.Handle("POST "+paths.Authorize, authorize)
	mux.Handle("POST "+paths.Token, srv.TokenHandler())
	mux.Handle("POST "+paths.Revoke, srv.RevokeHandler())
	mux.Handle("POST "+paths.Introspect, srv.IntrospectHandler())
	mux.Handle(paths.UserInfo, p.UserInfoHandler())
	mux.Handle("GET "+paths.Discovery, p.DiscoveryHandler())
	mux.Handle("GET "+paths.Metadata, srv.MetadataHandler())
	mux.Handle("GET "+paths.JWKS, p.JWKSHandler())
}

// pathIssuers resolves the issuer of a request from its path: a tenant
// path issuer, or the root issuer.
type pathIssuers struct{ base string }

func (p pathIssuers) Resolve(_ context.Context, r *http.Request) (string, string, error) {
	for _, tenant := range []string{tenantA, tenantB} {
		if strings.HasPrefix(r.URL.Path, tenant+"/") || r.URL.Path == "/.well-known/oauth-authorization-server"+tenant {
			return p.base + tenant, "api", nil
		}
	}

	return p.base, "api", nil
}

// issuerKeys is a KeySource with one ring per issuer, swapped by tests.
type issuerKeys struct {
	mu    sync.Mutex
	rings map[string]oidcprovider.KeyRing
}

func (k *issuerKeys) set(issuer string, ring oidcprovider.KeyRing) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.rings[issuer] = ring
}

func (k *issuerKeys) Keys(_ context.Context, issuer string) (oidcprovider.KeyRing, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	ring, ok := k.rings[issuer]
	if !ok {
		return oidcprovider.KeyRing{}, fmt.Errorf("no keys for %s", issuer)
	}

	return oidcprovider.KeyRing{Signing: slices.Clone(ring.Signing), Published: slices.Clone(ring.Published)}, nil
}

// autoLogin is the end-user agent: a browser whose session authenticated
// alice when the provider started. An interactive request the session
// does not satisfy (Request.Check: prompt=login, max_age) makes her
// authenticate again. She agrees to everything requested — every claim of
// the claims parameter, offline access when the consent dialog was asked
// for — unless a test narrows what she grants. A silent request is
// answered from the session as it is, leaving it to the provider to refuse
// a stale one or another end-user's; signed out, login_required.
type autoLogin struct {
	now       func() time.Time
	signedOut atomic.Bool

	mu       sync.Mutex
	authTime time.Time // when the session's end-user authenticated
	subject  string    // the session's end-user; "" is alice
	claims   []string  // the claims she releases; nil: every requested one
	scope    string    // the scope she grants; "": the requested one
}

func (a *autoLogin) Authorize(_ http.ResponseWriter, _ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	ev := a.event(req)
	if req.Check(ev, time.Time{}) != nil {
		a.authTime = a.now() // she authenticates again
		ev.AuthTime = a.authTime
	}

	return a.approve(req, ev), nil
}

func (a *autoLogin) AuthorizeSilently(_ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	if a.signedOut.Load() {
		return &oidcprovider.Decision{Refusal: oauth2.ErrLoginRequired}, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	return a.approve(req, a.event(req)), nil
}

// set changes the session and what she grants.
func (a *autoLogin) set(edit func(*autoLogin)) {
	a.mu.Lock()
	defer a.mu.Unlock()

	edit(a)
}

// event is the session's authentication.
func (a *autoLogin) event(req *oidcprovider.Request) oidcprovider.AuthenticationEvent {
	subject := a.subject
	if subject == "" {
		subject = endUser
	}

	return oidcprovider.AuthenticationEvent{Issuer: req.Issuer, Subject: subject, AuthTime: a.authTime, AMR: []string{"pwd"}}
}

func (a *autoLogin) approve(req *oidcprovider.Request, ev oidcprovider.AuthenticationEvent) *oidcprovider.Decision {
	d := &oidcprovider.Decision{Authentication: &ev, Scope: a.scope, Claims: slices.Clone(a.claims)}

	if a.claims == nil {
		for _, c := range append(slices.Clone(req.Claims.IDToken), req.Claims.UserInfo...) {
			d.Claims = append(d.Claims, c.Name)
		}
	}

	if req.OfflineAccess && req.Prompt.Consent {
		d.OfflineAccess = oidcprovider.OfflineAccessPrompted
	}

	return d
}

// claimsOf is the ClaimsSource: alice only.
type claimsOf struct{}

func (claimsOf) Claims(_ context.Context, q oidcprovider.ClaimsQuery) (map[string]any, error) {
	if q.Subject != endUser {
		return nil, oidcprovider.ErrUnknownSubject
	}

	return map[string]any{
		"name": "Alice Liddell", "email": "alice@example.com", "email_verified": true,
		"phone_number": "+33 1 23 45 67 89", "phone_number_verified": true,
	}, nil
}

// signingClient is a DefaultClient registering an ID Token algorithm.
type signingClient struct {
	*oauth2.DefaultClient

	alg jwtsec.Algorithm
}

func (c signingClient) IDTokenSignedResponseAlg() jwtsec.Algorithm { return c.alg }

// signingClientID is the client registering alg.
func signingClientID(alg jwtsec.Algorithm) string { return "rp-" + strings.ToLower(string(alg)) }

// staticClients is the ClientStore.
type staticClients map[string]oauth2.Client

func (s staticClients) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	return s[id], nil
}

func clients() staticClients {
	scopes := []string{"openid", "profile", "email", "offline_access"}
	grants := []string{"authorization_code", "refresh_token"}

	registered := staticClients{
		basicClientID: &oauth2.DefaultClient{
			IDValue: basicClientID, Secret: basicClientSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{redirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
			AuthMethodValues: []string{"client_secret_basic"},
		},
		postClientID: &oauth2.DefaultClient{
			IDValue: postClientID, Secret: postClientSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{redirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
			AuthMethodValues: []string{"client_secret_post"},
		},
		publicClientID: &oauth2.DefaultClient{
			IDValue: publicClientID, TypeValue: oauth2.ClientPublic,
			RedirectURIValues: []string{redirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
			AuthMethodValues: []string{"none"},
		},
	}

	for _, alg := range signingAlgorithms {
		registered[signingClientID(alg)] = signingClient{alg: alg, DefaultClient: &oauth2.DefaultClient{
			IDValue: signingClientID(alg), Secret: signingSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{redirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
			AuthMethodValues: []string{"client_secret_basic"},
		}}
	}

	return registered
}

// rp is a go-oidc + x/oauth2 relying party of one issuer.
type rp struct {
	issuer   string
	ctx      context.Context //nolint:containedctx // the go-oidc client context of the test
	provider *oidc.Provider
	config   xoauth2.Config
	verifier *oidc.IDTokenVerifier
	browser  *http.Client
}

// newRP discovers issuer — go-oidc requires the exact issuer — and
// registers as client with scopes (openid profile email by default).
func newRP(t *testing.T, o *op, issuer string, client clientSpec, scopes ...string) *rp {
	t.Helper()

	ctx := oidc.ClientContext(t.Context(), o.srv.Client())

	provider, err := oidc.NewProvider(ctx, issuer)
	require.NoError(t, err)

	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	endpoint := provider.Endpoint()
	endpoint.AuthStyle = client.style

	browser := *o.srv.Client()
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &rp{
		issuer: issuer, ctx: ctx, provider: provider,
		config: xoauth2.Config{
			ClientID: client.id, ClientSecret: client.secret, Endpoint: endpoint, RedirectURL: redirectURI, Scopes: scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: client.id}),
		browser:  &browser,
	}
}

// authorize sends the end-user's browser to the authorization endpoint and
// returns the parameters of the redirect back to the client.
func (r *rp) authorize(t *testing.T, opts ...xoauth2.AuthCodeOption) url.Values {
	t.Helper()

	resp, err := r.browser.Get(r.config.AuthCodeURL("state-1", opts...))
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, redirectURI, loc.Scheme+"://"+loc.Host+loc.Path)

	return loc.Query()
}

// flow runs the authorization code flow with S256 PKCE and a nonce, and
// verifies what an RP must: state, iss (RFC 9207), the ID Token (signature
// through the JWK Set, iss, aud, exp), its nonce and its at_hash.
func (r *rp) flow(t *testing.T, opts ...xoauth2.AuthCodeOption) (*xoauth2.Token, string, *oidc.IDToken) {
	t.Helper()

	verifier, nonce := xoauth2.GenerateVerifier(), randomNonce()
	params := r.authorize(t, append([]xoauth2.AuthCodeOption{xoauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}, opts...)...)
	require.Empty(t, params.Get("error"), params.Get("error_description"))
	require.Equal(t, "state-1", params.Get("state"))
	require.Equal(t, r.issuer, params.Get("iss"), "RFC 9207")

	tok, err := r.config.Exchange(r.ctx, params.Get("code"), xoauth2.VerifierOption(verifier))
	require.NoError(t, err)

	raw, ok := tok.Extra("id_token").(string)
	require.True(t, ok, "an id_token in the token response")

	idToken, err := r.verifier.Verify(r.ctx, raw)
	require.NoError(t, err)
	require.Equal(t, nonce, idToken.Nonce)
	require.NoError(t, idToken.VerifyAccessToken(tok.AccessToken))

	return tok, raw, idToken
}

func randomNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}
