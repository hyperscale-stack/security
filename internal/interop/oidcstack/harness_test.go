// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
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

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	clientmemory "github.com/hyperscale-stack/security/oidc/client/storage/memory"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/require"
)

// The issuers of the provider under test, relative to its origin: the
// root issuer, two tenants, and a tenant whose issuer ends with a slash.
const (
	tenantA = "/tenant-a"
	tenantB = "/tenant-b"
	tenantC = "/tenant-c/"
)

// The end-users the provider knows.
const (
	alice = "alice"
	bob   = "bob"
)

const (
	rpOrigin    = "https://rp.example"
	apiAudience = "api"
)

// transactionKey is the relying parties' transaction key.
var transactionKey = []byte("oidcstack transaction key, 32+ bytes")

// The keys are generated once: RSA-2048 is slow to generate.
var (
	rsaKeys = sync.OnceValue(func() []*rsa.PrivateKey {
		keys := make([]*rsa.PrivateKey, 12)
		for i := range keys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}

			keys[i] = k
		}

		return keys
	})
	ecKeys = sync.OnceValue(func() map[elliptic.Curve]*ecdsa.PrivateKey {
		keys := map[elliptic.Curve]*ecdsa.PrivateKey{}
		for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
			k, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				panic(err)
			}

			keys[c] = k
		}

		return keys
	})
)

// rsaKey returns RSA key i of rsaKeys for alg under kid.
func rsaKey(i int, alg jwtsec.Algorithm, kid string) jwtsec.PrivateKey {
	return jwtsec.PrivateKey{KeyID: kid, Algorithm: alg, Key: rsaKeys()[i]}
}

// rootRing signs with every algorithm a client may register: one key per
// algorithm (RFC 8725 §3.1), RS256 mandatory.
func rootRing() oidcprovider.KeyRing {
	ec := ecKeys()

	return oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{
		rsaKey(0, jwtsec.RS256, "root-rs256"),
		rsaKey(1, jwtsec.RS384, "root-rs384"),
		rsaKey(2, jwtsec.RS512, "root-rs512"),
		rsaKey(3, jwtsec.PS256, "root-ps256"),
		rsaKey(4, jwtsec.PS384, "root-ps384"),
		rsaKey(5, jwtsec.PS512, "root-ps512"),
		{KeyID: "root-es256", Algorithm: jwtsec.ES256, Key: ec[elliptic.P256()]},
		{KeyID: "root-es384", Algorithm: jwtsec.ES384, Key: ec[elliptic.P384()]},
		{KeyID: "root-es512", Algorithm: jwtsec.ES512, Key: ec[elliptic.P521()]},
	}}
}

// tenantRing is the ring of a tenant: its own RS256 key.
func tenantRing(i int, kid string) oidcprovider.KeyRing {
	return oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{rsaKey(i, jwtsec.RS256, kid)}}
}

// clock is the clock of a provider and of its relying parties: the wall
// clock shifted by an offset the tests move forward.
type clock struct{ offset atomic.Int64 }

func (c *clock) now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }

func (c *clock) advance(d time.Duration) { c.offset.Add(int64(d)) }

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

func (k *issuerKeys) get(issuer string) oidcprovider.KeyRing {
	k.mu.Lock()
	defer k.mu.Unlock()

	return k.rings[issuer]
}

func (k *issuerKeys) Keys(_ context.Context, issuer string) (oidcprovider.KeyRing, error) {
	ring := k.get(issuer)
	if len(ring.Signing) == 0 {
		return oidcprovider.KeyRing{}, fmt.Errorf("no keys for %s", issuer)
	}

	return oidcprovider.KeyRing{Signing: slices.Clone(ring.Signing), Published: slices.Clone(ring.Published)}, nil
}

// registration is a client registered at the provider.
type registration struct {
	id, secret string
	method     string   // client_secret_basic, client_secret_post or none
	issuers    []string // the issuers it is bound to (IssuerValues); nil: every issuer
	redirects  []string
	alg        jwtsec.Algorithm // id_token_signed_response_alg, "" for RS256
}

// signingClient is a DefaultClient registering an ID Token algorithm.
type signingClient struct {
	*oauth2.DefaultClient

	alg jwtsec.Algorithm
}

func (c signingClient) IDTokenSignedResponseAlg() jwtsec.Algorithm { return c.alg }

func (r registration) client() oauth2.Client {
	c := &oauth2.DefaultClient{
		IDValue: r.id, Secret: r.secret, TypeValue: oauth2.ClientConfidential,
		RedirectURIValues: r.redirects, IssuerValues: r.issuers,
		GrantTypeValues:  []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken},
		ScopeValues:      []string{"openid", "profile", "email", "offline_access"},
		AuthMethodValues: []string{r.method},
	}

	if r.method == "none" {
		c.TypeValue = oauth2.ClientPublic
	}

	if r.alg != "" {
		return signingClient{DefaultClient: c, alg: r.alg}
	}

	return c
}

// staticClients is the provider's ClientStore.
type staticClients struct {
	mu      sync.Mutex
	clients map[string]oauth2.Client
}

func (s *staticClients) add(r registration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[r.id] = r.client()
}

func (s *staticClients) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.clients[id], nil
}

// script is the Interaction: an end-user agent that authenticates and
// consents as the test configures it. By default it authenticates alice in
// the request's realm at the current time, releases every requested claim,
// grants a requested offline_access when the consent dialog was asked for,
// and answers prompt=none from a session.
type script struct {
	clock *clock

	mu        sync.Mutex
	subject   string        // the end-user of the session
	realm     string        // the realm of the session; "" = the request's issuer
	authAge   time.Duration // the session's authentication is this old
	acr       string
	deny      bool  // the end-user denies the request
	refusal   error // the application refuses with this error
	scope     string
	signedOut bool // no session: prompt=none answers login_required
	requests  []oidcprovider.Request
}

func (s *script) decide(req *oidcprovider.Request, silent bool) (*oidcprovider.Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.requests = append(s.requests, *req)

	switch {
	case silent && s.signedOut:
		return &oidcprovider.Decision{Refusal: oauth2.ErrLoginRequired}, nil
	case s.refusal != nil:
		return &oidcprovider.Decision{Refusal: s.refusal}, nil
	case s.deny:
		return &oidcprovider.Decision{}, nil
	}

	realm := s.realm
	if realm == "" {
		realm = req.Issuer
	}

	subject := s.subject
	if req.LoginHint == alice || req.LoginHint == bob {
		subject = req.LoginHint // the end-user the relying party hinted at signs in
	}

	d := &oidcprovider.Decision{
		Authentication: &oidcprovider.AuthenticationEvent{
			Issuer: realm, Subject: subject, AuthTime: s.clock.now().Add(-s.authAge), ACR: s.acr, AMR: []string{"pwd"},
		},
		Scope: s.scope,
	}

	for _, c := range append(slices.Clone(req.Claims.IDToken), req.Claims.UserInfo...) {
		d.Claims = append(d.Claims, c.Name)
	}

	if req.OfflineAccess && req.Prompt.Consent {
		d.OfflineAccess = oidcprovider.OfflineAccessPrompted
	}

	return d, nil
}

func (s *script) Authorize(_ http.ResponseWriter, _ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	return s.decide(req, false)
}

func (s *script) AuthorizeSilently(_ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	return s.decide(req, true)
}

func (s *script) set(f func(*script)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f(s)
}

// lastRequest returns the last request the Interaction saw.
func (s *script) lastRequest(t *testing.T) oidcprovider.Request {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	require.NotEmpty(t, s.requests, "the Interaction was reached")

	return s.requests[len(s.requests)-1]
}

// people is the ClaimsSource: alice and bob, until disabled.
type people struct {
	mu       sync.Mutex
	disabled map[string]bool
}

func (p *people) Claims(_ context.Context, q oidcprovider.ClaimsQuery) (map[string]any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if (q.Subject != alice && q.Subject != bob) || p.disabled[q.Subject] {
		return nil, oidcprovider.ErrUnknownSubject
	}

	name := strings.ToUpper(q.Subject[:1]) + q.Subject[1:]

	return map[string]any{
		"name": name + " Liddell", "given_name": name, "family_name": "Liddell",
		"email": q.Subject + "@example.com", "email_verified": true,
	}, nil
}

// op is our OpenID Provider on a TLS test server, behind the faults
// middleware.
type op struct {
	t        *testing.T
	srv      *httptest.Server
	base     string
	clock    *clock
	keys     *issuerKeys
	enduser  *script
	users    *people
	clients  *staticClients
	store    *faultyStorage
	faults   *faults
	provider *oidcprovider.Provider
	errs     *errorLog
	resolver *pathIssuers
}

// opConfig configures newOP.
type opConfig struct {
	profile         oauth2.Profile
	jwtAccessTokens bool
	sharedRing      bool // one key ring for every issuer
}

// issuers returns the four issuers of o.
func (o *op) issuers() []string {
	return []string{o.base, o.base + tenantA, o.base + tenantB, o.base + tenantC}
}

// issuer returns the issuer of the tenant path ("" for the root).
func (o *op) issuer(tenant string) string { return o.base + tenant }

// paths returns the Paths of issuer.
func (o *op) paths(issuer string) oidcprovider.Paths {
	p, err := o.provider.Paths(issuer)
	if err != nil {
		panic(err) // the issuers of the harness are valid
	}

	return p
}

// errorLog records what reaches the server's ErrorHook.
type errorLog struct {
	mu   sync.Mutex
	errs []error
}

func (l *errorLog) hook(_ context.Context, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.errs = append(l.errs, err)
}

// pathIssuers resolves the issuer of a request from its path; it can be
// made to fail at the authorization endpoint.
type pathIssuers struct {
	base          string
	failAuthorize atomic.Bool
}

var errResolver = errors.New("issuer resolver unavailable")

func (p *pathIssuers) Resolve(_ context.Context, r *http.Request) (string, string, error) {
	if p.failAuthorize.Load() && strings.HasSuffix(r.URL.Path, "/authorize") {
		return "", "", errResolver
	}

	for _, tenant := range []string{tenantA, tenantB, tenantC} {
		prefix := strings.TrimSuffix(tenant, "/")
		if strings.HasPrefix(r.URL.Path, prefix+"/") || strings.HasPrefix(r.URL.Path, "/.well-known/oauth-authorization-server"+prefix) {
			return p.base + tenant, apiAudience, nil
		}
	}

	return p.base, apiAudience, nil
}

// newOP starts our provider with its default registrations (see
// defaultRegistrations).
func newOP(t *testing.T, opts ...func(*opConfig)) *op {
	t.Helper()

	var cfg opConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	o := &op{
		t: t, srv: srv, base: srv.URL, clock: &clock{},
		keys:    &issuerKeys{rings: map[string]oidcprovider.KeyRing{}},
		users:   &people{disabled: map[string]bool{}},
		clients: &staticClients{clients: map[string]oauth2.Client{}},
		store:   &faultyStorage{Store: memory.New()},
		errs:    &errorLog{},
	}
	o.resolver = &pathIssuers{base: o.base}
	o.enduser = &script{clock: o.clock, subject: alice}

	o.keys.set(o.base, rootRing())
	o.keys.set(o.base+tenantA, tenantRing(6, "tenant-a"))
	o.keys.set(o.base+tenantB, tenantRing(7, "tenant-b"))
	o.keys.set(o.base+tenantC, tenantRing(8, "tenant-c"))

	if cfg.sharedRing {
		for _, issuer := range o.issuers()[1:] {
			o.keys.set(issuer, tenantRing(6, "shared"))
		}
	}

	for _, r := range defaultRegistrations(o) {
		o.clients.add(r)
	}

	gcfg := grant.Config{
		Storage:           o.store,
		AccessTokens:      token.NewOpaque(32),
		RefreshTokens:     token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:         time.Hour,
		RefreshTTL:        24 * time.Hour,
		RefreshTokenScope: oidcprovider.ScopeOfflineAccess,
	}

	if cfg.jwtAccessTokens {
		signer, err := jwtsec.NewOAuth2AccessTokenSigner(rsaKey(9, jwtsec.RS256, "access-tokens"))
		require.NoError(t, err)

		gcfg.AccessTokens = token.NewJWTAccessTokenGenerator(signer)
	}

	provider, err := oidcprovider.New(oauth2.ServerConfig{
		Profile:        cfg.profile,
		Storage:        o.store,
		ClientStore:    o.clients,
		IssuerResolver: o.resolver,
		Now:            o.clock.now,
		OnError:        o.errs.hook,
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg)},
	}, oidcprovider.Config{Keys: o.keys, Claims: o.users, Interaction: o.enduser})
	require.NoError(t, err)

	o.provider = provider

	if cfg.jwtAccessTokens {
		// The access-token key is published by the root issuer (RFC 9068
		// §4: one jwks_uri).
		ring := o.keys.get(o.base)
		pub, err := rsaKey(9, jwtsec.RS256, "access-tokens").Public()
		require.NoError(t, err)

		ring.Published = append(ring.Published, pub)
		o.keys.set(o.base, ring)
	}

	mux := http.NewServeMux()
	for _, issuer := range o.issuers() {
		o.mount(mux, issuer)
	}

	o.faults = newFaults(mux)
	srv.Config.Handler = o.faults

	return o
}

// mount mounts every endpoint of issuer where Paths says.
func (o *op) mount(mux *http.ServeMux, issuer string) {
	p := o.paths(issuer)
	srv := o.provider.Server()
	authorize := o.provider.AuthorizeHandler(oauth2.AuthorizeConfig{})

	mux.Handle("GET "+p.Authorize, authorize)
	mux.Handle("POST "+p.Authorize, authorize)
	mux.Handle("POST "+p.Token, srv.TokenHandler())
	mux.Handle("POST "+p.Revoke, srv.RevokeHandler())
	mux.Handle("POST "+p.Introspect, srv.IntrospectHandler())
	mux.Handle(p.UserInfo, o.provider.UserInfoHandler())
	mux.Handle("GET "+p.Discovery, o.provider.DiscoveryHandler())
	mux.Handle("GET "+p.JWKS, o.provider.JWKSHandler())
}

// pool trusts o's certificate.
func (o *op) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(o.srv.Certificate())

	return pool
}

// The client registrations of every provider, one per connection: each
// with the redirect URI of its connection only, bound to its issuer.
const (
	basicID     = "rp client%+:/=" // every character RFC 6749 §2.3.1 encodes
	basicSecret = "s3cr%t +:/=é"
	postID      = "rp-post"
	postSecret  = "post-secret"
	publicID    = "rp-public"
	tenantAID   = "rp-tenant-a"
	tenantBID   = "rp-tenant-b"
	tenantCID   = "rp-tenant-c"
	sharedID    = "rp-shared" // unbound: registered at every issuer
	otherID     = "rp-other"
	secret      = "client-secret"
)

// callback is the redirect URI of a connection.
func callback(connection string) string { return rpOrigin + "/oidc/" + connection + "/callback" }

func defaultRegistrations(o *op) []registration {
	root := []string{o.base}
	regs := []registration{
		{id: basicID, secret: basicSecret, method: "client_secret_basic", issuers: root, redirects: []string{callback("basic")}},
		{id: postID, secret: postSecret, method: "client_secret_post", issuers: root, redirects: []string{callback("post")}},
		{id: publicID, method: "none", issuers: root, redirects: []string{callback("public")}},
		{id: otherID, secret: secret, method: "client_secret_basic", issuers: root, redirects: []string{callback("other")}},
		{id: tenantAID, secret: secret, method: "client_secret_basic", issuers: []string{o.base + tenantA}, redirects: []string{callback("tenant-a")}},
		{id: tenantBID, secret: secret, method: "client_secret_basic", issuers: []string{o.base + tenantB}, redirects: []string{callback("tenant-b")}},
		{id: tenantCID, secret: secret, method: "client_secret_basic", issuers: []string{o.base + tenantC}, redirects: []string{callback("tenant-c")}},
		{id: sharedID, secret: secret, method: "client_secret_basic", redirects: []string{
			callback("shared-root"), callback("shared-a"), callback("shared-b"),
		}},
	}

	for _, alg := range []jwtsec.Algorithm{
		jwtsec.RS256, jwtsec.RS384, jwtsec.RS512, jwtsec.PS256, jwtsec.PS384, jwtsec.PS512,
		jwtsec.ES256, jwtsec.ES384, jwtsec.ES512,
	} {
		regs = append(regs, registration{
			id: "rp-" + strings.ToLower(string(alg)), secret: secret, method: "client_secret_basic", issuers: root,
			redirects: []string{callback(strings.ToLower(string(alg)))}, alg: alg,
		})
	}

	return regs
}

// connection is a relying-party connection to o: one oidcclient.Client.
type connection struct {
	name, issuer, clientID, secret string
	method                         oidcclient.AuthMethod
}

// conn returns the connection named name to issuer for the registration
// id/secret/method.
func conn(name, issuer, id, sec string, method oidcclient.AuthMethod) connection {
	return connection{name: name, issuer: issuer, clientID: id, secret: sec, method: method}
}

// rp builds the Client of c, modified by the mutators.
func (o *op) rp(t *testing.T, c connection, mutators ...func(*oidcclient.Config)) *oidcclient.Client {
	t.Helper()

	client, err := oidcclient.New(t.Context(), o.config(c, mutators...))
	require.NoError(t, err)

	return client
}

// config is the Config of c, modified by the mutators.
func (o *op) config(c connection, mutators ...func(*oidcclient.Config)) oidcclient.Config {
	cfg := oidcclient.Config{
		ConnectionID:    c.name,
		Issuer:          c.issuer,
		ClientID:        c.clientID,
		ClientSecret:    oidcclient.NewSecret(c.secret),
		AuthMethod:      c.method,
		RedirectURL:     callback(c.name),
		Scopes:          []string{"openid", "profile", "email"},
		Store:           clientmemory.New(),
		TransactionKeys: []oidcclient.Secret{oidcclient.NewSecret(string(transactionKey))},
		Outbound:        outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: o.pool(), Timeout: 2 * time.Second},
		Now:             o.clock.now,
	}

	for _, m := range mutators {
		m(&cfg)
	}

	return cfg
}

// The usual connections.
func (o *op) basic() connection {
	return conn("basic", o.base, basicID, basicSecret, oidcclient.AuthMethodClientSecretBasic)
}

func (o *op) tenant(path, id string) connection {
	return conn(strings.Trim(path, "/"), o.base+path, id, secret, oidcclient.AuthMethodClientSecretBasic)
}

// browser is the user agent: it never follows a redirect, so the tests see
// every hop.
func (o *op) browser() *http.Client {
	c := *o.srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &c
}

// authorize sends the user agent to authURL and returns the response.
func (o *op) authorize(t *testing.T, authURL string) *http.Response {
	t.Helper()

	resp, err := o.browser().Get(authURL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	return resp
}

// redirected returns the URL the provider sent the user agent back to.
func redirected(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()

	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, resp.StatusCode, "a redirect back to the relying party")

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	return loc
}

// callbackOf is the callback the user agent delivers for the response at
// loc, presenting binding.
func callbackOf(loc *url.URL, binding oidcclient.Secret) oidcclient.Callback {
	return oidcclient.Callback{Mode: oidcclient.ResponseModeQuery, URL: loc, Params: loc.Query(), Binding: binding}
}

// begin starts a login of c and authorizes it at the provider.
func (o *op) begin(t *testing.T, c *oidcclient.Client, opts oidcclient.AuthOptions) (*oidcclient.AuthRequest, *url.URL) {
	t.Helper()

	ar, err := c.Begin(t.Context(), opts)
	require.NoError(t, err)

	loc := redirected(t, o.authorize(t, ar.URL))
	require.Equal(t, "_", loc.Fragment, "the provider's query-mode responses end with #_ (RFC 9700 §4.1.3)")

	return ar, loc
}

// login runs a whole login of c.
func (o *op) login(t *testing.T, c *oidcclient.Client, opts oidcclient.AuthOptions) (*oidcclient.Identity, error) {
	t.Helper()

	ar, loc := o.begin(t, c, opts)

	return c.Complete(t.Context(), callbackOf(loc, ar.Binding))
}

// hits returns how many requests path received.
func (o *op) hits(path string) int { return o.faults.count(path) }

// faultyStorage is the provider's storage, with injectable failures.
type faultyStorage struct {
	*memory.Store

	mu         sync.Mutex
	failSave   error // SaveAuthorizationCode
	failPair   error // SaveTokenPair
	failLookup error // LookupAccessToken
}

func (s *faultyStorage) failures() (save, pair, lookup error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.failSave, s.failPair, s.failLookup
}

func (s *faultyStorage) SaveAuthorizationCode(ctx context.Context, code *oauth2.AuthorizationCode) error {
	if err, _, _ := s.failures(); err != nil {
		return err
	}

	return s.Store.SaveAuthorizationCode(ctx, code) //nolint:wrapcheck // test double
}

func (s *faultyStorage) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	if _, err, _ := s.failures(); err != nil {
		return err
	}

	return s.Store.SaveTokenPair(ctx, pair) //nolint:wrapcheck // test double
}

func (s *faultyStorage) LookupAccessToken(ctx context.Context, hash string) (*oauth2.AccessToken, error) {
	if _, _, err := s.failures(); err != nil {
		return nil, err
	}

	return s.Store.LookupAccessToken(ctx, hash) //nolint:wrapcheck // test double
}

var errStorageDown = errors.New("storage unavailable")
