// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
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
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer = "https://op.example"

	webClientID     = "web-app"
	webClientSecret = "web-secret-0123456789"
	webRedirectURI  = "https://rp.example/cb"

	spaClientID    = "spa-app"
	spaRedirectURI = "https://spa.example/cb"

	es256ClientID = "es256-app"

	// RFC 7636 Appendix B PKCE pair.
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// Test keys, generated once: RSA generation is slow.
var (
	rsaKeyA *rsa.PrivateKey
	rsaKeyB *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	ec384   *ecdsa.PrivateKey
	ec521   *ecdsa.PrivateKey
	rsa1024 *rsa.PrivateKey
)

func TestMain(m *testing.M) {
	var err error

	rsaKeyA, err = rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	rsaKeyB, err = rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	ec384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	must(err)
	ec521, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	must(err)
	//nolint:gosec // G403: a deliberately undersized key, refused by the code under test
	rsa1024, err = rsa.GenerateKey(rand.Reader, 1024)
	must(err)

	os.Exit(m.Run())
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// signingRSA is RS256 key A, the default signing key.
func signingRSA() jwtsec.PrivateKey {
	return jwtsec.PrivateKey{KeyID: "rsa-a", Algorithm: jwtsec.RS256, Key: rsaKeyA}
}

func signingRSAB() jwtsec.PrivateKey {
	return jwtsec.PrivateKey{KeyID: "rsa-b", Algorithm: jwtsec.RS256, Key: rsaKeyB}
}

func signingEC() jwtsec.PrivateKey {
	return jwtsec.PrivateKey{KeyID: "ec-1", Algorithm: jwtsec.ES256, Key: ecKey}
}

func publicOf(k jwtsec.PrivateKey) jwtsec.PublicKey {
	pub, err := k.Public()
	must(err)

	return pub
}

// defaultRing is RS256 + ES256 signing keys.
func defaultRing() oidcprovider.KeyRing {
	return oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSA(), signingEC()}}
}

// mutableKeys is a KeySource whose ring tests swap atomically (rotation),
// per issuer, or make fail.
type mutableKeys struct {
	ring  atomic.Pointer[oidcprovider.KeyRing]
	err   atomic.Pointer[error]
	calls atomic.Int32

	mu       sync.Mutex
	perIssue map[string]oidcprovider.KeyRing
}

func newMutableKeys(r oidcprovider.KeyRing) *mutableKeys {
	k := &mutableKeys{perIssue: map[string]oidcprovider.KeyRing{}}
	k.set(r)

	return k
}

func (k *mutableKeys) set(r oidcprovider.KeyRing) { k.ring.Store(&r) }

func (k *mutableKeys) fail(err error) { k.err.Store(&err) }

func (k *mutableKeys) setFor(issuer string, r oidcprovider.KeyRing) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.perIssue[issuer] = r
}

func (k *mutableKeys) Keys(_ context.Context, issuer string) (oidcprovider.KeyRing, error) {
	k.calls.Add(1)

	if e := k.err.Load(); e != nil {
		return oidcprovider.KeyRing{}, *e
	}

	k.mu.Lock()
	r, ok := k.perIssue[issuer]
	k.mu.Unlock()

	if ok {
		return r, nil
	}

	return *k.ring.Load(), nil
}

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

// errorSink collects what the server hands its ErrorHook.
type errorSink struct {
	mu   sync.Mutex
	errs []error
}

func (s *errorSink) hook(_ context.Context, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.errs = append(s.errs, err)
}

func (s *errorSink) all() []error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.errs)
}

// contains reports whether some hooked error matches target.
func (s *errorSink) contains(target error) bool {
	for _, e := range s.all() {
		if errors.Is(e, target) {
			return true
		}
	}

	return false
}

// es256Client is a confidential client that registered
// id_token_signed_response_alg ES256.
type es256Client struct{ oauth2.DefaultClient }

func (es256Client) IDTokenSignedResponseAlg() jwtsec.Algorithm { return jwtsec.ES256 }

// staticClients is a map-backed ClientStore.
type staticClients map[string]oauth2.Client

func (s staticClients) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	c, ok := s[id]
	if !ok {
		return nil, nil
	}

	return c, nil
}

// The grant types the test clients declare: a client may use only those
// (an empty list allows none). The confidential web clients also run
// client_credentials and the legacy implicit flow in some tests.
var (
	webGrantTypes = []string{
		oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken,
		oauth2.GrantTypeClientCredentials, oauth2.GrantTypeImplicit,
	}
	spaGrantTypes = []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken}
)

func testClients() staticClients {
	scopes := []string{"openid", "profile", "email", "address", "phone", "offline_access", "read"}

	return staticClients{
		webClientID: &oauth2.DefaultClient{
			IDValue: webClientID, Secret: webClientSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{webRedirectURI}, ScopeValues: scopes, GrantTypeValues: webGrantTypes,
		},
		spaClientID: &oauth2.DefaultClient{
			IDValue: spaClientID, TypeValue: oauth2.ClientPublic, AuthMethodValues: []string{"none"},
			RedirectURIValues: []string{spaRedirectURI}, ScopeValues: scopes, GrantTypeValues: spaGrantTypes,
		},
		es256ClientID: &es256Client{oauth2.DefaultClient{
			IDValue: es256ClientID, Secret: webClientSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{webRedirectURI}, ScopeValues: scopes, GrantTypeValues: webGrantTypes,
		}},
	}
}

// hostIssuer resolves the issuer from the request's Host, "https://<host>",
// with "op.example" for an empty Host (httptest).
type hostIssuer struct{}

func (hostIssuer) Resolve(_ context.Context, r *http.Request) (string, string, error) {
	host := r.Host
	if host == "" || host == "example.com" {
		host = "op.example"
	}

	return "https://" + host, "api", nil
}

// fixedIssuer resolves to one issuer, possibly invalid.
type fixedIssuer struct {
	issuer string
	err    error
}

func (f fixedIssuer) Resolve(context.Context, *http.Request) (string, string, error) {
	return f.issuer, "api", f.err
}

// env is a provider over a memory store with the authorization_code,
// refresh_token (refresh tokens gated on offline_access) and
// client_credentials grants, the test clients, the injectable clock and
// error sink, mutable keys and scripted application fakes.
type env struct {
	t           *testing.T
	op          *oidcprovider.Provider
	store       *memory.Store
	storage     oauth2.Storage
	clock       *testClock
	sink        *errorSink
	keys        *mutableKeys
	interaction *fakeInteraction
	claims      *fakeClaims
}

type envOption func(*oauth2.ServerConfig, *grant.Config, *oidcprovider.Config)

// withStore shares store between environments (one deployment, two
// configurations).
func withStore(store *memory.Store) envOption {
	return func(s *oauth2.ServerConfig, g *grant.Config, _ *oidcprovider.Config) {
		s.Storage, g.Storage = store, store
	}
}

// withSpy wraps the memory store in a spy counting its writes.
func withSpy(spy *spyStore) envOption {
	return func(s *oauth2.ServerConfig, g *grant.Config, _ *oidcprovider.Config) {
		spy.Store = s.Storage.(*memory.Store) //nolint:forcetypeassert // the env's own store
		s.Storage, g.Storage = spy, spy
	}
}

// withClient registers one more client.
func withClient(c oauth2.Client) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) {
		clients := s.ClientStore.(staticClients) //nolint:forcetypeassert // the env's own store
		clients[c.ID()] = c
	}
}

func withResolver(r oauth2.IssuerResolver) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) { s.IssuerResolver = r }
}

func withProfile(p oauth2.Profile) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) { s.Profile = p }
}

func withRoutePrefix(prefix string) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) { s.RoutePrefix = prefix }
}

func withConfig(f func(*oidcprovider.Config)) envOption {
	return func(_ *oauth2.ServerConfig, _ *grant.Config, c *oidcprovider.Config) { f(c) }
}

func withGrantConfig(f func(*grant.Config)) envOption {
	return func(_ *oauth2.ServerConfig, g *grant.Config, _ *oidcprovider.Config) { f(g) }
}

// withoutRefreshGrant registers only authorization_code and
// client_credentials.
func withoutRefreshGrant() envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) { s.Grants = nil }
}

func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()

	e := &env{
		t: t, store: memory.New(), clock: newTestClock(), sink: &errorSink{},
		keys: newMutableKeys(defaultRing()), claims: newFakeClaims(),
	}
	e.interaction = newFakeInteraction(e.clock)

	gcfg := grant.Config{
		Storage:           e.store,
		AccessTokens:      token.NewOpaque(32),
		RefreshTokens:     token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:         time.Hour,
		RefreshTTL:        24 * time.Hour,
		RefreshTokenScope: oidcprovider.ScopeOfflineAccess,
		OnError:           e.sink.hook,
	}
	scfg := oauth2.ServerConfig{
		Storage:        e.store,
		ClientStore:    testClients(),
		IssuerResolver: hostIssuer{},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
		Now:            e.clock.Now,
		OnError:        e.sink.hook,
		Grants:         []oauth2.Grant{}, // marker: default grants
	}
	ocfg := oidcprovider.Config{Keys: e.keys, Claims: e.claims, Interaction: e.interaction}

	for _, o := range opts {
		o(&scfg, &gcfg, &ocfg)
	}

	if shared, ok := scfg.Storage.(*memory.Store); ok {
		e.store = shared
	}

	e.storage = scfg.Storage

	switch {
	case scfg.Grants == nil:
		scfg.Grants = []oauth2.Grant{grant.NewAuthorizationCode(gcfg), grant.NewClientCredentials(gcfg)}
	case len(scfg.Grants) == 0:
		scfg.Grants = []oauth2.Grant{
			grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg), grant.NewClientCredentials(gcfg),
		}
	}

	op, err := oidcprovider.New(scfg, ocfg)
	require.NoError(t, err)

	e.op = op

	return e
}

// clients returns the env's client store, to change after issuance.
func (e *env) clients() staticClients {
	return e.op.Server().Config().ClientStore.(staticClients) //nolint:forcetypeassert // the env's own store
}

// serve runs h on a request and returns the recorder.
func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	return rec
}

// get builds a GET request on the test issuer's host.
func get(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, target, nil)
}

// fakeInteraction is a scripted Interaction. Unscripted, it approves as
// alice, authenticated now, releasing every requested claim.
type fakeInteraction struct {
	clock *testClock

	mu          sync.Mutex
	authorize   func(http.ResponseWriter, *http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error)
	silent      func(*http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error)
	interactive []oidcprovider.Request
	silentReqs  []oidcprovider.Request
}

func newFakeInteraction(clock *testClock) *fakeInteraction { return &fakeInteraction{clock: clock} }

// approval is the default decision: alice, authenticated at the clock's
// now within req's issuer, every requested claim released.
func (f *fakeInteraction) approval(req *oidcprovider.Request) *oidcprovider.Decision {
	var names []string
	for _, c := range append(slices.Clone(req.Claims.IDToken), req.Claims.UserInfo...) {
		names = append(names, c.Name)
	}

	return &oidcprovider.Decision{
		Authentication: &oidcprovider.AuthenticationEvent{
			Issuer: req.Issuer, Subject: "alice", AuthTime: f.clock.Now(), AMR: []string{"pwd"},
		},
		Claims: names,
	}
}

func (f *fakeInteraction) Authorize(w http.ResponseWriter, r *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	f.mu.Lock()
	f.interactive = append(f.interactive, *req)
	script := f.authorize
	f.mu.Unlock()

	if script != nil {
		return script(w, r, req)
	}

	return f.approval(req), nil
}

func (f *fakeInteraction) AuthorizeSilently(r *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	f.mu.Lock()
	f.silentReqs = append(f.silentReqs, *req)
	script := f.silent
	f.mu.Unlock()

	if script != nil {
		return script(r, req)
	}

	return f.approval(req), nil
}

func (f *fakeInteraction) script(fn func(http.ResponseWriter, *http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.authorize = fn
}

func (f *fakeInteraction) scriptSilent(fn func(*http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.silent = fn
}

// calls returns the interactive and silent calls so far.
func (f *fakeInteraction) calls() (interactive, silent []oidcprovider.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.interactive), slices.Clone(f.silentReqs)
}

// fakeClaims is a ClaimsSource over per-subject claims; it records every
// query and can be made to fail.
type fakeClaims struct {
	mu      sync.Mutex
	users   map[string]map[string]any
	err     error
	queries []oidcprovider.ClaimsQuery
}

func newFakeClaims() *fakeClaims {
	return &fakeClaims{users: map[string]map[string]any{
		"alice": {
			"name": "Alice Liddell", "name#fr": "Alice Liddell (fr)", "given_name": "Alice", "family_name": "Liddell",
			"email": "alice@example.com", "email_verified": true, "phone_number": "+33 1 23 45 67 89",
			"phone_number#x#y": "+0", "sub#x": "mallory",
			"address": map[string]any{"country": "FR"}, "updated_at": 1760000000, "nickname": "",
			"middle_name": nil, "groups": []string{"admins"},
			// Protocol claims an application must not be able to set.
			"sub": "mallory", "iss": "https://evil.example", "aud": "evil", "nonce": "evil", "auth_time": 1,
			"acr": "evil", "amr": []string{"evil"}, "at_hash": "evil", "exp": 1, "iat": 1, "azp": "evil",
		},
	}}
}

func (f *fakeClaims) Claims(_ context.Context, q oidcprovider.ClaimsQuery) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q.Names = slices.Clone(q.Names)
	f.queries = append(f.queries, q)

	if f.err != nil {
		return nil, f.err
	}

	user, ok := f.users[q.Subject]
	if !ok {
		return nil, fmt.Errorf("lookup %q: %w", q.Subject, oidcprovider.ErrUnknownSubject)
	}

	out := make(map[string]any, len(user))
	for k, v := range user {
		out[k] = v
	}

	return out, nil
}

func (f *fakeClaims) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.err = err
}

// user returns the claims of sub.
func (f *fakeClaims) user(sub string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.users[sub]
}

// setUser registers the claims of sub.
func (f *fakeClaims) setUser(sub string, claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.users[sub] = claims
}

func (f *fakeClaims) removeUser(sub string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.users, sub)
}

func (f *fakeClaims) recorded() []oidcprovider.ClaimsQuery {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.queries)
}

// spyStore is a memory store counting the writes that issue something.
type spyStore struct {
	*memory.Store

	codes atomic.Int32
	pairs atomic.Int32
}

func (s *spyStore) SaveAuthorizationCode(ctx context.Context, code *oauth2.AuthorizationCode) error {
	s.codes.Add(1)

	return s.Store.SaveAuthorizationCode(ctx, code) //nolint:wrapcheck // test double
}

func (s *spyStore) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	s.pairs.Add(1)

	return s.Store.SaveTokenPair(ctx, pair) //nolint:wrapcheck // test double
}

func (s *spyStore) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.TokenPair) error {
	s.pairs.Add(1)

	return s.Store.RotateRefreshToken(ctx, oldHash, next) //nolint:wrapcheck // test double
}

// algClient is a confidential client that registered an
// id_token_signed_response_alg.
type algClient struct {
	oauth2.DefaultClient

	alg jwtsec.Algorithm
}

func (c *algClient) IDTokenSignedResponseAlg() jwtsec.Algorithm { return c.alg }

func newAlgClient(id string, alg jwtsec.Algorithm) *algClient {
	return &algClient{DefaultClient: oauth2.DefaultClient{
		IDValue: id, Secret: webClientSecret, TypeValue: oauth2.ClientConfidential,
		RedirectURIValues: []string{webRedirectURI}, ScopeValues: []string{"openid", "profile", "email", "offline_access"},
		GrantTypeValues: webGrantTypes,
	}, alg: alg}
}
