// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/require"
)

// testNow is the instant every test clock starts at.
var testNow = time.Unix(1_800_000_000, 0).UTC()

// testTransactionKey is the server-held transaction key of the test
// Clients (Config.TransactionKeys).
var testTransactionKey = []byte("0123456789abcdef0123456789abcdef")

const (
	testClientID     = "client-1"
	testClientSecret = "s3cr3t-with-enough-entropy-for-hs256"
	testConnection   = "acme"
	testCallbackPath = "/oidc/acme/callback"
	testRedirectURL  = "https://rp.example.com" + testCallbackPath
	testSubject      = "248289761001"
	testAccessToken  = "at-1"
)

// testClock is a settable clock shared by a fake OP and its clients.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *testClock { return &testClock{now: testNow} }

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

// signingKey is a private key and the JOSE parameters it signs with.
type signingKey struct {
	alg  jose.SignatureAlgorithm
	kid  string
	priv crypto.Signer
}

// jwk is the public JWK of k, with alg and use as an OP publishes them.
func (k signingKey) jwk() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.priv.Public(), KeyID: k.kid, Algorithm: string(k.alg), Use: "sig"}
}

// bareJWK is the public JWK of k without alg (as Entra ID publishes keys).
func (k signingKey) bareJWK() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.priv.Public(), KeyID: k.kid}
}

var (
	keysOnce sync.Once
	rsaA     *rsa.PrivateKey
	rsaB     *rsa.PrivateKey
	rsaEvil  *rsa.PrivateKey
	rsaWeak  *rsa.PrivateKey
	ecP256   *ecdsa.PrivateKey
	ecP384   *ecdsa.PrivateKey
	ecP521   *ecdsa.PrivateKey
	edKey    ed25519.PrivateKey
)

func loadKeys() {
	keysOnce.Do(func() {
		must := func(err error) {
			if err != nil {
				panic(err)
			}
		}

		var err error

		rsaA, err = rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		rsaB, err = rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		rsaEvil, err = rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		rsaWeak, err = rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the point: a weak key the RP must skip
		must(err)
		ecP256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		ecP384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		must(err)
		ecP521, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		must(err)
		_, edKey, err = ed25519.GenerateKey(rand.Reader)
		must(err)
	})
}

func keyRSA(alg jose.SignatureAlgorithm, kid string) signingKey {
	loadKeys()

	return signingKey{alg: alg, kid: kid, priv: rsaA}
}

func keyRSAB(kid string) signingKey {
	loadKeys()

	return signingKey{alg: jose.RS256, kid: kid, priv: rsaB}
}

func keyEvil(kid string) signingKey {
	loadKeys()

	return signingKey{alg: jose.RS256, kid: kid, priv: rsaEvil}
}

func keyWeak(kid string) signingKey {
	loadKeys()

	return signingKey{alg: jose.RS256, kid: kid, priv: rsaWeak}
}

func keyEC(alg jose.SignatureAlgorithm, kid string) signingKey {
	loadKeys()

	switch alg {
	case jose.ES384:
		return signingKey{alg: alg, kid: kid, priv: ecP384}
	case jose.ES512:
		return signingKey{alg: alg, kid: kid, priv: ecP521}
	default:
		return signingKey{alg: alg, kid: kid, priv: ecP256}
	}
}

func keyEd(kid string) signingKey {
	loadKeys()

	return signingKey{alg: jose.EdDSA, kid: kid, priv: edKey}
}

// signJWS signs payload with key, adding header (typ defaults to JWT; a nil
// value removes it).
func signJWS(t *testing.T, key signingKey, header map[string]any, payload []byte) string {
	t.Helper()

	extra := map[jose.HeaderKey]any{jose.HeaderType: "JWT"}

	for k, v := range header {
		if v == nil {
			delete(extra, jose.HeaderKey(k))

			continue
		}

		extra[jose.HeaderKey(k)] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: key.alg, Key: jose.JSONWebKey{Key: key.priv, KeyID: key.kid}},
		&jose.SignerOptions{ExtraHeaders: extra},
	)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	out, err := jws.CompactSerialize()
	require.NoError(t, err)

	return out
}

// leftHalfHash is the at_hash of token for alg (OpenID Connect Core
// §3.1.3.6), SHA-512 for EdDSA.
func leftHalfHash(alg jose.SignatureAlgorithm, token string) string {
	var h hash.Hash

	switch alg {
	case jose.RS384, jose.PS384, jose.ES384:
		h = sha512.New384()
	case jose.RS512, jose.PS512, jose.ES512, jose.EdDSA:
		h = sha512.New()
	default:
		h = sha256.New()
	}

	h.Write([]byte(token))
	sum := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// grant is an authorization the fake OP issued a code for.
type grant struct {
	clientID     string
	redirectURI  string
	scope        string
	state        string
	nonce        string
	challenge    string
	method       string
	responseMode string
	maxAge       string
	acrValues    string
	used         bool
}

// tokenRequest is a token request as the fake OP received it.
type tokenRequest struct {
	method        string
	contentType   string
	accept        string
	authorization string
	form          url.Values
}

// fakeOP is an in-process OpenID Provider on a loopback TLS server whose
// behavior tests script through its fields (under mu).
type fakeOP struct {
	t      *testing.T
	srv    *httptest.Server
	issuer string
	clock  *testClock

	mu             sync.Mutex
	metadata       map[string]any
	metadataRaw    []byte
	metadataType   string
	metadataStatus int
	discoveryPaths []string
	jwks           []jose.JSONWebKey
	jwksRaw        []byte
	jwksType       string
	jwksStatus     int
	jwksGate       chan struct{}
	jwksEntered    chan struct{}
	signer         signingKey
	clientID       string
	clientSecret   string
	authMethod     oidcclient.AuthMethod
	accessToken    string
	grants         map[string]*grant
	codes          int
	claimsHook     func(g *grant, claims map[string]any)
	headerHook     func(header map[string]any)
	tokenHook      func(g *grant, body map[string]any)
	idTokenHook    func(g *grant) string
	tokenHandler   http.HandlerFunc
	tokenRequests  []tokenRequest
	userinfo       http.HandlerFunc
	hits           map[string]int
	// redirects maps a request path to the Location the OP answers it
	// with (302 Found), before any other handling.
	redirects map[string]string
}

// newFakeOP starts a fake OP whose issuer is the server URL plus
// issuerPath.
func newFakeOP(t *testing.T, issuerPath ...string) *fakeOP {
	t.Helper()

	op := &fakeOP{
		t:            t,
		clock:        newClock(),
		clientID:     testClientID,
		clientSecret: testClientSecret,
		authMethod:   oidcclient.AuthMethodClientSecretBasic,
		accessToken:  testAccessToken,
		grants:       map[string]*grant{},
		hits:         map[string]int{},
		signer:       keyRSA(jose.RS256, "rsa-1"),
		metadataType: "application/json",
		jwksType:     "application/json",
	}
	op.jwks = []jose.JSONWebKey{op.signer.jwk()}

	op.srv = httptest.NewTLSServer(http.HandlerFunc(op.serve))
	t.Cleanup(op.srv.Close)

	op.issuer = op.srv.URL + strings.Join(issuerPath, "")
	op.metadata = op.defaultMetadata()

	return op
}

func (op *fakeOP) defaultMetadata() map[string]any {
	base := op.srv.URL

	return map[string]any{
		"issuer":                                op.issuer,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"userinfo_endpoint":                     base + "/userinfo",
		"jwks_uri":                              base + "/jwks",
		"response_types_supported":              []string{"code", "code id_token"},
		"response_modes_supported":              []string{"query", "form_post"},
		"subject_types_supported":               []string{"public"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"id_token_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
		},
	}
}

// set runs f under the OP's lock.
func (op *fakeOP) set(f func(op *fakeOP)) {
	op.mu.Lock()
	defer op.mu.Unlock()

	f(op)
}

// hitCount returns how many requests path received.
func (op *fakeOP) hitCount(path string) int {
	op.mu.Lock()
	defer op.mu.Unlock()

	return op.hits[path]
}

func (op *fakeOP) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(op.srv.Certificate())

	return p
}

func (op *fakeOP) serve(w http.ResponseWriter, r *http.Request) {
	op.mu.Lock()
	op.hits[r.URL.Path]++
	location, redirected := op.redirects[r.URL.Path]
	op.mu.Unlock()

	if redirected {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)

		return
	}

	switch {
	case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
		op.serveDiscovery(w, r)
	case r.URL.Path == "/jwks":
		op.serveJWKS(w)
	case r.URL.Path == "/authorize":
		op.serveAuthorize(w, r)
	case r.URL.Path == "/token":
		op.mu.Lock()
		h := op.tokenHandler
		op.mu.Unlock()

		if h != nil {
			h(w, r)

			return
		}

		op.serveToken(w, r)
	case r.URL.Path == "/userinfo":
		op.mu.Lock()
		h := op.userinfo
		op.mu.Unlock()

		if h == nil {
			http.NotFound(w, r)

			return
		}

		h(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (op *fakeOP) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	op.mu.Lock()
	op.discoveryPaths = append(op.discoveryPaths, r.URL.Path)
	body := op.metadataRaw

	if body == nil {
		var err error

		body, err = json.Marshal(op.metadata)
		if err != nil {
			panic(err)
		}
	}

	status, contentType := op.metadataStatus, op.metadataType
	op.mu.Unlock()

	if status == 0 {
		status = http.StatusOK
	}

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (op *fakeOP) serveJWKS(w http.ResponseWriter) {
	op.mu.Lock()
	gate, entered := op.jwksGate, op.jwksEntered
	op.mu.Unlock()

	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}

	if gate != nil {
		<-gate
	}

	op.mu.Lock()
	body := op.jwksRaw

	if body == nil {
		var err error

		body, err = json.Marshal(jose.JSONWebKeySet{Keys: op.jwks})
		if err != nil {
			panic(err)
		}
	}

	status, contentType := op.jwksStatus, op.jwksType
	op.mu.Unlock()

	if status == 0 {
		status = http.StatusOK
	}

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// authorize plays the authorization endpoint for the user agent: it
// records the request and returns the code the OP would redirect with.
func (op *fakeOP) authorize(t *testing.T, authURL string) string {
	t.Helper()

	u, err := url.Parse(authURL)
	require.NoError(t, err)

	q := u.Query()

	op.mu.Lock()
	defer op.mu.Unlock()

	op.codes++
	code := "code-" + strconv.Itoa(op.codes)
	op.grants[code] = &grant{
		clientID:     q.Get("client_id"),
		redirectURI:  q.Get("redirect_uri"),
		scope:        q.Get("scope"),
		state:        q.Get("state"),
		nonce:        q.Get("nonce"),
		challenge:    q.Get("code_challenge"),
		method:       q.Get("code_challenge_method"),
		responseMode: q.Get("response_mode"),
		maxAge:       q.Get("max_age"),
		acrValues:    q.Get("acr_values"),
	}

	return code
}

// serveAuthorize is the authorization endpoint of a user who is already
// logged in and consents: it answers with the code in the query (302) or
// with an auto-submitted form (form_post).
func (op *fakeOP) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	code := op.authorize(op.t, r.URL.String())
	q := r.URL.Query()

	if q.Get("response_mode") == "form_post" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `<form method="post" action="`+q.Get("redirect_uri")+`">`+
			`<input type="hidden" name="code" value="`+code+`">`+
			`<input type="hidden" name="state" value="`+q.Get("state")+`"></form>`)

		return
	}

	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)

		return
	}

	params := target.Query()
	params.Set("code", code)
	params.Set("state", q.Get("state"))
	target.RawQuery = params.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// serveToken is a strict token endpoint: client authentication per
// authMethod, single-use codes bound to client and redirect URI, PKCE S256.
func (op *fakeOP) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request")

		return
	}

	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")

		return
	}

	op.mu.Lock()
	defer op.mu.Unlock()

	op.tokenRequests = append(op.tokenRequests, tokenRequest{
		method:        r.Method,
		contentType:   r.Header.Get("Content-Type"),
		accept:        r.Header.Get("Accept"),
		authorization: r.Header.Get("Authorization"),
		form:          r.PostForm,
	})

	if !op.clientAuthenticated(r) {
		oauthError(w, http.StatusUnauthorized, "invalid_client")

		return
	}

	g, ok := op.grants[r.PostForm.Get("code")]
	if !ok || g.used || r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("redirect_uri") != g.redirectURI || g.clientID != op.clientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant")

		return
	}

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if g.method != "S256" || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant")

		return
	}

	g.used = true

	idToken := op.idToken(g)
	body := map[string]any{
		"access_token":  op.accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "rt-1",
		"scope":         g.scope,
		"id_token":      idToken,
	}

	if op.tokenHook != nil {
		op.tokenHook(g, body)
	}

	writeJSON(w, http.StatusOK, body)
}

func (op *fakeOP) clientAuthenticated(r *http.Request) bool {
	user, pass, hasBasic := r.BasicAuth()

	switch op.authMethod {
	case oidcclient.AuthMethodClientSecretBasic:
		id, err1 := url.QueryUnescape(user)
		secret, err2 := url.QueryUnescape(pass)

		return hasBasic && err1 == nil && err2 == nil && id == op.clientID && secret == op.clientSecret &&
			r.PostForm.Get("client_secret") == ""
	case oidcclient.AuthMethodClientSecretPost:
		return !hasBasic && r.PostForm.Get("client_id") == op.clientID && r.PostForm.Get("client_secret") == op.clientSecret
	default:
		return !hasBasic && r.PostForm.Get("client_id") == op.clientID && !r.PostForm.Has("client_secret")
	}
}

// idClaims are the claims of a correct ID Token for g. The caller holds mu.
func (op *fakeOP) idClaims(g *grant) map[string]any {
	now := op.clock.Now()
	claims := map[string]any{
		"iss":     op.issuer,
		"sub":     testSubject,
		"aud":     op.clientID,
		"exp":     now.Add(5 * time.Minute).Unix(),
		"iat":     now.Unix(),
		"nonce":   g.nonce,
		"at_hash": leftHalfHash(op.signer.alg, op.accessToken),
		"email":   "jane@example.com",
	}

	if g.maxAge != "" {
		claims["auth_time"] = now.Add(-30 * time.Second).Unix()
	}

	if g.acrValues != "" {
		claims["acr"] = strings.Fields(g.acrValues)[0]
	}

	return claims
}

// idToken mints the ID Token for g, applying the hooks. The caller holds
// mu.
func (op *fakeOP) idToken(g *grant) string {
	if op.idTokenHook != nil {
		return op.idTokenHook(g)
	}

	claims := op.idClaims(g)
	if op.claimsHook != nil {
		op.claimsHook(g, claims)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}

	header := map[string]any{}
	if op.headerHook != nil {
		op.headerHook(header)
	}

	return signJWS(op.t, op.signer, header, payload)
}

// config returns a working Config for op, modified by the mutators.
func (op *fakeOP) config(mutators ...func(*oidcclient.Config)) oidcclient.Config {
	cfg := oidcclient.Config{
		ConnectionID:    testConnection,
		Issuer:          op.issuer,
		ClientID:        testClientID,
		ClientSecret:    testClientSecret,
		AuthMethod:      oidcclient.AuthMethodClientSecretBasic,
		RedirectURL:     testRedirectURL,
		Scopes:          []string{"openid", "profile"},
		Store:           memory.New(),
		TransactionKeys: [][]byte{testTransactionKey},
		Outbound:        outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: op.pool()},
		Now:             op.clock.Now,
	}

	for _, m := range mutators {
		m(&cfg)
	}

	return cfg
}

// client builds a Client for op.
func (op *fakeOP) client(t *testing.T, mutators ...func(*oidcclient.Config)) *oidcclient.Client {
	t.Helper()

	c, err := oidcclient.New(context.Background(), op.config(mutators...))
	require.NoError(t, err)

	return c
}

// begin starts a login and lets the OP authorize it, returning the
// request and the code.
func (op *fakeOP) begin(t *testing.T, c *oidcclient.Client, opts oidcclient.AuthOptions) (*oidcclient.AuthRequest, string) {
	t.Helper()

	ar, err := c.Begin(context.Background(), opts)
	require.NoError(t, err)

	return ar, op.authorize(t, ar.URL)
}

// receivedOn parses the URL a callback was received on.
func receivedOn(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
}

// callbackFor is the query-mode callback the user agent delivers for ar on
// the test redirect URL.
func callbackFor(ar *oidcclient.AuthRequest, code string) oidcclient.Callback {
	params := url.Values{"code": {code}, "state": {ar.State}}
	received := receivedOn(testRedirectURL)
	received.RawQuery = params.Encode()

	return oidcclient.Callback{
		Mode:    oidcclient.ResponseModeQuery,
		URL:     received,
		Params:  params,
		Binding: ar.Binding,
	}
}

// login runs a whole login against op with c.
func (op *fakeOP) login(t *testing.T, c *oidcclient.Client) (*oidcclient.Identity, error) {
	t.Helper()

	ar, code := op.begin(t, c, oidcclient.AuthOptions{})

	return c.Complete(context.Background(), callbackFor(ar, code))
}

// receive returns the next value of ch, failing the test — instead of
// hanging until the global test timeout — when none comes within ten
// seconds.
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()

	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a channel value")

		var zero T

		return zero
	}
}

// readAll reads and closes a body.
func readAll(t *testing.T, rc io.ReadCloser) []byte {
	t.Helper()

	defer func() { _ = rc.Close() }()

	b, err := io.ReadAll(rc)
	require.NoError(t, err)

	return b
}
