// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command oidc-provider is a runnable OpenID Provider built on
// oidc/provider: the Authorization Code flow with PKCE, ID Tokens,
// UserInfo, Discovery and the JWK Set, with the application's own login
// and consent pages.
//
// Run:
//
//	go run ./oidc-provider
//
// Discovery: http://localhost:8083/.well-known/openid-configuration. Point
// a relying party at the issuer http://localhost:8083 with the confidential
// client demo-rp / demo-rp-secret (client_secret_basic) or the public
// client demo-spa (PKCE only), both registered with the redirect URI
// http://127.0.0.1:9000/oidc/demo/callback — the callback of the "demo"
// connection of examples/oidc-client served at http://127.0.0.1:9000 — and
// sign in as alice / alice-secret. The provider runs Profile20BCP, which
// accepts no http redirect URI but the loopback IP literals 127.0.0.1 and
// [::1] (RFC 9700 §2.6, RFC 8252 §7.3) — not localhost. A refresh token
// comes with offline_access when the end-user ticks "Keep access while I am
// away" on the consent page, which offers it to plain OAuth 2.0 requests
// and to OpenID requests with prompt=consent.
//
// The environment overrides the defaults: OIDC_PROVIDER_ISSUER (https, or
// http on a loopback host), OIDC_PROVIDER_ADDR (the listen address) and
// OIDC_PROVIDER_REDIRECT_URI (the redirect URI of both clients, checked by
// oauth2.ValidateRedirectURI). With examples/oidc-client, from the examples
// directory:
//
//	go run ./oidc-provider &
//	BASE_URL=http://127.0.0.1:9000 ADDR=127.0.0.1:9000 OIDC_DEV_ALLOW_LOOPBACK=1 \
//	OIDC_CONNECTIONS=demo OIDC_DEMO_ISSUER=http://localhost:8083 \
//	OIDC_DEMO_CLIENT_ID=demo-rp OIDC_DEMO_CLIENT_SECRET=demo-rp-secret \
//	go run ./oidc-client
//
// then open http://127.0.0.1:9000. make e2e-oidc runs both the same way
// (e2e/oidc), through a browser.
//
// The demo cuts corners a deployment must not: an http issuer
// (AllowInsecureLoopbackIssuer — production issuers are https), a key
// generated at startup (production keys come from a KMS-backed KeySource
// and rotate through KeyRing.Published), and in-memory storage: tokens,
// consents and the logins in progress — the latter bounded (10,000) and
// expiring after 15 minutes of disuse. Consent is remembered per end-user
// and client, for the scopes and claims the end-user last allowed —
// offline access never: it is asked for every time (OpenID Connect Core
// §11).
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	httpsec "github.com/hyperscale-stack/security/http"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/hyperscale-stack/security/password"
	"github.com/hyperscale-stack/security/session"
)

// Demo configuration. A deployment loads clients and accounts from its
// stores.
const (
	defaultIssuer      = "http://localhost:8083"
	defaultAddr        = "localhost:8083"
	defaultRedirectURI = "http://127.0.0.1:9000/oidc/demo/callback"
	rpClientID         = "demo-rp"
	rpClientSecret     = "demo-rp-secret" //nolint:gosec // demo credential
	spaClientID        = "demo-spa"
	apiAudience        = "demo-api"
)

// profile is the security baseline of the demo's authorization server: the
// OAuth 2.0 Security BCP (RFC 9700).
const profile = oauth2.Profile20BCP

// config is the demo's configuration.
type config struct {
	// Issuer is the issuer identifier: https, or http on a loopback host
	// (development).
	Issuer string
	// Addr is the listen address.
	Addr string
	// RedirectURI is the redirect URI registered for both clients.
	RedirectURI string
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}

	return fallback
}

// loadConfig reads the configuration from the environment
// (OIDC_PROVIDER_ISSUER, OIDC_PROVIDER_ADDR, OIDC_PROVIDER_REDIRECT_URI),
// with the demo's defaults. The provider validates the issuer.
func loadConfig() (config, error) {
	cfg := config{
		Issuer:      envOr("OIDC_PROVIDER_ISSUER", defaultIssuer),
		Addr:        envOr("OIDC_PROVIDER_ADDR", defaultAddr),
		RedirectURI: envOr("OIDC_PROVIDER_REDIRECT_URI", defaultRedirectURI),
	}

	// The registration-time check of the provider's profile (RFC 6749
	// §3.1.2, RFC 9700 §2.6): /authorize would refuse any other URI.
	if err := oauth2.ValidateRedirectURI(profile, cfg.RedirectURI); err != nil {
		return config{}, fmt.Errorf("OIDC_PROVIDER_REDIRECT_URI: %w", err)
	}

	return cfg, nil
}

// account is an end-user of the demo.
type account struct {
	passwordHash string
	claims       map[string]any
}

// principal is the session principal: the end-user's sub.
type principal struct{ subject string }

func (p principal) Subject() string { return p.subject }

// consentAnswer is an end-user's answer to the consent page of one
// authorization request: subject's, and no one else's.
type consentAnswer struct {
	subject        string
	allow, offline bool
}

// consentRecord is what an end-user last allowed a client: the scopes —
// offline_access excepted, never remembered (OpenID Connect Core §11: "a
// previously saved user consent is not always sufficient to grant offline
// access") — and the names of the requested claims. Each consent replaces
// it: it never grows.
type consentRecord struct{ scopes, claims []string }

// app is the application side of the provider — what oidc/provider leaves
// to it through Interaction and ClaimsSource: end-user sessions, the login
// and consent pages, consent records and end-user claims.
type app struct {
	now      func() time.Time
	issuer   string
	paths    oidcprovider.Paths
	sessions *session.Manager
	hasher   password.Hasher
	accounts map[string]account
	// dummyHash is what the password of an unknown username is compared
	// with: a login attempt takes as long whether the account exists or not.
	dummyHash string

	mu sync.Mutex
	// consents remembers, by subject and client, what the end-user last
	// allowed the client.
	consents map[string]consentRecord
	// pending holds the authorization requests in progress, by browser
	// session and request: server-side state bound to this browser and this
	// request (Decision.InteractionStartedAt, consent answers), carried over
	// to the session a login opens. At most pendingLimit entries.
	pending      map[string]*pendingRequest
	pendingLimit int
	lastPurge    time.Time
}

// Bounds on the authorization requests in progress the demo remembers.
const (
	// maxPendingRequests is the default limit, across all browsers.
	maxPendingRequests = 10000
	// pendingPurgeInterval spaces the purges of expired ones.
	pendingPurgeInterval = time.Minute
)

// pendingRequest is the server-side state of an authorization request in
// progress in one browser: when its login began and the answer of its
// consent page. Unused for oidcprovider.MaxInteractionDuration, it has
// expired.
type pendingRequest struct {
	started time.Time
	answer  *consentAnswer
	updated time.Time
}

// newServer builds the provider of cfg and the application around it. It
// is separate from main so that the end-to-end test drives the exact same
// wiring.
func newServer(cfg config) (http.Handler, error) {
	handler, _, err := buildServer(cfg, time.Now)

	return handler, err
}

// buildServer is newServer with the clock now, shared by the provider and
// the application.
func buildServer(cfg config, now func() time.Time) (http.Handler, *app, error) {
	issuer := cfg.Issuer

	a, err := newApp(issuer, now)
	if err != nil {
		return nil, nil, err
	}

	keys, err := demoKeys()
	if err != nil {
		return nil, nil, err
	}

	store := memory.New()
	grants := grant.Config{
		Storage:       store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    30 * 24 * time.Hour,
		// A refresh token only with offline_access, granted by the
		// end-user (OpenID Connect Core §11).
		RefreshTokenScope: oidcprovider.ScopeOfflineAccess,
	}

	op, err := oidcprovider.New(oauth2.ServerConfig{
		Profile:        profile,
		Storage:        store,
		ClientStore:    demoClients(cfg.RedirectURI),
		IssuerResolver: oauth2.StaticIssuer(issuer, apiAudience),
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(grants), grant.NewRefreshToken(grants)},
		Now:            now,
	}, oidcprovider.Config{
		Keys:        keys,
		Claims:      a,
		Interaction: a,
		// Discovery claims_supported: what the ClaimsSource can supply.
		ClaimsSupported:             slices.Sorted(maps.Keys(a.accounts["alice"].claims)),
		AllowInsecureLoopbackIssuer: true, // http://localhost demo only
	})
	if err != nil {
		return nil, nil, fmt.Errorf("new provider: %w", err)
	}

	if a.paths, err = op.Paths(issuer); err != nil {
		return nil, nil, fmt.Errorf("paths: %w", err)
	}

	srv := op.Server()
	authorize := op.AuthorizeHandler(oauth2.AuthorizeConfig{})

	mux := http.NewServeMux()
	mux.Handle("GET "+a.paths.Authorize, authorize)
	mux.Handle("POST "+a.paths.Authorize, authorize)
	mux.Handle("POST "+a.paths.Token, srv.TokenHandler())
	mux.Handle("POST "+a.paths.Revoke, srv.RevokeHandler())
	mux.Handle("POST "+a.paths.Introspect, srv.IntrospectHandler())
	mux.Handle(a.paths.UserInfo, op.UserInfoHandler()) // GET and POST
	mux.Handle("GET "+a.paths.Discovery, op.DiscoveryHandler())
	mux.Handle("GET "+a.paths.Metadata, srv.MetadataHandler())
	mux.Handle("GET "+a.paths.JWKS, op.JWKSHandler())
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /consent", a.consent)

	return mux, a, nil
}

// newApp builds the application of issuer, on the clock now — its sessions'
// too.
func newApp(issuer string, now func() time.Time) (*app, error) {
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}

	codec, err := session.NewCodec(cookieKey)
	if err != nil {
		return nil, fmt.Errorf("session codec: %w", err)
	}

	hasher := password.NewBCryptHasher(10)

	aliceHash, err := hasher.Hash(context.Background(), "alice-secret")
	if err != nil {
		return nil, fmt.Errorf("hash alice: %w", err)
	}

	dummyHash, err := hasher.Hash(context.Background(), "no account has this password")
	if err != nil {
		return nil, fmt.Errorf("dummy hash: %w", err)
	}

	// Secure cookies need https: off for an http (loopback) issuer only.
	secure := strings.HasPrefix(issuer, "https://")

	return &app{
		now:      now,
		issuer:   issuer,
		sessions: session.NewManager(codec, session.WithCookieName("op_session"), session.WithSecure(secure), session.WithClock(now)),
		hasher:   hasher,
		accounts: map[string]account{"alice": {passwordHash: aliceHash, claims: map[string]any{
			"name": "Alice Liddell", "given_name": "Alice", "family_name": "Liddell",
			"email": "alice@example.com", "email_verified": true,
		}}},
		dummyHash:    dummyHash,
		consents:     map[string]consentRecord{},
		pending:      map[string]*pendingRequest{},
		pendingLimit: maxPendingRequests,
	}, nil
}

// demoKeys generates the signing key at startup: every restart rotates it
// abruptly. A deployment serves its keys from a KMS-backed KeySource and
// rotates them through KeyRing.Published (see KeyRing).
func demoKeys() (oidcprovider.KeySource, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}

	keys, err := oidcprovider.StaticKeys(oidcprovider.KeyRing{
		Signing: []jwtsec.PrivateKey{{KeyID: "demo-1", Algorithm: jwtsec.RS256, Key: key}},
	})
	if err != nil {
		return nil, fmt.Errorf("key ring: %w", err)
	}

	return keys, nil
}

// staticClients is the ClientStore of the demo.
type staticClients map[string]oauth2.Client

func (s staticClients) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	return s[id], nil
}

func demoClients(redirectURI string) staticClients {
	scopes := []string{oidcprovider.ScopeOpenID, oidcprovider.ScopeProfile, oidcprovider.ScopeEmail, oidcprovider.ScopeOfflineAccess}
	grants := []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken}

	return staticClients{
		rpClientID: &oauth2.DefaultClient{
			IDValue: rpClientID, Secret: rpClientSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{redirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
			AuthMethodValues: []string{"client_secret_basic"},
		},
		spaClientID: &oauth2.DefaultClient{
			IDValue: spaClientID, TypeValue: oauth2.ClientPublic,
			RedirectURIValues: []string{redirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
			AuthMethodValues: []string{"none"},
		},
	}
}

// Authorize implements oidcprovider.Interaction: the end-user signs in,
// then consents, each on a page of the application; the page sends the
// browser back to the authorization request, which resumes here.
func (a *app) Authorize(w http.ResponseWriter, r *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	carrier := httpsec.NewCarrier(w, r)
	key := requestKey(r.Form)
	resume := a.paths.Authorize + "?" + r.Form.Encode()
	s, ev := a.signedIn(r.Context(), carrier)

	if ev != nil && reauthenticate(req) && !a.signedInSince(*ev, s, key) {
		// prompt=login, max_age=0: sign in again during this request —
		// Request.Check only refuses an authentication older than the
		// request, to the second of auth_time.
		ev = nil
	}

	if ev != nil {
		// prompt=login, max_age, a designated end-user, an essential acr:
		// the request's rules, checked against the session.
		err := req.Check(*ev, a.startedAt(s, key))

		switch {
		case oauth2.IsCode(err) == oauth2.CodeLoginRequired:
			ev = nil // stale session, or another end-user: sign in again
		case err != nil:
			a.done(s, key)

			return refusal(err)
		}
	}

	if ev == nil {
		login, err := a.loginSession(r.Context(), carrier, s)
		if err != nil {
			return nil, err
		}

		a.begin(login.ID, key, req.ReceivedAt)

		return nil, renderLogin(w, login, resume, http.StatusOK, "")
	}

	return a.consentTo(w, s, *ev, req, key, resume)
}

// consentTo ends the authorization request of key once ev authenticated
// the end-user: the consent page when the request needs one — prompt=consent,
// offline access to choose, or a request the remembered consent does not
// cover — or the decision.
func (a *app) consentTo(
	w http.ResponseWriter, s *session.Session, ev oidcprovider.AuthenticationEvent, req *oidcprovider.Request, key, resume string,
) (*oidcprovider.Decision, error) {
	answer, answered := a.answerOf(s, key, ev.Subject)

	switch {
	case answered && !answer.allow:
		a.done(s, key)

		return &oidcprovider.Decision{}, nil // the end-user denied: access_denied
	case !answered && (req.Prompt.Consent || offlineChoice(req) || !a.covered(ev.Subject, req)):
		return nil, a.renderConsent(w, s, req, resume)
	}

	if answered {
		a.remember(ev.Subject, req)
	}

	d := a.decision(ev, req, a.startedAt(s, key))
	if answered && answer.offline && offlineChoice(req) {
		// Otherwise the provider drops offline_access from the grant — and
		// denies a request that asked for nothing else.
		d.OfflineAccess = oidcprovider.OfflineAccessPrompted
	}

	a.done(s, key)

	return d, nil
}

// offlineChoice reports whether the consent page offers offline access:
// requested, and grantable on the end-user's choice — an OpenID request
// only with prompt=consent (OpenID Connect Core §11), a plain OAuth 2.0
// request always.
func offlineChoice(req *oidcprovider.Request) bool {
	return req.OfflineAccess && (req.Prompt.Consent || !req.OpenID)
}

// AuthorizeSilently implements oidcprovider.Interaction for prompt=none:
// the current session and a remembered consent, or an error — never a
// page.
func (a *app) AuthorizeSilently(r *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	_, ev := a.signedIn(r.Context(), httpsec.NewCarrier(nil, r))
	if ev == nil {
		return refusal(oauth2.ErrLoginRequired)
	}

	if err := req.Check(*ev, time.Time{}); err != nil {
		return refusal(err)
	}

	if !a.covered(ev.Subject, req) {
		return refusal(oauth2.ErrConsentRequired)
	}

	return a.decision(*ev, req, time.Time{}), nil
}

// refusal answers the authorization request with the protocol error err —
// the redirect to the client carries it.
func refusal(err error) (*oidcprovider.Decision, error) {
	return &oidcprovider.Decision{Refusal: err}, nil
}

// Claims implements oidcprovider.ClaimsSource. The provider releases only
// what the request and the end-user allow.
func (a *app) Claims(_ context.Context, q oidcprovider.ClaimsQuery) (map[string]any, error) {
	acc, ok := a.accounts[q.Subject]
	if !ok {
		return nil, oidcprovider.ErrUnknownSubject
	}

	return maps.Clone(acc.claims), nil
}

// signedIn returns the session and the authentication event of its
// end-user — nil when nobody signed in. The session records the sub; its
// creation is the authentication time; its realm is the single issuer of
// the demo — a multi-issuer deployment records the realm in the session,
// and the provider refuses a session of another realm.
func (a *app) signedIn(ctx context.Context, c *httpsec.Carrier) (*session.Session, *oidcprovider.AuthenticationEvent) {
	s, err := a.sessions.Get(ctx, c)
	if err != nil {
		return nil, nil
	}

	sub, _ := s.Values["sub"].(string)
	if sub == "" {
		return s, nil // a session opened for the login form's CSRF token
	}

	return s, &oidcprovider.AuthenticationEvent{Issuer: a.issuer, Subject: sub, AuthTime: s.CreatedAt, AMR: []string{"pwd"}}
}

// reauthenticate reports whether req asks the end-user to sign in again.
func reauthenticate(req *oidcprovider.Request) bool {
	return req.Prompt.Login || (req.MaxAge != nil && *req.MaxAge == 0)
}

// signedInSince reports whether ev happened during the authorization
// request of key in this browser: after its login page was first shown.
func (a *app) signedInSince(ev oidcprovider.AuthenticationEvent, s *session.Session, key string) bool {
	started := a.startedAt(s, key)

	return !started.IsZero() && !ev.AuthTime.Before(started)
}

// decision approves req for ev, releasing every individually requested
// claim: the consent page listed them, or a remembered consent covers them.
func (a *app) decision(ev oidcprovider.AuthenticationEvent, req *oidcprovider.Request, started time.Time) *oidcprovider.Decision {
	return &oidcprovider.Decision{Authentication: &ev, InteractionStartedAt: started, Claims: claimNames(req)}
}

// login signs the end-user in and sends the browser back to the
// authorization request.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	carrier := httpsec.NewCarrier(w, r)

	s, err := a.sessions.Get(r.Context(), carrier)
	if err != nil || !session.VerifyCSRF(s, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)

		return
	}

	resume := r.PostFormValue("return_to")

	form, ok := a.authorizationRequest(resume)
	if !ok {
		http.Error(w, "invalid return_to", http.StatusBadRequest)

		return
	}

	username := r.PostFormValue("username")
	if !a.verifyPassword(r.Context(), username, r.PostFormValue("password")) {
		if err := renderLogin(w, s, resume, http.StatusUnauthorized, "Invalid username or password."); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
		}

		return
	}

	// A new session: a fresh ID (no fixation), a fresh authentication time.
	signedIn, err := a.sessions.Login(r.Context(), carrier, principal{subject: username})
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)

		return
	}

	a.carryOver(s.ID, signedIn.ID, requestKey(form))

	//nolint:gosec // G710: resume is a relative URL of the authorization endpoint (authorizationRequest)
	http.Redirect(w, r, resume, http.StatusSeeOther)
}

// consent records the end-user's answer and sends the browser back to the
// authorization request.
func (a *app) consent(w http.ResponseWriter, r *http.Request) {
	s, ev := a.signedIn(r.Context(), httpsec.NewCarrier(w, r))
	if ev == nil || !session.VerifyCSRF(s, r.PostFormValue("csrf_token")) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)

		return
	}

	resume := r.PostFormValue("return_to")

	form, ok := a.authorizationRequest(resume)
	if !ok {
		http.Error(w, "invalid return_to", http.StatusBadRequest)

		return
	}

	// The answer applies to the request the page showed; Authorize
	// remembers an allowed consent from that request once it resumes.
	allow := r.PostFormValue("decision") == "allow"

	answer := consentAnswer{subject: ev.Subject, allow: allow, offline: allow && r.PostFormValue("offline_access") == "on"}

	a.mu.Lock()
	a.update(s.ID, requestKey(form), func(p *pendingRequest) { p.answer = &answer })
	a.mu.Unlock()

	//nolint:gosec // G710: resume is a relative URL of the authorization endpoint (authorizationRequest)
	http.Redirect(w, r, resume, http.StatusSeeOther)
}

// verifyPassword checks the credentials of username.
func (a *app) verifyPassword(ctx context.Context, username, pass string) bool {
	acc, known := a.accounts[username]

	hash := acc.passwordHash
	if !known {
		// The same work for an unknown username: the response time does not
		// tell whether an account exists.
		hash = a.dummyHash
	}

	match, err := a.hasher.Verify(ctx, hash, pass)

	return known && err == nil && match
}

// authorizationRequest returns the parameters of resume, a relative URL of
// this provider's authorization endpoint — anything else could redirect the
// browser elsewhere.
func (a *app) authorizationRequest(resume string) (url.Values, bool) {
	u, err := url.Parse(resume)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Path != a.paths.Authorize || strings.HasPrefix(resume, "//") {
		return nil, false
	}

	return u.Query(), true
}

// requestKey identifies an authorization request across its resumptions:
// the digest of all its parameters, in their canonical encoding — what a
// login started or a consent page showed applies to that very request,
// never to another one sharing its client_id, state, nonce or
// code_challenge.
func requestKey(form url.Values) string {
	sum := sha256.Sum256([]byte(form.Encode()))

	return hex.EncodeToString(sum[:])
}

// begin records when the login of an authorization request began in the
// browser of session sessionID, unless it already did.
func (a *app) begin(sessionID, key string, at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if p, ok := a.pendingOf(sessionID, key); ok && !p.started.IsZero() && at.Sub(p.started) <= oidcprovider.MaxInteractionDuration {
		return
	}

	a.update(sessionID, key, func(p *pendingRequest) { p.started = at })
}

// startedAt returns when the login of an authorization request began in
// the browser of s — zero when it took no other HTTP request, or began too
// long ago.
func (a *app) startedAt(s *session.Session, key string) time.Time {
	if s == nil {
		return time.Time{}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	p, ok := a.pendingOf(s.ID, key)
	if !ok || p.started.IsZero() || a.now().Sub(p.started) > oidcprovider.MaxInteractionDuration {
		return time.Time{}
	}

	return p.started
}

// carryOver moves the pending authorization request of key from the session
// a login replaced to the session it opened: the browser is the same.
func (a *app) carryOver(from, to, key string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if p, ok := a.pending[pendingKey(from, key)]; ok {
		delete(a.pending, pendingKey(from, key))
		a.pending[pendingKey(to, key)] = p
	}
}

// answerOf returns the answer subject gave to the consent page of an
// authorization request — none when another end-user gave it: a login in
// the same browser hands the pending request over, never the answer.
func (a *app) answerOf(s *session.Session, key, subject string) (consentAnswer, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	p, ok := a.pendingOf(s.ID, key)
	if !ok || p.answer == nil || p.answer.subject != subject {
		return consentAnswer{}, false
	}

	return *p.answer, true
}

// pendingKey identifies the authorization request of key in the browser
// of session sessionID.
func pendingKey(sessionID, key string) string { return sessionID + "\x00" + key }

// pendingOf returns the pending authorization request of key in session
// sessionID, unless it expired. The caller holds a.mu.
func (a *app) pendingOf(sessionID, key string) (*pendingRequest, bool) {
	p, ok := a.pending[pendingKey(sessionID, key)]
	if !ok || a.now().Sub(p.updated) > oidcprovider.MaxInteractionDuration {
		return nil, false
	}

	return p, true
}

// update applies change to the pending authorization request of key in
// session sessionID, created when missing. The caller holds a.mu.
func (a *app) update(sessionID, key string, change func(*pendingRequest)) {
	id := pendingKey(sessionID, key)

	p, ok := a.pending[id]
	if !ok {
		a.makeRoom()

		p = &pendingRequest{}
		a.pending[id] = p
	}

	change(p)
	p.updated = a.now()
}

// makeRoom keeps the pending authorization requests below pendingLimit:
// it purges the expired ones — a full scan, at most once per
// pendingPurgeInterval — then evicts arbitrary ones. A flood of requests
// costs a pending login one more sign-in, never memory. The caller holds
// a.mu.
func (a *app) makeRoom() {
	if len(a.pending) < a.pendingLimit {
		return
	}

	if now := a.now(); now.Sub(a.lastPurge) >= pendingPurgeInterval {
		a.lastPurge = now

		for id, p := range a.pending {
			if now.Sub(p.updated) > oidcprovider.MaxInteractionDuration {
				delete(a.pending, id)
			}
		}
	}

	for id := range a.pending {
		if len(a.pending) < a.pendingLimit {
			break
		}

		delete(a.pending, id)
	}
}

// covered reports whether the consent the end-user last gave the client of
// req covers req: its scopes — offline_access aside — and its claims.
func (a *app) covered(subject string, req *oidcprovider.Request) bool {
	a.mu.Lock()
	record, ok := a.consents[subject+"\x00"+req.Client.ID()]
	a.mu.Unlock()

	if !ok {
		return false
	}

	for _, scope := range req.Scopes {
		if scope != oidcprovider.ScopeOfflineAccess && !slices.Contains(record.scopes, scope) {
			return false
		}
	}

	for _, name := range claimNames(req) {
		if !slices.Contains(record.claims, name) {
			return false
		}
	}

	return true
}

// remember records that the end-user allowed req, offline access aside.
func (a *app) remember(subject string, req *oidcprovider.Request) {
	scopes := slices.DeleteFunc(slices.Clone(req.Scopes), func(s string) bool { return s == oidcprovider.ScopeOfflineAccess })

	a.mu.Lock()
	defer a.mu.Unlock()

	a.consents[subject+"\x00"+req.Client.ID()] = consentRecord{scopes: scopes, claims: claimNames(req)}
}

// claimNames returns the names of the claims req requests, the ID Token's
// then UserInfo's.
func claimNames(req *oidcprovider.Request) []string {
	names := make([]string, 0, len(req.Claims.IDToken)+len(req.Claims.UserInfo))
	for _, c := range append(slices.Clone(req.Claims.IDToken), req.Claims.UserInfo...) {
		names = append(names, c.Name)
	}

	return names
}

// done forgets the state of a completed authorization request.
func (a *app) done(s *session.Session, key string) {
	if s == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.pending, pendingKey(s.ID, key))
}

// pageData is what the login and consent pages show.
type pageData struct {
	CSRF, Resume, Problem, Client string
	Scopes, Claims                []string
	// Offline offers offline access: requested, and grantable on the
	// end-user's choice (see offlineChoice).
	Offline bool
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<title>Sign in</title>
<h1>Sign in</h1>
{{if .Problem}}<p>{{.Problem}}</p>{{end}}
<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<input type="hidden" name="return_to" value="{{.Resume}}">
<input name="username" placeholder="username" autocomplete="username">
<input name="password" type="password" placeholder="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
`))

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<title>Consent</title>
<h1>{{.Client}} asks for access</h1>
<p>Scopes: {{range .Scopes}}{{.}} {{end}}</p>
{{if .Claims}}<p>Claims: {{range .Claims}}{{.}} {{end}}</p>{{end}}
<form method="post" action="/consent">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<input type="hidden" name="return_to" value="{{.Resume}}">
{{if .Offline}}<label><input type="checkbox" name="offline_access"> Keep access while I am away</label>{{end}}
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form>
`))

// loginSession returns s, or a new session — for the login form's CSRF
// token and the pending logins of this browser — when there is none.
func (a *app) loginSession(ctx context.Context, c *httpsec.Carrier, s *session.Session) (*session.Session, error) {
	if s != nil {
		return s, nil
	}

	s, err := a.sessions.Login(ctx, c, nil)
	if err != nil {
		return nil, fmt.Errorf("login session: %w", err)
	}

	return s, nil
}

// renderLogin renders the login form of session s.
func renderLogin(w http.ResponseWriter, s *session.Session, resume string, status int, problem string) error {
	return render(w, status, loginPage, pageData{CSRF: session.CSRFToken(s), Resume: resume, Problem: problem})
}

// renderConsent renders the consent form of req.
func (a *app) renderConsent(w http.ResponseWriter, s *session.Session, req *oidcprovider.Request, resume string) error {
	return render(w, http.StatusOK, consentPage, pageData{
		CSRF: session.CSRFToken(s), Resume: resume, Client: req.Client.ID(), Scopes: req.Scopes, Claims: claimNames(req),
		Offline: offlineChoice(req),
	})
}

// render writes a page that is never framed (clickjacking) nor cached.
func render(w http.ResponseWriter, status int, page *template.Template, data pageData) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	if err := page.Execute(w, data); err != nil {
		return fmt.Errorf("render %s: %w", page.Name(), err)
	}

	return nil
}

// newHTTPServer is the demo's HTTP server: it bounds the time a client may
// take to send a request and to read the response, and how long an idle
// connection stays open — a slow client cannot hold one forever.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("oidc-provider: %v", err)
	}

	handler, err := newServer(cfg)
	if err != nil {
		log.Fatalf("oidc-provider: %v", err)
	}

	srv := newHTTPServer(cfg.Addr, handler)

	log.Printf("oidc-provider: issuer %s, listening on %s", cfg.Issuer, cfg.Addr)
	log.Fatal(srv.ListenAndServe())
}
