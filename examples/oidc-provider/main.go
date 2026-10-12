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
// http://localhost:9000/callback, and sign in as alice / alice-secret.
// Request offline_access with prompt=consent to get a refresh token.
//
// The demo cuts corners a deployment must not: an http issuer
// (AllowInsecureLoopbackIssuer — production issuers are https), a key
// generated at startup (production keys come from a KMS-backed KeySource
// and rotate through KeyRing.Published), in-memory storage, and consent
// remembered per client rather than per scope.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"html/template"
	"log"
	"maps"
	"net/http"
	"net/url"
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
	demoIssuer     = "http://localhost:8083"
	demoAddr       = "localhost:8083"
	rpClientID     = "demo-rp"
	rpClientSecret = "demo-rp-secret" //nolint:gosec // demo credential
	spaClientID    = "demo-spa"
	rpRedirectURI  = "http://localhost:9000/callback"
	apiAudience    = "demo-api"
)

// account is an end-user of the demo.
type account struct {
	passwordHash string
	claims       map[string]any
}

// principal is the session principal: the end-user's sub.
type principal struct{ subject string }

func (p principal) Subject() string { return p.subject }

// consentAnswer is the end-user's answer to the consent page of one
// authorization request.
type consentAnswer struct{ allow, offline bool }

// app is the application side of the provider — what oidc/provider leaves
// to it through Interaction and ClaimsSource: end-user sessions, the login
// and consent pages, consent records and end-user claims.
type app struct {
	issuer   string
	paths    oidcprovider.Paths
	sessions *session.Manager
	hasher   password.Hasher
	accounts map[string]account

	mu sync.Mutex
	// consents remembers, by subject and client, a consent given.
	consents map[string]bool
	// started records, by authorization request, when its login began:
	// server-side state bound to the request (Decision.InteractionStartedAt).
	started map[string]time.Time
	// answers holds consent page answers, by session and authorization
	// request.
	answers map[string]consentAnswer
}

// newServer builds the provider for issuer and the application around it.
// It is separate from main so that the end-to-end test drives the exact
// same wiring.
func newServer(issuer string) (http.Handler, error) {
	a, err := newApp(issuer)
	if err != nil {
		return nil, err
	}

	keys, err := demoKeys()
	if err != nil {
		return nil, err
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
		Storage:        store,
		ClientStore:    demoClients(),
		IssuerResolver: oauth2.StaticIssuer(issuer, apiAudience),
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(grants), grant.NewRefreshToken(grants)},
	}, oidcprovider.Config{
		Keys:        keys,
		Claims:      a,
		Interaction: a,
		// Discovery claims_supported: what the ClaimsSource can supply.
		ClaimsSupported:             slices.Sorted(maps.Keys(a.accounts["alice"].claims)),
		AllowInsecureLoopbackIssuer: true, // http://localhost demo only
	})
	if err != nil {
		return nil, fmt.Errorf("new provider: %w", err)
	}

	if a.paths, err = op.Paths(issuer); err != nil {
		return nil, fmt.Errorf("paths: %w", err)
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

	return mux, nil
}

func newApp(issuer string) (*app, error) {
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

	return &app{
		issuer: issuer,
		// Secure cookies need https: off for the http demo only.
		sessions: session.NewManager(codec, session.WithCookieName("op_session"), session.WithSecure(false)),
		hasher:   hasher,
		accounts: map[string]account{"alice": {passwordHash: aliceHash, claims: map[string]any{
			"name": "Alice Liddell", "given_name": "Alice", "family_name": "Liddell",
			"email": "alice@example.com", "email_verified": true,
		}}},
		consents: map[string]bool{},
		started:  map[string]time.Time{},
		answers:  map[string]consentAnswer{},
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

func demoClients() staticClients {
	scopes := []string{oidcprovider.ScopeOpenID, oidcprovider.ScopeProfile, oidcprovider.ScopeEmail, oidcprovider.ScopeOfflineAccess}
	grants := []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken}

	return staticClients{
		rpClientID: &oauth2.DefaultClient{
			IDValue: rpClientID, Secret: rpClientSecret, TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{rpRedirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
			AuthMethodValues: []string{"client_secret_basic"},
		},
		spaClientID: &oauth2.DefaultClient{
			IDValue: spaClientID, TypeValue: oauth2.ClientPublic,
			RedirectURIValues: []string{rpRedirectURI}, GrantTypeValues: grants, ScopeValues: scopes,
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

	if ev != nil && reauthenticate(req) && !a.signedInSince(*ev, key) {
		// prompt=login, max_age=0: sign in again during this request —
		// Request.Check only refuses an authentication older than the
		// request, to the second of auth_time.
		ev = nil
	}

	if ev != nil {
		// prompt=login, max_age, a designated end-user, an essential acr:
		// the request's rules, checked against the session.
		err := req.Check(*ev, a.startedAt(key))

		switch {
		case oauth2.IsCode(err) == oauth2.CodeLoginRequired:
			ev = nil // stale session, or another end-user: sign in again
		case err != nil:
			a.done(s, key)

			return refusal(err)
		}
	}

	if ev == nil {
		a.begin(key, req.ReceivedAt)

		return nil, a.renderLogin(w, r, carrier, resume, http.StatusOK, "")
	}

	answer, answered := a.answerOf(s, key)

	switch {
	case answered && !answer.allow:
		a.done(s, key)

		return &oidcprovider.Decision{}, nil // the end-user denied: access_denied
	case !answered && (req.Prompt.Consent || !a.consented(ev.Subject, req.Client.ID())):
		return nil, a.renderConsent(w, s, req, resume)
	}

	d := a.decision(*ev, req, a.startedAt(key))
	if answered && answer.offline && req.OfflineAccess && req.Prompt.Consent {
		d.OfflineAccess = oidcprovider.OfflineAccessPrompted
	}

	a.done(s, key)

	return d, nil
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

	if !a.consented(ev.Subject, req.Client.ID()) {
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
// request of key: after its login page was first shown.
func (a *app) signedInSince(ev oidcprovider.AuthenticationEvent, key string) bool {
	started := a.startedAt(key)

	return !started.IsZero() && !ev.AuthTime.Before(started)
}

// decision approves req for ev, releasing every individually requested
// claim: the consent page listed them.
func (a *app) decision(ev oidcprovider.AuthenticationEvent, req *oidcprovider.Request, started time.Time) *oidcprovider.Decision {
	d := &oidcprovider.Decision{Authentication: &ev, InteractionStartedAt: started}

	for _, c := range append(slices.Clone(req.Claims.IDToken), req.Claims.UserInfo...) {
		d.Claims = append(d.Claims, c.Name)
	}

	return d
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
	if _, ok := a.authorizationRequest(resume); !ok {
		http.Error(w, "invalid return_to", http.StatusBadRequest)

		return
	}

	username := r.PostFormValue("username")
	if !a.verifyPassword(r.Context(), username, r.PostFormValue("password")) {
		if err := a.renderLogin(w, r, carrier, resume, http.StatusUnauthorized, "Invalid username or password."); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
		}

		return
	}

	// A new session: a fresh ID (no fixation), a fresh authentication time.
	if _, err := a.sessions.Login(r.Context(), carrier, principal{subject: username}); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)

		return
	}

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

	allow := r.PostFormValue("decision") == "allow"

	a.mu.Lock()
	a.answers[s.ID+"\x00"+requestKey(form)] = consentAnswer{allow: allow, offline: allow && r.PostFormValue("offline_access") == "on"}

	if allow {
		a.consents[ev.Subject+"\x00"+form.Get("client_id")] = true
	}
	a.mu.Unlock()

	//nolint:gosec // G710: resume is a relative URL of the authorization endpoint (authorizationRequest)
	http.Redirect(w, r, resume, http.StatusSeeOther)
}

// verifyPassword checks the credentials of username.
func (a *app) verifyPassword(ctx context.Context, username, pass string) bool {
	acc, ok := a.accounts[username]
	if !ok {
		return false
	}

	match, err := a.hasher.Verify(ctx, acc.passwordHash, pass)

	return err == nil && match
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

// requestKey identifies an authorization request across its resumptions.
func requestKey(form url.Values) string {
	return strings.Join([]string{
		form.Get("client_id"), form.Get("state"), form.Get("nonce"), form.Get("code_challenge"),
	}, "\x00")
}

// begin records when the login of an authorization request began, unless
// it already did.
func (a *app) begin(key string, at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if started, ok := a.started[key]; !ok || at.Sub(started) > oidcprovider.MaxInteractionDuration {
		a.started[key] = at
	}
}

// startedAt returns when the login of an authorization request began —
// zero when it took no other HTTP request, or began too long ago.
func (a *app) startedAt(key string) time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()

	started, ok := a.started[key]
	if !ok || time.Since(started) > oidcprovider.MaxInteractionDuration {
		return time.Time{}
	}

	return started
}

// answerOf returns the consent page answer of an authorization request.
func (a *app) answerOf(s *session.Session, key string) (consentAnswer, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	answer, ok := a.answers[s.ID+"\x00"+key]

	return answer, ok
}

// consented reports a consent the end-user gave the client before.
func (a *app) consented(subject, clientID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.consents[subject+"\x00"+clientID]
}

// done forgets the state of a completed authorization request.
func (a *app) done(s *session.Session, key string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.started, key)

	if s != nil {
		delete(a.answers, s.ID+"\x00"+key)
	}
}

// pageData is what the login and consent pages show.
type pageData struct {
	CSRF, Resume, Problem, Client string
	Scopes, Claims                []string
	// Offline offers offline access: requested with the consent dialog
	// (OpenID Connect Core §11).
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

// renderLogin renders the login form, opening a session for its CSRF token
// when there is none.
func (a *app) renderLogin(w http.ResponseWriter, r *http.Request, c *httpsec.Carrier, resume string, status int, problem string) error {
	s, err := a.sessions.Get(r.Context(), c)
	if err != nil {
		if s, err = a.sessions.Login(r.Context(), c, nil); err != nil {
			return fmt.Errorf("login session: %w", err)
		}
	}

	return render(w, status, loginPage, pageData{CSRF: session.CSRFToken(s), Resume: resume, Problem: problem})
}

// renderConsent renders the consent form of req.
func (a *app) renderConsent(w http.ResponseWriter, s *session.Session, req *oidcprovider.Request, resume string) error {
	claims := make([]string, 0, len(req.Claims.IDToken)+len(req.Claims.UserInfo))
	for _, c := range append(slices.Clone(req.Claims.IDToken), req.Claims.UserInfo...) {
		claims = append(claims, c.Name)
	}

	return render(w, http.StatusOK, consentPage, pageData{
		CSRF: session.CSRFToken(s), Resume: resume, Client: req.Client.ID(), Scopes: req.Scopes, Claims: claims,
		Offline: req.OfflineAccess && req.Prompt.Consent,
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

func main() {
	handler, err := newServer(demoIssuer)
	if err != nil {
		log.Fatalf("oidc-provider: %v", err)
	}

	srv := &http.Server{Addr: demoAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	log.Printf("oidc-provider: issuer %s", demoIssuer)
	log.Fatal(srv.ListenAndServe())
}
