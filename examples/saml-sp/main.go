// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command saml-sp is a runnable SAML 2.0 Service Provider: SP-initiated
// login against an enterprise IdP, with the configuration, the storage and
// the session all owned by the application.
//
//   - Configuration: the application decides its connections (here one,
//     read from a trusted IdP metadata file) and their SP entity ID and ACS
//     URL (one pair per connection).
//   - Storage: the transaction store and the replay cache are an in-memory
//     samlsp.Storage; a multi-instance deployment plugs the SQL
//     (saml/sp/store/sql) or Redis (saml/sp/store/redis) store instead.
//   - Session: after the ACS the application creates its own session (the
//     session module's encrypted, SameSite=Lax cookie), keyed by the
//     connection and the NameID, bounded by SessionNotOnOrAfter. Logging out
//     ends this local session only: it is not SAML Single Logout.
//
// Run:
//
//	SAMLSP_IDP_METADATA=/path/to/idp-metadata.xml go run ./saml-sp
//
// then register http://localhost:8084/saml/corp/metadata at the IdP (entity
// ID http://localhost:8084/saml/corp, ACS http://localhost:8084/saml/corp/acs)
// and open http://localhost:8084. Plain http is accepted on loopback hosts
// only, which browsers treat as secure: they keep the Secure, __Host-
// prefixed cookies there.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	httpsec "github.com/hyperscale-stack/security/http"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/hyperscale-stack/security/session"
)

// appConfig is the application's own configuration.
type appConfig struct {
	baseURL      string // e.g. http://localhost:8084
	connectionID string
	idpMetadata  []byte // trusted IdP metadata (administrator-provided)
	now          func() time.Time
}

// mailAttribute is the SAML V2.0 X.500/LDAP attribute profile name of
// "mail"; which attributes an IdP releases, and under which names, is part
// of its configuration.
const mailAttribute = "urn:oid:0.9.2342.19200300.100.1.3"

// principal is the session principal: the stable external identity key.
type principal struct{ subject string }

func (p principal) Subject() string { return p.subject }

// app holds the demo dependencies.
type app struct {
	sp       *samlsp.ServiceProvider
	sessions *session.Manager
	connID   string
	now      func() time.Time
}

// newServer wires the demo; it is separate from main so the test drives the
// same wiring.
func newServer(cfg appConfig) (http.Handler, error) {
	if cfg.now == nil {
		cfg.now = time.Now
	}

	idp, err := samlsp.ParseIdentityProviderMetadata(cfg.idpMetadata, samlsp.MetadataOptions{Now: cfg.now})
	if err != nil {
		return nil, fmt.Errorf("import IdP metadata: %w", err)
	}

	// The application owns its connections: one per tenant IdP, each with
	// its own SP entity ID and ACS URL.
	conn := &samlsp.Connection{
		ID:               cfg.connectionID,
		SPEntityID:       cfg.baseURL + "/saml/" + cfg.connectionID,
		ACSURL:           cfg.baseURL + "/saml/" + cfg.connectionID + "/acs",
		IdentityProvider: *idp,
		NameIDFormat:     samlsp.NameIDFormatPersistent,
	}

	// Resolution validates connections on every use; checking at startup
	// reports a misconfiguration before the first login.
	if err := conn.Validate(); err != nil {
		return nil, fmt.Errorf("connection %q: %w", conn.ID, err)
	}

	connections := samlsp.ConnectionResolverFunc(func(_ context.Context, id string) (*samlsp.Connection, error) {
		if id != conn.ID {
			return nil, samlsp.ErrUnknownConnection
		}

		return conn, nil
	})

	store := memory.New() // swap for sqlstore / redisstore in production

	sp, err := samlsp.New(samlsp.Config{
		Connections:  connections,
		Transactions: store,
		ReplayCache:  store,
		Now:          cfg.now,
	})
	if err != nil {
		return nil, fmt.Errorf("new service provider: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}

	codec, err := session.NewCodec(key)
	if err != nil {
		return nil, fmt.Errorf("session codec: %w", err)
	}

	a := &app{
		sp:       sp,
		sessions: session.NewManager(codec, session.WithClock(cfg.now)),
		connID:   conn.ID,
		now:      cfg.now,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /saml/{conn}/metadata", func(w http.ResponseWriter, r *http.Request) {
		a.sp.ServeMetadata(w, r, r.PathValue("conn"))
	})
	mux.HandleFunc("POST /saml/{conn}/acs", a.acs)
	mux.HandleFunc("POST /logout", a.logout)

	return mux, nil
}

// safeReturn keeps only local paths: the return target lives server-side
// in the transaction, but it came from the browser (no open redirect).
func safeReturn(target string) string {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.ContainsAny(target, "\\\r\n") {
		return "/"
	}

	return target
}

// login starts an SP-initiated login with the configured connection.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	target, err := a.sp.BeginLogin(r.Context(), w, r, a.connID, samlsp.LoginOptions{
		AppState: safeReturn(r.URL.Query().Get("return")),
	})
	if err != nil {
		log.Printf("saml-sp: begin login: %v", err)
		http.Error(w, "sign-in unavailable", http.StatusInternalServerError)

		return
	}

	// target is the SSO URL of the trusted IdP metadata with the encoded
	// AuthnRequest: no part of it comes from the browser.
	http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // G710: see above
}

// acs consumes the IdP response and creates the application session.
func (a *app) acs(w http.ResponseWriter, r *http.Request) {
	res, err := a.sp.CompleteLogin(r.Context(), r, r.PathValue("conn"))

	switch {
	case errors.Is(err, samlsp.ErrRejected):
		// Bindings §3.5.6: no HTTP error status for SAML processing
		// failures; never echo the reason (or a StatusMessage) to the user.
		log.Printf("saml-sp: login rejected: %v", err)
		fmt.Fprint(w, `<h1>Sign-in failed</h1><p><a href="/login">Try again</a></p>`)

		return
	case err != nil:
		log.Printf("saml-sp: login error: %v", err)
		http.Error(w, "sign-in unavailable", http.StatusServiceUnavailable)

		return
	}

	id := res.Identity

	// The stable key: connection + persistent NameID (never an email).
	// Login mints the session into a scratch header; its cookie is written
	// once, by Touch, after the values are set.
	s, err := a.sessions.Login(r.Context(), http.Header{}, principal{subject: id.ConnectionID + "|" + id.NameID.Value})
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)

		return
	}

	s.Values["mail"] = strings.Join(id.AttributeValues(mailAttribute), ", ")
	if !id.SessionNotOnOrAfter.IsZero() {
		s.Values["saml_session_end"] = id.SessionNotOnOrAfter.Unix()
	}

	if err := a.sessions.Touch(r.Context(), httpsec.NewCarrier(w, r), s); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)

		return
	}

	http.Redirect(w, r, safeReturn(res.AppState), http.StatusSeeOther) //nolint:gosec // G710: safeReturn keeps local paths only
}

// home renders the signed-in page or a login link.
func (a *app) home(w http.ResponseWriter, r *http.Request) {
	s, err := a.sessions.Get(r.Context(), httpsec.NewCarrier(w, r))
	if err != nil || a.samlSessionEnded(s) {
		fmt.Fprint(w, `<h1>Welcome</h1><p><a href="/login">Sign in with your company account</a></p>`)

		return
	}

	sub, _ := s.Values["sub"].(string)
	mail, _ := s.Values["mail"].(string)

	//nolint:gosec // G705: every interpolated value is HTML-escaped
	fmt.Fprintf(w, `<h1>Signed in</h1><p>%s (%s)</p>
<form method="post" action="/logout"><input type="hidden" name="csrf_token" value="%s">
<button type="submit">Log out (local session only, not Single Logout)</button></form>`,
		html.EscapeString(sub), html.EscapeString(mail), html.EscapeString(session.CSRFToken(s)))
}

// samlSessionEnded honors the IdP's SessionNotOnOrAfter (Core §2.7.2): the
// local session must not outlive it.
func (a *app) samlSessionEnded(s *session.Session) bool {
	end, ok := s.Values["saml_session_end"].(int64)
	if !ok {
		f, isFloat := s.Values["saml_session_end"].(float64) // JSON round trip
		end, ok = int64(f), isFloat
	}

	return ok && !a.now().Before(time.Unix(end, 0))
}

// logout ends the local session after checking the CSRF token.
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	carrier := httpsec.NewCarrier(w, r)

	s, err := a.sessions.Get(r.Context(), carrier)
	if err == nil && session.VerifyCSRF(s, r.FormValue("csrf_token")) {
		a.sessions.Logout(r.Context(), carrier)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	path := os.Getenv("SAMLSP_IDP_METADATA")
	if path == "" {
		log.Fatal("saml-sp: set SAMLSP_IDP_METADATA to the trusted IdP metadata file")
	}

	metadata, err := os.ReadFile(path) //nolint:gosec // G304: an administrator-chosen file
	if err != nil {
		log.Fatalf("saml-sp: %v", err)
	}

	baseURL := os.Getenv("SAMLSP_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8084"
	}

	handler, err := newServer(appConfig{baseURL: baseURL, connectionID: "corp", idpMetadata: metadata})
	if err != nil {
		log.Fatalf("saml-sp: %v", err)
	}

	log.Print("saml-sp: listening on :8084")
	log.Fatal(http.ListenAndServe(":8084", handler)) //nolint:gosec // demo server, no timeouts needed
}
