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
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

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

// maxReturnLen bounds a return target.
const maxReturnLen = 1024

// safeReturn returns target when it is a local path, "/" otherwise: the
// target lives server-side in the transaction, but it came from the browser
// (no open redirect). It accepts an absolute path, with an optional query,
// made of RFC 3986 path and query characters only, starting with exactly
// one slash, which stays a local path once percent-decoded. Everything else
// is refused rather than cleaned: browsers drop TAB, LF and CR inside a URL
// ("/\t/evil.example" is "//evil.example", another origin) and treat "\"
// as "/". With one leading slash and no "\", no browser or url.Parse can
// read a scheme or a host in the result.
func safeReturn(target string) string {
	if len(target) > maxReturnLen || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return "/"
	}

	for i := 0; i < len(target); i++ {
		if !isPathOrQueryChar(target[i]) {
			return "/"
		}
	}

	path, _, _ := strings.Cut(target, "?")

	decoded, err := url.PathUnescape(path)
	if err != nil || strings.HasPrefix(decoded, "//") || strings.ContainsFunc(decoded, func(r rune) bool {
		return r == '\\' || unicode.IsControl(r) || unicode.IsSpace(r)
	}) {
		return "/"
	}

	return target
}

// isPathOrQueryChar reports the RFC 3986 characters of a path and a query
// (§3.3, §3.4): unreserved, sub-delims, ":", "@", "/", "?" and "%" (whose
// escapes safeReturn decodes and checks).
func isPathOrQueryChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	default:
		return strings.IndexByte("-._~!$&'()*+,;=:@/?%", c) >= 0
	}
}

// accountKey is the application's key for the external account of id: the
// connection, the issuer, the NameID qualifiers (absent ones stand for the
// issuer and the SP) and the NameID, each length-prefixed so that no two
// identities share a key ("a|b"+"c" and "a"+"b|c" would). The connection
// requires a persistent NameID: transient NameIDs and email attributes never
// key accounts, and accounts are never linked by email.
func accountKey(id *samlsp.Identity) string {
	var b strings.Builder

	for _, part := range []string{
		id.ConnectionID, id.Issuer,
		cmp.Or(id.NameID.NameQualifier, id.Issuer), cmp.Or(id.NameID.SPNameQualifier, id.Audience),
		id.NameID.Format, id.NameID.Value,
	} {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
		b.WriteByte(';')
	}

	return b.String()
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
	s, err := a.sessions.Login(r.Context(), http.Header{}, principal{subject: accountKey(&id)})
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)

		return
	}

	s.Values["nameid"] = id.NameID.Value
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

	nameID, _ := s.Values["nameid"].(string)
	mail, _ := s.Values["mail"].(string)

	//nolint:gosec // G705: every interpolated value is HTML-escaped
	fmt.Fprintf(w, `<h1>Signed in</h1><p>%s (%s)</p>
<form method="post" action="/logout"><input type="hidden" name="csrf_token" value="%s">
<button type="submit">Log out (local session only, not Single Logout)</button></form>`,
		html.EscapeString(nameID), html.EscapeString(mail), html.EscapeString(session.CSRFToken(s)))
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
