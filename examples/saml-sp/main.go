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
// prefixed cookies there. The server listens on 127.0.0.1:8084 (SAMLSP_ADDR
// changes it) with read, write and idle timeouts, and refuses logins
// started from another site (Sec-Fetch-Site).
//
// SAMLSP_TRANSACTION_KEYS holds the keys protecting the pending logins in
// the transaction store (samlsp.Config.TransactionKeys): hex-encoded keys
// of at least 32 bytes, separated by commas, the same on every instance and
// kept in a secret store (openssl rand -hex 32). Unset, a random key is
// drawn for this process only.
//
// SAMLSP_RESPONSE_ORIGINS, when set, lists the origins of the IdP pages
// allowed to post responses to the ACS (samlsp.Connection.ResponseOrigins),
// separated by commas, e.g. https://idp.example.com: a response posted from
// another site — the login CSRF a leaked IdP redirect URL allows — is then
// refused. Leave it unset for an IdP whose response page hides its origin
// (Referrer-Policy no-referrer): browsers then post "Origin: null".
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	// transactionKeys protect the pending logins in the transaction store
	// (samlsp.Config.TransactionKeys): secret, the same on every instance.
	transactionKeys [][]byte
	// responseOrigins are the IdP origins allowed to post to the ACS
	// (samlsp.Connection.ResponseOrigins); empty: not checked.
	responseOrigins []string
	now             func() time.Time
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
		ResponseOrigins:  cfg.responseOrigins,
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
		Connections:     connections,
		Transactions:    store,
		ReplayCache:     store,
		TransactionKeys: cfg.transactionKeys,
		Now:             cfg.now,
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

// login starts an SP-initiated login with the configured connection. A page
// of another site must not be able to start one in the user's browser
// (forced login initiation, a form of login CSRF): browsers send
// Sec-Fetch-Site with every navigation, and only same-origin navigations
// and the user's own (a typed URL or a bookmark: "none") are accepted.
// Requests without it (older browsers, scripts) are accepted; an
// application needing more serves the entry point behind a CSRF-protected
// POST.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		http.Error(w, "sign-in must start from this site", http.StatusForbidden)

		return
	}

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
// local session must not outlive it. Session numbers come back from the
// cookie as json.Number (GetInt64 reads them); a value that is present but
// unreadable ends the session — failing open would keep a session the IdP
// has closed.
func (a *app) samlSessionEnded(s *session.Session) bool {
	if _, present := s.Values["saml_session_end"]; !present {
		return false
	}

	end, ok := s.GetInt64("saml_session_end")

	return !ok || !a.now().Before(time.Unix(end, 0))
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

	keys, err := transactionKeys(os.Getenv("SAMLSP_TRANSACTION_KEYS"))
	if err != nil {
		log.Fatalf("saml-sp: %v", err)
	}

	handler, err := newServer(appConfig{
		baseURL: baseURL, connectionID: "corp", idpMetadata: metadata, transactionKeys: keys,
		responseOrigins: responseOrigins(os.Getenv("SAMLSP_RESPONSE_ORIGINS")),
	})
	if err != nil {
		log.Fatalf("saml-sp: %v", err)
	}

	addr := os.Getenv("SAMLSP_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	log.Print("saml-sp: listening")
	log.Fatal(newHTTPServer(addr, handler).ListenAndServe())
}

// responseOrigins splits SAMLSP_RESPONSE_ORIGINS on commas; the connection
// validates each origin.
func responseOrigins(raw string) []string {
	var out []string

	for part := range strings.SplitSeq(raw, ",") {
		if origin := strings.TrimSpace(part); origin != "" {
			out = append(out, origin)
		}
	}

	return out
}

// errKeyNotHex reports a malformed SAMLSP_TRANSACTION_KEYS entry.
var errKeyNotHex = errors.New("not hex-encoded")

// transactionKeys decodes SAMLSP_TRANSACTION_KEYS: hex-encoded keys
// separated by commas. Unset, it draws one random key — for a single
// development instance only: the logins in progress do not survive a
// restart.
func transactionKeys(raw string) ([][]byte, error) {
	if strings.TrimSpace(raw) == "" {
		key := make([]byte, samlsp.MinTransactionKeySize)
		_, _ = rand.Read(key) // crypto/rand.Read never fails

		log.Print("saml-sp: SAMLSP_TRANSACTION_KEYS is not set: using a random per-process transaction key " +
			"(logins in progress fail on a restart and cannot span instances)")

		return [][]byte{key}, nil
	}

	var keys [][]byte

	for part := range strings.SplitSeq(raw, ",") {
		key, err := hex.DecodeString(strings.TrimSpace(part))
		if err != nil {
			// Not wrapped: the decoder's error would echo a character of the key.
			return nil, fmt.Errorf("SAMLSP_TRANSACTION_KEYS: key %d: %w", len(keys)+1, errKeyNotHex)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// defaultAddr is the listening address: the loopback interface. Set
// SAMLSP_ADDR to listen elsewhere, behind a TLS-terminating proxy.
const defaultAddr = "127.0.0.1:8084"

// newHTTPServer bounds the time a client may take at every stage, so that
// slow clients cannot hold connections open.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}
