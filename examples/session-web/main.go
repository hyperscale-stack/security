// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command session-web is a runnable cookie-session web demo.
//
// It is a tiny login-form application: a successful login mints an
// encrypted session cookie, the home page reads it, and logout clears it.
// Both forms are protected against CSRF: the sign-in form by the token of a
// session opened for it (against login CSRF), the logout form by the
// session's token; net/http's CrossOriginProtection also refuses
// cross-origin form posts. The credentials are checked by a
// basic.Authenticator, which spends one password verification on every
// attempt, so the response time does not tell which accounts exist.
//
// Run:
//
//	go run ./session-web
//
// Then open http://localhost:8082 in a browser and log in with
// alice / alice-secret. The session cookie, __Host-session, is AES-256-GCM
// sealed; tampering with it simply drops the session.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"html"
	"log"
	"net/http"
	"time"

	"github.com/hyperscale-stack/security/basic"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/hyperscale-stack/security/password"
	"github.com/hyperscale-stack/security/session"
)

// user is an in-memory [basic.PasswordUser]. A real application would back
// this with a database row.
type user struct{ subject, hash string }

func (u user) Subject() string            { return u.subject }
func (u user) GetPasswordHash() string    { return u.hash }
func (u user) IsEnabled() bool            { return true }
func (u user) IsLocked() bool             { return false }
func (u user) IsExpired() bool            { return false }
func (u user) IsCredentialsExpired() bool { return false }

// users is an in-memory [basic.UserLoader]: an unknown user is (nil, nil),
// and the Authenticator verifies the password against its dummy hash.
type users map[string]user

// demoUser is the demo account (password alice-secret).
const demoUser = "alice"

func (u users) LoadByUsername(_ context.Context, username string) (basic.PasswordUser, error) {
	known, ok := u[username]
	if !ok {
		return nil, nil
	}

	return known, nil
}

// app holds the demo dependencies.
type app struct {
	manager *session.Manager
	login   *basic.Authenticator
}

// newServer builds the demo handler. It is separate from main so the
// end-to-end test can drive the exact same wiring.
func newServer() (http.Handler, error) {
	key := make([]byte, session.MinKeySize) // in production: from your secret store
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate codec key: %w", err)
	}

	codec, err := session.NewCodec(key)
	if err != nil {
		return nil, fmt.Errorf("new codec: %w", err)
	}

	hasher := password.NewBCryptHasher(10)

	aliceHash, err := hasher.Hash(context.Background(), "alice-secret")
	if err != nil {
		return nil, fmt.Errorf("hash alice: %w", err)
	}

	a := &app{
		manager: session.NewManager(codec),
		login:   basic.NewAuthenticator(users{demoUser: {subject: demoUser, hash: aliceHash}}, hasher),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.home)
	mux.HandleFunc("GET /login", a.loginForm)
	mux.HandleFunc("POST /login", a.signIn)
	mux.HandleFunc("POST /logout", a.logout)

	// Refuses cross-origin unsafe requests (Sec-Fetch-Site, Origin): a
	// second line of defense against CSRF next to the synchronizer tokens.
	return http.NewCrossOriginProtection().Handler(mux), nil
}

// home renders the protected page, or redirects to the login form when the
// request carries no signed-in session.
func (a *app) home(w http.ResponseWriter, r *http.Request) {
	s, err := a.manager.Get(r.Context(), httpsec.NewCarrier(w, r))
	if err != nil || s.GetString("sub") == "" { // a session opened for the form is not signed in
		http.Redirect(w, r, "/login", http.StatusSeeOther)

		return
	}

	//nolint:gosec // G705: both interpolated values are HTML-escaped
	fmt.Fprintf(w, `<h1>Welcome %s</h1>
<form method="post" action="/logout">
<input type="hidden" name="csrf_token" value="%s">
<button type="submit">Log out</button>
</form>`, html.EscapeString(s.GetString("sub")), html.EscapeString(session.CSRFToken(s)))
}

// loginForm renders the login form with the CSRF token of the browser's
// session, opening one for the form when there is none: without it another
// site could post its own credentials and sign the victim into the
// attacker's account (login CSRF).
func (a *app) loginForm(w http.ResponseWriter, r *http.Request) {
	carrier := httpsec.NewCarrier(w, r)

	s, err := a.manager.Get(r.Context(), carrier)
	if err != nil {
		if s, err = a.manager.Login(r.Context(), carrier, nil); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)

			return
		}
	}

	//nolint:gosec // G705: the interpolated token is HTML-escaped
	fmt.Fprintf(w, `<h1>Sign in</h1>
<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="%s">
<input name="username" placeholder="username">
<input name="password" type="password" placeholder="password">
<button type="submit">Sign in</button>
</form>`, html.EscapeString(session.CSRFToken(s)))
}

// signIn checks the form's CSRF token, verifies the credentials and mints a
// fresh session — new ID, new CSRF token, new lifetime — on success.
func (a *app) signIn(w http.ResponseWriter, r *http.Request) {
	carrier := httpsec.NewCarrier(w, r)

	form, err := a.manager.Get(r.Context(), carrier)
	if err != nil || !session.VerifyCSRF(form, r.FormValue("csrf_token")) {
		http.Error(w, "bad CSRF token: reload the sign-in form", http.StatusForbidden)

		return
	}

	auth, err := a.login.Authenticate(r.Context(), basic.New(r.FormValue("username"), r.FormValue("password")))
	if err != nil {
		// Same response for unknown user, wrong password and malformed
		// input (anti-enumeration).
		http.Error(w, "invalid credentials", http.StatusUnauthorized)

		return
	}

	if _, err := a.manager.Login(r.Context(), carrier, auth.Principal()); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)

		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logout clears the session after checking the CSRF token.
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	carrier := httpsec.NewCarrier(w, r)

	s, err := a.manager.Get(r.Context(), carrier)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)

		return
	}

	if !session.VerifyCSRF(s, r.FormValue("csrf_token")) {
		http.Error(w, "bad CSRF token", http.StatusForbidden)

		return
	}

	a.manager.Logout(r.Context(), carrier)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

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

func main() {
	handler, err := newServer()
	if err != nil {
		log.Fatalf("session-web: %v", err)
	}

	addr := ":8082"
	log.Printf("session-web: listening on %s", addr)
	log.Fatal(newHTTPServer(addr, handler).ListenAndServe())
}
