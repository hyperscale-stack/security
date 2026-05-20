// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command session-web is a runnable cookie-session web demo.
//
// It is a tiny login-form application: a successful login mints an
// encrypted session cookie, the home page reads it, and logout clears it.
// The logout form is protected by a CSRF synchronizer token.
//
// Run:
//
//	go run ./session-web
//
// Then open http://localhost:8082 in a browser and log in with
// alice / alice-secret. The session cookie is AES-256-GCM sealed; tampering
// with it simply drops the session.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"html"
	"log"
	"net/http"

	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/hyperscale-stack/security/password"
	"github.com/hyperscale-stack/security/session"
)

// principal is the minimal [security.Principal] stored on login.
type principal struct{ subject string }

func (p principal) Subject() string { return p.subject }

// app holds the demo dependencies.
type app struct {
	manager *session.Manager
	hasher  password.Hasher
	users   map[string]string // username -> bcrypt hash
}

// newServer builds the demo handler. It is separate from main so the
// end-to-end test can drive the exact same wiring.
func newServer() (http.Handler, error) {
	key := make([]byte, 32) // AES-256
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
		hasher:  hasher,
		users:   map[string]string{"alice": aliceHash},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.home)
	mux.HandleFunc("GET /login", a.loginForm)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /logout", a.logout)

	return mux, nil
}

// home renders the protected page, or redirects to the login form when no
// valid session cookie is present.
func (a *app) home(w http.ResponseWriter, r *http.Request) {
	s, err := a.manager.Get(r.Context(), httpsec.NewCarrier(w, r))
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)

		return
	}

	sub, _ := s.Values["sub"].(string)

	//nolint:gosec // G705: both interpolated values are HTML-escaped above
	fmt.Fprintf(w, `<h1>Welcome %s</h1>
<form method="post" action="/logout">
<input type="hidden" name="csrf_token" value="%s">
<button type="submit">Log out</button>
</form>`, html.EscapeString(sub), html.EscapeString(session.CSRFToken(s)))
}

// loginForm renders the login form.
func (a *app) loginForm(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, `<h1>Sign in</h1>
<form method="post" action="/login">
<input name="username" placeholder="username">
<input name="password" type="password" placeholder="password">
<button type="submit">Sign in</button>
</form>`)
}

// login verifies the credentials and mints a session on success.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	hash, ok := a.users[username]

	if ok {
		match, err := a.hasher.Verify(r.Context(), hash, r.FormValue("password"))
		if err == nil && match {
			if _, err := a.manager.Login(r.Context(), httpsec.NewCarrier(w, r), principal{subject: username}); err != nil {
				http.Error(w, "session error", http.StatusInternalServerError)

				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)

			return
		}
	}

	// Same response for unknown user and wrong password (anti-enumeration).
	http.Error(w, "invalid credentials", http.StatusUnauthorized)
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

func main() {
	handler, err := newServer()
	if err != nil {
		log.Fatalf("session-web: %v", err)
	}

	addr := ":8082"
	log.Printf("session-web: listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler)) //nolint:gosec // demo server, no timeouts needed
}
