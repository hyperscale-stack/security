// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command basic-http is a runnable HTTP Basic authentication demo.
//
// It wires the security core into a net/http server: every request is
// authenticated against an in-memory user store, and the /admin route is
// additionally gated by a role-based authorization decision.
//
// Run:
//
//	go run ./basic-http
//
// Probe — public identity behind Basic auth:
//
//	curl -i -u alice:alice-secret http://localhost:8080/
//
// Probe — admin route (alice is not an admin -> 403):
//
//	curl -i -u alice:alice-secret http://localhost:8080/admin
//
// Probe — admin route as an admin -> 200:
//
//	curl -i -u root:root-secret http://localhost:8080/admin
//
// Probe — wrong password -> 401:
//
//	curl -i -u alice:nope http://localhost:8080/
//
// Every 401 carries the challenge of the scheme the server accepts,
// `WWW-Authenticate: Basic realm="basic-http", charset="UTF-8"` (RFC 7617).
package main

import (
	"context"
	"fmt"
	"html"
	"log"
	"net/http"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/hyperscale-stack/security/password"
	"github.com/hyperscale-stack/security/voter"
)

// user is an in-memory [basic.PasswordUser]. A real application would back
// this with a database row.
type user struct {
	subject string
	hash    string
	roles   []string
}

func (u user) Subject() string            { return u.subject }
func (u user) GetPasswordHash() string    { return u.hash }
func (u user) IsEnabled() bool            { return true }
func (u user) IsLocked() bool             { return false }
func (u user) IsExpired() bool            { return false }
func (u user) IsCredentialsExpired() bool { return false }

// loader is an in-memory [basic.UserLoader].
type loader struct{ users map[string]user }

// LoadByUsername implements [basic.UserLoader]. An unknown user yields an
// error wrapping [security.ErrInvalidCredentials] so the response is
// indistinguishable from a wrong password (anti-enumeration). The error does
// not echo the typed username: it may be a password typed in the wrong
// field.
func (l loader) LoadByUsername(_ context.Context, username string) (basic.PasswordUser, error) {
	u, ok := l.users[username]
	if !ok {
		return nil, fmt.Errorf("unknown user: %w", security.ErrInvalidCredentials)
	}

	return u, nil
}

// newServer builds the demo HTTP handler. It is separate from main so the
// end-to-end test can exercise the exact same wiring.
func newServer() (http.Handler, error) {
	hasher := password.NewBCryptHasher(10)

	ctx := context.Background()

	aliceHash, err := hasher.Hash(ctx, "alice-secret")
	if err != nil {
		return nil, fmt.Errorf("hash alice: %w", err)
	}

	rootHash, err := hasher.Hash(ctx, "root-secret")
	if err != nil {
		return nil, fmt.Errorf("hash root: %w", err)
	}

	// Roles are carried as ROLE_<name> authorities (security.RolePrefix):
	// that is what voter.HasRole matches.
	store := loader{users: map[string]user{
		"alice": {subject: "alice", hash: aliceHash, roles: []string{"ROLE_USER"}},             //nolint:goconst // example code, readability over deduplication
		"root":  {subject: "root", hash: rootHash, roles: []string{"ROLE_USER", "ROLE_ADMIN"}}, //nolint:goconst // example code, readability over deduplication
	}}

	authenticator := basic.NewAuthenticator(store, hasher,
		basic.WithAuthorityResolver(func(u basic.PasswordUser) []string {
			if known, ok := u.(user); ok {
				return known.roles
			}

			return nil
		}),
	)

	engine := security.NewEngine(
		security.NewManager(authenticator),
		basic.NewExtractor(),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth, _ := security.FromContext(r.Context())

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		//nolint:gosec // G705: name is the authenticated identity, written escaped to a text/plain body
		fmt.Fprintf(w, "hello %s (roles: %s)\n",
			html.EscapeString(auth.Name()), html.EscapeString(fmt.Sprint(auth.Authorities())))
	})

	admin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, _ := security.FromContext(r.Context())

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		//nolint:gosec // G705: name is the authenticated identity, written escaped to a text/plain body
		fmt.Fprintf(w, "admin area, welcome %s\n", html.EscapeString(auth.Name()))
	})

	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))
	mux.Handle("/admin", httpsec.Authorize(adm, security.Role("ADMIN"))(admin))

	// The challenge names the scheme the extractors accept: Basic, with the
	// realm RFC 7617 §2 requires (the default challenge is Bearer).
	return httpsec.Middleware(engine, httpsec.WithChallengeScheme("Basic"), httpsec.WithRealm(realm))(mux), nil
}

// realm is the protection space of the demo (RFC 7617 §2).
const realm = "basic-http"

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
		log.Fatalf("basic-http: %v", err)
	}

	addr := ":8080"
	log.Printf("basic-http: listening on %s", addr)
	log.Fatal(newHTTPServer(addr, handler).ListenAndServe())
}
