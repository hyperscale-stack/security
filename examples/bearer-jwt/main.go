// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command bearer-jwt is a runnable JWT bearer-token demo.
//
// It plays both roles in one process: a tiny issuer that mints an
// EdDSA-signed RFC 9068 access token at start-up, and a resource server
// that validates the Bearer token on every request and gates one route on
// an OAuth2 scope. A real issuer authenticates its clients before minting
// tokens: the demo has no public token endpoint, it writes its token —
// valid 15 minutes — to a file only the current user can read, logs the
// file's path (never the token) and removes the file when it stops.
//
// Run:
//
//	go run ./bearer-jwt
//
// Probe — read the token from the file the demo logged:
//
//	TOKEN=$(cat /path/from/the/log)
//
// Probe — call the protected route:
//
//	curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8081/
//
// Probe — call the scope-gated route (token carries "resource:read"):
//
//	curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8081/reports
//
// Probe — no token -> 401:
//
//	curl -i http://localhost:8081/
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	httpsec "github.com/hyperscale-stack/security/http"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	oauth2token "github.com/hyperscale-stack/security/oauth2/token"
	"github.com/hyperscale-stack/security/voter"
)

const (
	issuer   = "https://issuer.example"
	audience = "https://api.example"
	keyID    = "demo-key"
	clientID = "demo-client"
)

// tokenLifetime is the lifetime of the demo tokens: short, a leaked one
// expires soon.
const tokenLifetime = 15 * time.Minute

// minter signs a demo access token carrying scope, issued at issuedAt.
type minter func(scope string, issuedAt time.Time) (string, error)

// newServer builds the demo handler and the minter sharing its signing key.
// The signer mints tokens, the verifier validates them; in a real deployment
// those live in separate processes and the resource server fetches the
// issuer's public keys over JWKS. It is separate from main so the
// end-to-end test drives the same wiring.
func newServer() (http.Handler, minter, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	signer, err := jwtsec.NewOAuth2AccessTokenSigner(jwtsec.PrivateKey{
		KeyID:     keyID,
		Algorithm: jwtsec.EdDSA,
		Key:       priv,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("signer: %w", err)
	}

	jwks := jwtsec.NewStaticJWKS([]jwtsec.PublicKey{{
		KeyID:     keyID,
		Algorithm: jwtsec.EdDSA,
		Key:       pub,
	}})

	verifier := jwtsec.NewVerifier(jwks,
		jwtsec.WithIssuer(issuer),
		jwtsec.WithAudience(audience),
		jwtsec.WithType(jwtsec.TypeAccessToken), // RFC 9068 §4: refuse ID Tokens
	)

	engine := security.NewEngine(
		security.NewManager(bearer.NewAuthenticator(jwtsec.BearerVerifier(verifier, nil))),
		bearer.NewExtractor(),
	)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth, _ := security.FromContext(r.Context())

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		//nolint:gosec // G705: name is the authenticated identity, written escaped to a text/plain body
		fmt.Fprintf(w, "hello %s (authorities: %s)\n",
			html.EscapeString(auth.Name()), html.EscapeString(fmt.Sprint(auth.Authorities())))
	})

	reports := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "here are your reports")
	})

	adm := security.NewAffirmativeDecisionManager(voter.HasScope("resource:read"))
	mux.Handle("/reports", httpsec.Authorize(adm, security.Scope("resource:read"))(reports))

	mint := func(scope string, issuedAt time.Time) (string, error) {
		token, err := signer.SignAccessToken(context.Background(), oauth2token.AccessTokenClaims{
			Issuer:    issuer,
			Subject:   "demo-user",
			Audience:  audience,
			ClientID:  clientID,
			IssuedAt:  issuedAt,
			ExpiresAt: issuedAt.Add(tokenLifetime),
			Scope:     scope,
		})
		if err != nil {
			return "", fmt.Errorf("mint token: %w", err)
		}

		return token, nil
	}

	// Every route requires a valid token.
	return httpsec.Middleware(engine)(mux), mint, nil
}

// writeDemoToken writes token to a new file in dir (the system's temporary
// directory when dir is "") that only the current user can read, and
// returns its path: the demo never prints a credential to its logs.
func writeDemoToken(dir, token string) (string, error) {
	f, err := os.CreateTemp(dir, "bearer-jwt-*.token") // mode 0600
	if err != nil {
		return "", fmt.Errorf("create token file: %w", err)
	}

	if _, err := f.WriteString(token); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())

		return "", fmt.Errorf("write token file: %w", err)
	}

	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close token file: %w", err)
	}

	return f.Name(), nil
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
	handler, mint, err := newServer()
	if err != nil {
		log.Fatalf("bearer-jwt: %v", err)
	}

	token, err := mint("resource:read", time.Now())
	if err != nil {
		log.Fatalf("bearer-jwt: %v", err)
	}

	path, err := writeDemoToken("", token)
	if err != nil {
		log.Fatalf("bearer-jwt: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := newHTTPServer(":8081", handler)

	go func() {
		<-ctx.Done()

		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = srv.Shutdown(shutdown)
	}()

	log.Printf("bearer-jwt: listening on %s; demo token (valid %s) in %s", srv.Addr, tokenLifetime, path)

	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Printf("bearer-jwt: %v", err)
	}

	_ = os.Remove(path)
}
