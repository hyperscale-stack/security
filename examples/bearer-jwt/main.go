// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command bearer-jwt is a runnable JWT bearer-token demo.
//
// It plays both roles in one process: a tiny issuer that mints EdDSA-signed
// JWTs, and a resource server that validates the Bearer token on every
// request and gates one route on an OAuth2 scope.
//
// Run:
//
//	go run ./bearer-jwt
//
// Probe — mint a token:
//
//	TOKEN=$(curl -s -X POST http://localhost:8081/token | sed 's/.*"access_token":"//;s/".*//')
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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	httpsec "github.com/hyperscale-stack/security/http"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/voter"
)

const (
	issuer   = "https://issuer.example"
	audience = "https://api.example"
	keyID    = "demo-key"
)

// newServer builds the demo handler. The signer mints tokens, the verifier
// validates them; in a real deployment those live in separate processes and
// the resource server fetches the issuer's public keys over JWKS.
func newServer() (http.Handler, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	signer := jwtsec.NewSigner(jwtsec.PrivateKey{
		KeyID:     keyID,
		Algorithm: jwtsec.EdDSA,
		Key:       priv,
	})

	jwks := jwtsec.NewStaticJWKS([]jwtsec.PublicKey{{
		KeyID:     keyID,
		Algorithm: jwtsec.EdDSA,
		Key:       pub,
	}})

	verifier := jwtsec.NewVerifier(jwks,
		jwtsec.WithIssuer(issuer),
		jwtsec.WithAudience(audience),
	)

	engine := security.NewEngine(
		security.NewManager(bearer.NewAuthenticator(jwtsec.BearerVerifier(verifier, nil))),
		bearer.NewExtractor(),
	)

	mux := http.NewServeMux()

	// /token mints a demo token. A real issuer would authenticate the
	// caller and derive the subject + scopes from the grant.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()

		token, err := signer.Sign(r.Context(), &jwtsec.StandardClaims{
			Issuer:    issuer,
			Subject:   "demo-user",
			Audience:  jwtsec.Audience{audience},
			IssuedAt:  jwtsec.NewNumericDate(now),
			ExpiresAt: jwtsec.NewNumericDate(now.Add(time.Hour)),
			Scope:     "resource:read",
		})
		if err != nil {
			http.Error(w, "mint failed", http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": token})
	})

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

	// The /token route is public; everything else requires a valid token.
	protected := httpsec.Middleware(engine)(mux)

	root := http.NewServeMux()
	root.Handle("/token", mux)
	root.Handle("/", protected)

	return root, nil
}

func main() {
	handler, err := newServer()
	if err != nil {
		log.Fatalf("bearer-jwt: %v", err)
	}

	addr := ":8081"
	log.Printf("bearer-jwt: listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler)) //nolint:gosec // demo server, no timeouts needed
}
