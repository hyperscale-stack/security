// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command connectrpc-bearer is a runnable ConnectRPC Bearer-token demo.
//
// It exposes the gRPC-style health service behind two ConnectRPC interceptors:
// one authenticates every RPC against a JWT, the other authorizes it against
// an OAuth2 scope. The process also mints a demo token at start-up.
//
// Run:
//
//	go run ./connectrpc-bearer
//
// The server logs a ready-to-use token. Probe it with curl over the Connect
// protocol:
//
//	curl -H "Authorization: Bearer <TOKEN>" \
//	     -H "Content-Type: application/json" \
//	     -d '{}' http://localhost:9091/grpc.health.v1.Health/Check
//
// Without the token the call fails with connect.CodeUnauthenticated (HTTP
// 401); with a token that lacks the "health:read" scope it fails with
// connect.CodePermissionDenied (HTTP 403).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/voter"
)

const (
	issuer   = "https://issuer.example"
	audience = "https://connect.example"
	keyID    = "demo-key"
	scope    = "health:read"
	addr     = ":9091"
)

// minter signs a demo JWT carrying the requested scope.
type minter func(scope string) (string, error)

// newServer builds the ConnectRPC handler with the security interceptors and
// returns a token minter sharing the server's signing key. It is separate
// from main so the end-to-end test can serve it over httptest.
func newServer() (http.Handler, minter, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
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

	adm := security.NewAffirmativeDecisionManager(voter.HasScope(scope))

	path, handler := grpchealth.NewHandler(
		grpchealth.NewStaticChecker(grpchealth.HealthV1ServiceName),
		connect.WithInterceptors(
			connectrpcsec.NewAuthenticationInterceptor(engine),
			connectrpcsec.NewAuthorizationInterceptor(adm, []security.Attribute{security.Scope(scope)}),
		),
	)

	mux := http.NewServeMux()
	mux.Handle(path, handler)

	mint := func(grant string) (string, error) {
		now := time.Now()

		token, err := signer.Sign(context.Background(), &jwtsec.StandardClaims{
			Issuer:    issuer,
			Subject:   "demo-user",
			Audience:  jwtsec.Audience{audience},
			IssuedAt:  jwtsec.NewNumericDate(now),
			ExpiresAt: jwtsec.NewNumericDate(now.Add(time.Hour)),
			Scope:     grant,
		})
		if err != nil {
			return "", fmt.Errorf("mint token: %w", err)
		}

		return token, nil
	}

	return mux, mint, nil
}

func main() {
	handler, mint, err := newServer()
	if err != nil {
		log.Fatalf("connectrpc-bearer: %v", err)
	}

	token, err := mint(scope)
	if err != nil {
		log.Fatalf("connectrpc-bearer: %v", err)
	}

	var lc net.ListenConfig

	lis, err := lc.Listen(context.Background(), "tcp", addr) //nolint:gosec // G102: demo server, binding to all interfaces is intentional
	if err != nil {
		log.Fatalf("connectrpc-bearer: listen: %v", err)
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("connectrpc-bearer: listening on %s", addr)
	log.Printf("connectrpc-bearer: demo token: %s", token)
	log.Fatal(srv.Serve(lis))
}
