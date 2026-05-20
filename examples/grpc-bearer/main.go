// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command grpc-bearer is a runnable gRPC Bearer-token demo.
//
// It exposes the standard gRPC health service behind two interceptors: one
// authenticates every RPC against a JWT, the other authorizes it against an
// OAuth2 scope. The process also mints a demo token at start-up.
//
// Run:
//
//	go run ./grpc-bearer
//
// The server logs a ready-to-use token. Probe it with grpcurl:
//
//	grpcurl -plaintext \
//	    -H "authorization: Bearer <TOKEN>" \
//	    localhost:9090 grpc.health.v1.Health/Check
//
// Without the token the call fails with codes.Unauthenticated; with a token
// that lacks the "health:read" scope it fails with codes.PermissionDenied.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/voter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	issuer   = "https://issuer.example"
	audience = "https://grpc.example"
	keyID    = "demo-key"
	scope    = "health:read"
)

// minter signs a demo JWT carrying the requested scope.
type minter func(scope string) (string, error)

// newServer builds the gRPC server with the security interceptors and
// returns a token minter sharing the server's signing key. It is separate
// from main so the end-to-end test can serve it over an in-memory listener.
func newServer() (*grpc.Server, minter, error) {
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

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcsec.UnaryServerInterceptor(engine),
			grpcsec.UnaryAuthorize(adm, []security.Attribute{security.Scope(scope)}),
		),
	)
	healthpb.RegisterHealthServer(srv, health.NewServer())

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

	return srv, mint, nil
}

func main() {
	srv, mint, err := newServer()
	if err != nil {
		log.Fatalf("grpc-bearer: %v", err)
	}

	token, err := mint(scope)
	if err != nil {
		log.Fatalf("grpc-bearer: %v", err)
	}

	addr := ":9090"

	var lc net.ListenConfig

	lis, err := lc.Listen(context.Background(), "tcp", addr) //nolint:gosec // G102: demo server, binding to all interfaces is intentional
	if err != nil {
		log.Fatalf("grpc-bearer: listen: %v", err)
	}

	log.Printf("grpc-bearer: listening on %s", addr)
	log.Printf("grpc-bearer: demo token: %s", token)
	log.Fatal(srv.Serve(lis))
}
