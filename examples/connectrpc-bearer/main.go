// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command connectrpc-bearer is a runnable ConnectRPC Bearer-token demo.
//
// It exposes the gRPC-style health service behind two ConnectRPC interceptors:
// one authenticates every RPC against a JWT, the other authorizes it against
// an OAuth2 scope. The process also mints a demo token — valid 15 minutes —
// at start-up, writes it to a file only the current user can read, logs the
// file's path (never the token) and removes the file when it stops.
//
// Run:
//
//	go run ./connectrpc-bearer
//
// Probe it with curl over the Connect protocol, reading the token from the
// file the server logged:
//
//	curl -H "Authorization: Bearer $(cat /path/from/the/log)" \
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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	oauth2token "github.com/hyperscale-stack/security/oauth2/token"
	"github.com/hyperscale-stack/security/voter"
)

const (
	issuer   = "https://issuer.example"
	audience = "https://connect.example"
	keyID    = "demo-key"
	clientID = "demo-client"
	scope    = "health:read"
	addr     = ":9091"
)

// tokenLifetime is the lifetime of the demo tokens: short, a leaked one
// expires soon.
const tokenLifetime = 15 * time.Minute

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

		token, err := signer.SignAccessToken(context.Background(), oauth2token.AccessTokenClaims{
			Issuer:    issuer,
			Subject:   "demo-user",
			Audience:  audience,
			ClientID:  clientID,
			IssuedAt:  now,
			ExpiresAt: now.Add(tokenLifetime),
			Scope:     grant,
		})
		if err != nil {
			return "", fmt.Errorf("mint token: %w", err)
		}

		return token, nil
	}

	return mux, mint, nil
}

// writeDemoToken writes token to a new file in dir (the system's temporary
// directory when dir is "") that only the current user can read, and
// returns its path: the demo never prints a credential to its logs.
func writeDemoToken(dir, token string) (string, error) {
	f, err := os.CreateTemp(dir, "connectrpc-bearer-*.token") // mode 0600
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
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
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
		log.Fatalf("connectrpc-bearer: %v", err)
	}

	token, err := mint(scope)
	if err != nil {
		log.Fatalf("connectrpc-bearer: %v", err)
	}

	path, err := writeDemoToken("", token)
	if err != nil {
		log.Fatalf("connectrpc-bearer: %v", err)
	}

	defer func() { _ = os.Remove(path) }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lc net.ListenConfig

	lis, err := lc.Listen(ctx, "tcp", addr) //nolint:gosec // G102: demo server, binding to all interfaces is intentional
	if err != nil {
		log.Printf("connectrpc-bearer: listen: %v", err)

		return
	}

	srv := newHTTPServer(handler)

	go func() {
		<-ctx.Done()

		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = srv.Shutdown(shutdown)
	}()

	log.Printf("connectrpc-bearer: listening on %s; demo token (valid %s) in %s", addr, tokenLifetime, path)

	if err := srv.Serve(lis); !errors.Is(err, http.ErrServerClosed) {
		log.Printf("connectrpc-bearer: %v", err)
	}
}
