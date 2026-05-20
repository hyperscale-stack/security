// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package main demonstrates wiring of the v2 security library: an OAuth2
// authorization server (client_credentials + refresh_token) plus a
// resource server protected by a bearer middleware sharing the same
// storage as the auth server.
//
// Run:
//
//	go run ./example/oauth2
//
// Probe — request an access token:
//
//	curl -i -u 5cc06c3b-5755-4229-958c-a515a245aaeb:WTvuAztPD2XBauomleRzGFYuZawS07Ym \
//	    -d 'grant_type=client_credentials&scope=api:read' \
//	    http://localhost:1337/oauth2/token
//
// Probe — call the protected resource with the issued token:
//
//	TOKEN=...  # from the previous response
//	curl -i -H "Authorization: Bearer $TOKEN" http://localhost:1337/protected
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// Demo credentials. Hard-coded for the example; in real usage these come
// from a client store seeded out-of-band.
const (
	demoClientID     = "5cc06c3b-5755-4229-958c-a515a245aaeb"
	demoClientSecret = "WTvuAztPD2XBauomleRzGFYuZawS07Ym" //nolint:gosec // demo
)

// pepper is the server-wide secret used to hash tokens before persistence.
// In production load it from a secret store; never commit it.
var pepper = []byte("demo-pepper-do-not-use-in-production")

// staticClientStore is a tiny in-memory [oauth2.ClientStore] suitable for
// dev / demos. Production deployments plug a database-backed store.
type staticClientStore struct{ clients map[string]oauth2.Client }

func (s *staticClientStore) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, nil
	}

	return c, nil
}

// localIntrospectVerifier is the in-process verifier used by the resource
// server. It hashes the bearer token and queries the OAuth2 storage —
// the local equivalent of an RFC 7662 introspection call.
type localIntrospectVerifier struct {
	store  oauth2.AccessTokenStore
	pepper []byte
}

// Verify implements [bearer.TokenVerifier].
func (v *localIntrospectVerifier) Verify(ctx context.Context, tok string) (security.Authentication, error) {
	hash := oauth2.HashToken(v.pepper, tok)

	at, err := v.store.LookupAccessToken(ctx, hash)
	if err != nil {
		return nil, security.ErrTokenNotFound
	}

	if at.IsExpired(time.Now()) {
		return nil, security.ErrTokenExpired
	}

	return bearer.New(tok).WithAuthenticated(principal{sub: at.Subject}, nil, at.Subject), nil
}

type principal struct{ sub string }

func (p principal) Subject() string { return p.sub }

// buildServer wires the authorization server and the Bearer-protected
// resource server onto a single mux. It is separate from main so the
// end-to-end test can exercise the exact same wiring.
func buildServer() (http.Handler, error) {
	// Storage shared between the authorization server and the resource
	// server. In a multi-process deployment each side uses its own
	// storage implementation (SQL / Redis / introspection HTTP call).
	store := memory.New()

	// Seed a demo confidential client.
	clients := &staticClientStore{clients: map[string]oauth2.Client{
		demoClientID: &oauth2.DefaultClient{
			IDValue:           demoClientID,
			Secret:            demoClientSecret,
			TypeValue:         oauth2.ClientConfidential,
			RedirectURIValues: []string{"https://connect.myservice.tld"},
			ScopeValues:       []string{"api:read"},
		},
	}}

	// Authorization server.
	gcfg := grant.Config{
		Storage:             store,
		AccessTokens:        token.NewOpaque(pepper, 32),
		RefreshTokens:       token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(pepper, 32)},
		AccessTTL:           time.Hour,
		RefreshTTL:          24 * time.Hour,
		RotateRefreshTokens: true,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("http://localhost:1337", "api"),
		Grants:         []oauth2.Grant{grant.NewClientCredentials(gcfg), grant.NewRefreshToken(gcfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost()},
	})
	if err != nil {
		return nil, fmt.Errorf("oauth2.NewServer: %w", err)
	}

	// Resource server: Bearer middleware backed by the introspection
	// verifier that consults the shared storage.
	verifier := &localIntrospectVerifier{store: store, pepper: pepper}
	engine := security.NewEngine(
		security.NewManager(bearer.NewAuthenticator(verifier)),
		bearer.NewExtractor(),
	)
	protect := httpsec.Middleware(engine, httpsec.WithRealm("api"))

	mux := http.NewServeMux()
	mux.Handle("POST /oauth2/token", srv.TokenHandler())
	mux.Handle("POST /oauth2/revoke", srv.RevokeHandler())
	mux.Handle("POST /oauth2/introspect", srv.IntrospectHandler())
	mux.Handle("GET /.well-known/oauth-authorization-server", srv.MetadataHandler())
	mux.Handle("GET /protected", protect(http.HandlerFunc(protectedHandler)))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("public\n"))
	})

	return mux, nil
}

func main() {
	handler, err := buildServer()
	if err != nil {
		log.Fatalf("example/oauth2: %v", err)
	}

	addr := ":1337"
	log.Printf("listening on %s", addr)

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	auth, _ := security.FromContext(r.Context())

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("hello " + auth.Principal().Subject() + "\n")) //nolint:gosec // demo
}
