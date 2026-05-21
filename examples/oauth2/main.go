// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package main demonstrates wiring of the v2 security library: an OAuth2
// authorization server (authorization_code with PKCE, client_credentials,
// refresh_token) plus a resource server protected by a bearer middleware
// sharing the same storage as the auth server.
//
// Run:
//
//	go run ./examples/oauth2
//
// Probe — request an access token (client_credentials):
//
//	curl -i -u 5cc06c3b-5755-4229-958c-a515a245aaeb:WTvuAztPD2XBauomleRzGFYuZawS07Ym \
//	    -d 'grant_type=client_credentials&scope=api:read' \
//	    http://localhost:1337/oauth2/token
//
// Probe — call the protected resource with the issued token:
//
//	TOKEN=...  # from the previous response
//	curl -i -H "Authorization: Bearer $TOKEN" http://localhost:1337/protected
//
// Probe — the authorization-code flow is browser-driven: open
// http://localhost:1337/oauth2/authorize?response_type=code&client_id=5cc06c3b-5755-4229-958c-a515a245aaeb&redirect_uri=http://localhost:1337/callback&scope=api:read&state=demo&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
// then approve — the browser lands on /callback with the code.
package main

import (
	"context"
	"fmt"
	"html"
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
	store oauth2.AccessTokenStore
}

// Verify implements [bearer.TokenVerifier].
func (v *localIntrospectVerifier) Verify(ctx context.Context, tok string) (security.Authentication, error) {
	hash := oauth2.HashToken(nil, tok)

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

	// Seed a demo confidential client. The redirect URI points back at this
	// same binary so the authorization-code flow is observable end to end.
	clients := &staticClientStore{clients: map[string]oauth2.Client{
		demoClientID: &oauth2.DefaultClient{
			IDValue:           demoClientID,
			Secret:            demoClientSecret,
			TypeValue:         oauth2.ClientConfidential,
			RedirectURIValues: []string{"http://localhost:1337/callback"},
			ScopeValues:       []string{"api:read"},
		},
	}}

	// Authorization server.
	gcfg := grant.Config{
		Storage:             store,
		AccessTokens:        token.NewOpaque(32),
		RefreshTokens:       token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:           time.Hour,
		RefreshTTL:          24 * time.Hour,
		RotateRefreshTokens: true,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("http://localhost:1337", "api"),
		Grants: []oauth2.Grant{
			grant.NewAuthorizationCode(gcfg),
			grant.NewClientCredentials(gcfg),
			grant.NewRefreshToken(gcfg),
		},
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost()},
	})
	if err != nil {
		return nil, fmt.Errorf("oauth2.NewServer: %w", err)
	}

	// Resource server: Bearer middleware backed by the introspection
	// verifier that consults the shared storage.
	verifier := &localIntrospectVerifier{store: store}
	engine := security.NewEngine(
		security.NewManager(bearer.NewAuthenticator(verifier)),
		bearer.NewExtractor(),
	)
	protect := httpsec.Middleware(engine, httpsec.WithRealm("api"))

	// The mount paths must match ServerConfig.RoutePrefix (default
	// "/oauth2") so the metadata document advertises the right URLs.
	mux := http.NewServeMux()
	// /authorize answers GET (consent page) and POST (decision).
	authorize := srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, consentHandler)
	mux.Handle("GET /oauth2/authorize", authorize)
	mux.Handle("POST /oauth2/authorize", authorize)
	mux.Handle("POST /oauth2/token", srv.TokenHandler())
	mux.Handle("POST /oauth2/revoke", srv.RevokeHandler())
	mux.Handle("POST /oauth2/introspect", srv.IntrospectHandler())
	mux.Handle("GET /.well-known/oauth-authorization-server", srv.MetadataHandler())
	mux.Handle("GET /protected", protect(http.HandlerFunc(protectedHandler)))
	mux.HandleFunc("GET /callback", showCallback)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("public\n"))
	})

	return mux, nil
}

// consentHandler is the /authorize consent hook. A real application
// authenticates the resource owner and renders branded UI; this demo
// renders a bare Approve / Deny form and treats every visitor as the
// fixed "demo-user".
func consentHandler(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
	if r.Method == http.MethodPost {
		return &oauth2.Consent{
			Approved: r.FormValue("decision") == "approve",
			Subject:  "demo-user",
		}, nil
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	//nolint:gosec // G705: every interpolated value is HTML-escaped
	fmt.Fprintf(w, `<!doctype html><title>Authorize</title>
<p>Client <b>%s</b> requests scope <b>%s</b>.</p>
<form method="post" action="/oauth2/authorize?%s">
<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button>
</form>`,
		html.EscapeString(ar.Client.ID()),
		html.EscapeString(ar.Scope),
		html.EscapeString(r.URL.RawQuery))

	return nil, nil // the consent page was rendered
}

// showCallback stands in for the client's redirect endpoint: it just
// echoes the authorization code the browser was redirected with.
func showCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	//nolint:gosec // G705: the code is echoed HTML-escaped
	fmt.Fprintf(w, "authorization code: %s\n", html.EscapeString(r.URL.Query().Get("code")))
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
