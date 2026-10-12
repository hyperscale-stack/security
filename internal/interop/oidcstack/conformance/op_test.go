// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package conformance_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"text/template"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/require"
)

// The OP helper process is configured by run.sh through the environment.
const (
	envOPReady    = "OIDC_CONFORMANCE_OP_READY"    // the file written once the provider listens
	envOPAddr     = "OIDC_CONFORMANCE_OP_ADDR"     // the listen address
	envOPIssuer   = "OIDC_CONFORMANCE_OP_ISSUER"   // the root issuer, https
	envOPCert     = "OIDC_CONFORMANCE_OP_CERT"     // the TLS certificate (PEM)
	envOPKey      = "OIDC_CONFORMANCE_OP_KEY"      // its private key (PEM)
	envOPCallback = "OIDC_CONFORMANCE_OP_CALLBACK" // the suite's redirect URI for the plans' alias
)

// tenantPath is the path issuer the configuration plan also runs against
// (Discovery §4.1).
const tenantPath = "/tenant-a"

// endUser is the test end-user: every standard claim (Core §5.1).
const endUser = "conformance-user"

var endUserClaims = map[string]any{
	"name": "Jane Doe", "given_name": "Jane", "family_name": "Doe", "middle_name": "Quinn",
	"nickname": "JD", "preferred_username": "jane", "profile": "https://example.com/jane",
	"picture": "https://example.com/jane.png", "website": "https://example.com", "email": "jane@example.com",
	"email_verified": true, "gender": "female", "birthdate": "1990-01-31", "zoneinfo": "Europe/Paris",
	"locale": "fr-FR", "phone_number": "+33 1 23 45 67 89", "phone_number_verified": true,
	"address": map[string]any{
		"formatted": "1 rue de la Paix\n75002 Paris\nFrance", "street_address": "1 rue de la Paix",
		"locality": "Paris", "region": "Ile-de-France", "postal_code": "75002", "country": "France",
	},
	"updated_at": 1767225600,
}

// TestConformanceOPHelperProcess serves the provider under test of the
// suite's OP plans. It is not a test: it runs only when run.sh sets
// OIDC_CONFORMANCE_OP_READY, writes that file — the issuers and the
// per-run client secrets — and the plans' configurations next to it once it
// listens, and serves until SIGTERM or SIGINT.
//
// The provider runs under oauth2.Profile20: the Basic OP plan sends no PKCE
// but in one module, which the default profile would refuse. Its
// Interaction is headless: a session cookie, an end-user who authenticates
// whenever a request needs it (no session, prompt=login, max_age) and
// consents to everything requested — offline access only with
// prompt=consent (Core §11). The login and consent pages are application
// code, not under test.
func TestConformanceOPHelperProcess(t *testing.T) {
	ready := os.Getenv(envOPReady)
	if ready == "" {
		t.Skip("helper process of internal/interop/oidcstack/conformance/run.sh")
	}

	issuer, callback := os.Getenv(envOPIssuer), os.Getenv(envOPCallback)
	require.NotEmpty(t, issuer, envOPIssuer)
	require.NotEmpty(t, callback, envOPCallback)

	secrets := map[string]string{"conformance-1": randomSecret(t), "conformance-2": randomSecret(t)}

	handler := newConformanceProvider(t, issuer, callback, secrets)

	ln, err := net.Listen("tcp", os.Getenv(envOPAddr))
	require.NoError(t, err)

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	served := make(chan error, 1)

	go func() { served <- srv.ServeTLS(ln, os.Getenv(envOPCert), os.Getenv(envOPKey)) }()

	writePlanConfigs(t, filepath.Dir(ready), issuer, callback, secrets)

	state, err := json.Marshal(map[string]any{"issuer": issuer, "tenant_issuer": issuer + tenantPath})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(ready, state, 0o600))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	select {
	case <-ctx.Done():
	case err := <-served:
		require.NoError(t, err)
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, srv.Shutdown(shutdown))
}

// randomSecret returns a fresh client secret.
func randomSecret(t *testing.T) string {
	t.Helper()

	return rand.Text() + rand.Text()
}

// writePlanConfigs renders the configurations of the OP plans — the root
// issuer and the path issuer — from testdata/op-config.json.tmpl.
func writePlanConfigs(t *testing.T, dir, issuer, callback string, secrets map[string]string) {
	t.Helper()

	tmpl, err := template.ParseFiles(filepath.Join("testdata", "op-config.json.tmpl"))
	require.NoError(t, err)

	for name, iss := range map[string]string{"op-config.json": issuer, "op-config-tenant.json": issuer + tenantPath} {
		var out bytes.Buffer

		require.NoError(t, tmpl.Execute(&out, map[string]string{
			"Issuer": iss, "Origin": issuer, "Callback": callback,
			"Secret1": secrets["conformance-1"], "Secret2": secrets["conformance-2"],
		}))
		require.True(t, json.Valid(out.Bytes()), "%s renders valid JSON", name)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), out.Bytes(), 0o600))
	}
}

// newConformanceProvider builds the provider: the root issuer and a path
// issuer, each signing with RS256, PS256 and ES256 keys generated now.
func newConformanceProvider(t *testing.T, issuer, callback string, secrets map[string]string) http.Handler {
	t.Helper()

	keys := map[string]oidcprovider.KeyRing{issuer: newRing(t, "root"), issuer + tenantPath: newRing(t, "tenant")}

	store := memory.New()
	gcfg := grant.Config{
		Storage:           store,
		AccessTokens:      token.NewOpaque(32),
		RefreshTokens:     token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:         time.Hour,
		RefreshTTL:        24 * time.Hour,
		RefreshTokenScope: oidcprovider.ScopeOfflineAccess,
	}

	provider, err := oidcprovider.New(oauth2.ServerConfig{
		Profile:        oauth2.Profile20,
		Storage:        store,
		ClientStore:    conformanceClients(callback, secrets),
		IssuerResolver: twoIssuers{root: issuer},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost()},
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg)},
	}, oidcprovider.Config{
		Keys:            staticRings(keys),
		Claims:          claimsSource{},
		Interaction:     &headless{sessions: map[string]session{}},
		ClaimsSupported: slices.Sorted(maps.Keys(endUserClaims)),
	})
	require.NoError(t, err)

	mux := http.NewServeMux()

	for _, iss := range []string{issuer, issuer + tenantPath} {
		paths, err := provider.Paths(iss)
		require.NoError(t, err)

		srv := provider.Server()
		authorize := provider.AuthorizeHandler(oauth2.AuthorizeConfig{})

		mux.Handle("GET "+paths.Authorize, authorize)
		mux.Handle("POST "+paths.Authorize, authorize)
		mux.Handle("POST "+paths.Token, srv.TokenHandler())
		mux.Handle("POST "+paths.Revoke, srv.RevokeHandler())
		mux.Handle("POST "+paths.Introspect, srv.IntrospectHandler())
		mux.Handle(paths.UserInfo, provider.UserInfoHandler())
		mux.Handle("GET "+paths.Discovery, provider.DiscoveryHandler())
		mux.Handle("GET "+paths.Metadata, srv.MetadataHandler())
		mux.Handle("GET "+paths.JWKS, provider.JWKSHandler())
	}

	return mux
}

// newRing generates one key per algorithm (RFC 8725 §3.1), RS256 first.
func newRing(t *testing.T, prefix string) oidcprovider.KeyRing {
	t.Helper()

	rs, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ps, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	es, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{
		{KeyID: prefix + "-rs256", Algorithm: jwtsec.RS256, Key: rs},
		{KeyID: prefix + "-ps256", Algorithm: jwtsec.PS256, Key: ps},
		{KeyID: prefix + "-es256", Algorithm: jwtsec.ES256, Key: es},
	}}
}

// staticRings is the KeySource: one ring per issuer.
type staticRings map[string]oidcprovider.KeyRing

func (s staticRings) Keys(_ context.Context, issuer string) (oidcprovider.KeyRing, error) {
	ring, ok := s[issuer]
	if !ok {
		return oidcprovider.KeyRing{}, fmt.Errorf("no keys for %s", issuer)
	}

	return oidcprovider.KeyRing{Signing: slices.Clone(ring.Signing)}, nil
}

// twoIssuers resolves the path issuer from its path prefix, the root
// issuer otherwise.
type twoIssuers struct{ root string }

func (i twoIssuers) Resolve(_ context.Context, r *http.Request) (string, string, error) {
	if strings.HasPrefix(r.URL.Path, tenantPath+"/") || r.URL.Path == "/.well-known/oauth-authorization-server"+tenantPath {
		return i.root + tenantPath, "conformance-api", nil
	}

	return i.root, "conformance-api", nil
}

// staticClients is the ClientStore: conformance-1 authenticates with
// client_secret_basic or client_secret_post (the Basic plan uses both),
// conformance-2 with client_secret_basic.
type staticClients map[string]oauth2.Client

func (s staticClients) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	return s[id], nil
}

func conformanceClients(callback string, secrets map[string]string) staticClients {
	clients := staticClients{}

	for id, methods := range map[string][]string{
		"conformance-1": {"client_secret_basic", "client_secret_post"},
		"conformance-2": {"client_secret_basic"},
	} {
		clients[id] = &oauth2.DefaultClient{
			IDValue: id, Secret: secrets[id], TypeValue: oauth2.ClientConfidential,
			RedirectURIValues: []string{callback},
			GrantTypeValues:   []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken},
			ScopeValues: []string{
				oidcprovider.ScopeOpenID, oidcprovider.ScopeProfile, oidcprovider.ScopeEmail,
				oidcprovider.ScopeAddress, oidcprovider.ScopePhone, oidcprovider.ScopeOfflineAccess,
			},
			AuthMethodValues: methods,
		}
	}

	return clients
}

// claimsSource returns the test end-user's claims; the provider releases
// those the request and the end-user allow.
type claimsSource struct{}

func (claimsSource) Claims(_ context.Context, q oidcprovider.ClaimsQuery) (map[string]any, error) {
	if q.Subject != endUser {
		return nil, oidcprovider.ErrUnknownSubject
	}

	return maps.Clone(endUserClaims), nil
}

// sessionCookie names the headless end-user's session at the provider.
const sessionCookie = "conformance_op_session"

// session is a signed-in browser: the realm and when the end-user
// authenticated.
type session struct {
	issuer   string
	authTime time.Time
}

// headless is the Interaction: no page, a session per browser.
type headless struct {
	mu       sync.Mutex
	sessions map[string]session
}

func (h *headless) Authorize(w http.ResponseWriter, r *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	ev, ok := h.event(r)
	if !ok || req.Check(ev, time.Time{}) != nil {
		ev = h.signIn(w, req)
	}

	return approve(req, ev), nil
}

func (h *headless) AuthorizeSilently(r *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
	ev, ok := h.event(r)
	if !ok {
		return &oidcprovider.Decision{Refusal: oauth2.ErrLoginRequired}, nil
	}

	if err := req.Check(ev, time.Time{}); err != nil {
		return &oidcprovider.Decision{Refusal: err}, nil
	}

	return approve(req, ev), nil
}

// event returns the authentication of the browser's session.
func (h *headless) event(r *http.Request) (oidcprovider.AuthenticationEvent, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return oidcprovider.AuthenticationEvent{}, false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	s, ok := h.sessions[cookie.Value]
	if !ok {
		return oidcprovider.AuthenticationEvent{}, false
	}

	return oidcprovider.AuthenticationEvent{Issuer: s.issuer, Subject: endUser, AuthTime: s.authTime, AMR: []string{"pwd"}}, true
}

// signIn authenticates the end-user now, in a new session.
func (h *headless) signIn(w http.ResponseWriter, req *oidcprovider.Request) oidcprovider.AuthenticationEvent {
	id := rand.Text()
	s := session{issuer: req.Issuer, authTime: time.Now()}

	h.mu.Lock()
	h.sessions[id] = s
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})

	return oidcprovider.AuthenticationEvent{Issuer: s.issuer, Subject: endUser, AuthTime: s.authTime, AMR: []string{"pwd"}}
}

// approve consents to everything requested: the scope, every claim of the
// claims parameter, offline access when the consent dialog was asked for.
func approve(req *oidcprovider.Request, ev oidcprovider.AuthenticationEvent) *oidcprovider.Decision {
	d := &oidcprovider.Decision{Authentication: &ev}

	for _, c := range append(slices.Clone(req.Claims.IDToken), req.Claims.UserInfo...) {
		d.Claims = append(d.Claims, c.Name)
	}

	if req.OfflineAccess && req.Prompt.Consent {
		d.OfflineAccess = oidcprovider.OfflineAccessPrompted
	}

	return d
}
