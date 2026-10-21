// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Command oidc-client signs users in through external OpenID Providers
// with the oidc/client module — one oidcclient.Client per connection — and
// keeps them signed in with a cookie session.
//
// The library runs the protocol; the application owns everything around
// it, as an identity broker would: which connections exist (here,
// environment variables; in a broker, its tenant configuration), where
// pending logins are stored, how an external identity maps to a local
// account, and the local session.
//
// Run, with a client registered at an OpenID Provider with the redirect
// URI http://localhost:8083/oidc/default/callback:
//
//	OIDC_DEFAULT_ISSUER=https://accounts.example.com \
//	OIDC_DEFAULT_CLIENT_ID=my-client OIDC_DEFAULT_CLIENT_SECRET=my-secret \
//	go run ./oidc-client
//
// then open http://localhost:8083. More connections:
// OIDC_CONNECTIONS=acme,globex with OIDC_ACME_ISSUER, OIDC_ACME_CLIENT_ID,
// OIDC_ACME_CLIENT_SECRET, … Each connection gets its own callback route,
// /oidc/{connection}/callback: a redirect URI distinct per connection is
// the mix-up defense (RFC 9700 §4.4.2.2). An empty client secret makes a
// public client; OIDC_{ID}_RESPONSE_MODE=form_post needs https (BASE_URL).
//
// Pending logins are protected by a server-held transaction key
// (oidcclient.Config.TransactionKeys): OIDC_TRANSACTION_KEYS, hex-encoded
// keys of at least 32 bytes separated by commas — the first protects new
// logins, all are accepted, which is how a key is rotated (generate one with
// openssl rand -hex 32). Every instance serving callbacks needs the same
// keys, like a session key. Without the variable the demo draws a random
// key at startup: logins in progress then fail on a restart and cannot
// span instances.
//
// Login starts are unauthenticated — non-browser clients pass the
// cross-origin protection — and each stores a pending login for ten
// minutes. The demo lets each client (an IPv4 address, an IPv6 /64) start
// 20 logins a minute and each network (an IPv4 /24, an IPv6 /48) 60,
// answering 429 Too Many Requests beyond, and keeps at most 10 000 pending
// logins (memory.WithCapacity), answering 503 Service Unavailable beyond:
// one network holds at most about 600 of them. The capacity bounds memory,
// not availability: a flood from enough networks fills the store, and new
// logins then answer 503 until its transactions expire — rate-limit at the
// edge in production. Behind a reverse proxy, key the limits on the client
// address your proxy forwards.
//
// Plain http on localhost is for development only: it drops the Secure
// attribute of the cookies (oidcclient.Config.InsecureCookies and
// session.WithSecure(false)). Serve https in production. Likewise,
// OIDC_DEV_ALLOW_LOOPBACK=1 lets the demo reach a provider on the loopback
// interface, over plain http — examples/oidc-provider, see its package
// documentation for running both: by default the requests to the providers
// reach public https destinations only.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	httpsec "github.com/hyperscale-stack/security/http"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/hyperscale-stack/security/session"
)

// connectionConfig is the application's record of one connection.
type connectionConfig struct {
	ID           string
	Issuer       string
	ClientID     string
	ClientSecret oidcclient.Secret
	ResponseMode string // "" (query) or "form_post"
}

// config is the demo's configuration.
type config struct {
	// BaseURL is the public origin of the application.
	BaseURL     string
	Connections []connectionConfig
	// Outbound is the policy of the requests to the providers; the zero
	// value reaches public https destinations only.
	Outbound outbound.Policy
	// TransactionKeys protect the pending logins
	// (oidcclient.Config.TransactionKeys): secret, shared by every instance.
	TransactionKeys []oidcclient.Secret
	// MaxPendingLogins bounds the logins in progress the store keeps
	// (defaultMaxPendingLogins when not positive).
	MaxPendingLogins int
	// LoginStartsPerMinute is how many logins one client may start per
	// minute, its network networkShare times as many
	// (defaultLoginStartsPerMinute when not positive).
	LoginStartsPerMinute int
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}

	return fallback
}

// loadConfig reads the configuration from the environment.
func loadConfig() (config, error) {
	cfg := config{BaseURL: envOr("BASE_URL", "http://localhost:8083")}

	keys, err := transactionKeys(os.Getenv("OIDC_TRANSACTION_KEYS"))
	if err != nil {
		return config{}, err
	}

	cfg.TransactionKeys = keys

	if raw := os.Getenv("OIDC_DEV_ALLOW_LOOPBACK"); raw != "" {
		allow, err := strconv.ParseBool(raw)
		if err != nil {
			return config{}, fmt.Errorf("OIDC_DEV_ALLOW_LOOPBACK: %w", err)
		}

		if allow {
			cfg.Outbound = devLoopbackPolicy()
		}
	}

	for id := range strings.SplitSeq(envOr("OIDC_CONNECTIONS", "default"), ",") {
		id = strings.TrimSpace(id)
		prefix := "OIDC_" + strings.ToUpper(id) + "_"
		cfg.Connections = append(cfg.Connections, connectionConfig{
			ID:           id,
			Issuer:       os.Getenv(prefix + "ISSUER"),
			ClientID:     os.Getenv(prefix + "CLIENT_ID"),
			ClientSecret: oidcclient.NewSecret(os.Getenv(prefix + "CLIENT_SECRET")),
			ResponseMode: os.Getenv(prefix + "RESPONSE_MODE"),
		})
	}

	return cfg, nil
}

// schemeHTTP is plain http: development on the loopback interface only.
const schemeHTTP = "http"

// Abuse bounds of the login starts.
const (
	// defaultMaxPendingLogins bounds the pending logins of the in-memory
	// store: about 0.5 KB each, kept for the transaction TTL.
	defaultMaxPendingLogins = 10_000
	// defaultLoginStartsPerMinute is the login starts one client may make
	// per minute; its network may make networkShare times as many.
	defaultLoginStartsPerMinute = 20
	// maxLimitedPrefixes bounds the prefixes each tier of the limiter
	// tracks per minute; the others share one budget.
	maxLimitedPrefixes = 10_000
	// retryAfter is the Retry-After of a refused login start, in seconds.
	retryAfter = "60"
)

// errHTTPBeyondLoopback refuses plain http to a host off the loopback
// interface.
var errHTTPBeyondLoopback = errors.New("plain http is allowed to the loopback interface only")

// devLoopbackPolicy is the outbound policy of OIDC_DEV_ALLOW_LOOPBACK, for
// development only: the loopback interface becomes reachable, over https
// or plain http; any other destination stays public and https-only.
func devLoopbackPolicy() outbound.Policy {
	return outbound.Policy{
		AllowHTTP:       true,
		AllowedPrefixes: outbound.LoopbackPrefixes(),
		CheckURL: func(_ context.Context, u *url.URL) error {
			if u.Scheme == schemeHTTP && !loopbackHost(u.Hostname()) {
				return errHTTPBeyondLoopback
			}

			return nil
		},
	}
}

// loopbackHost reports whether host is localhost or a loopback IP address.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}

	addr, err := netip.ParseAddr(host)

	return err == nil && addr.IsLoopback()
}

// errKeyNotHex reports a malformed OIDC_TRANSACTION_KEYS entry.
var errKeyNotHex = errors.New("not hex-encoded")

// transactionKeys decodes OIDC_TRANSACTION_KEYS: hex-encoded keys separated
// by commas. Unset, it draws one random key — for a single development
// instance only: the logins in progress do not survive a restart.
func transactionKeys(raw string) ([]oidcclient.Secret, error) {
	if strings.TrimSpace(raw) == "" {
		key := make([]byte, oidcclient.MinTransactionKeySize)
		_, _ = rand.Read(key) // crypto/rand.Read never fails

		log.Print("oidc-client: OIDC_TRANSACTION_KEYS is not set: using a random per-process transaction key " +
			"(logins in progress fail on a restart and cannot span instances)")

		return []oidcclient.Secret{oidcclient.NewSecret(string(key))}, nil
	}

	var keys []oidcclient.Secret

	for part := range strings.SplitSeq(raw, ",") {
		key, err := hex.DecodeString(strings.TrimSpace(part))
		if err != nil {
			// Not wrapped: the decoder's error would echo a character of the key.
			return nil, fmt.Errorf("OIDC_TRANSACTION_KEYS: key %d: %w", len(keys)+1, errKeyNotHex)
		}

		keys = append(keys, oidcclient.NewSecret(string(key)))
	}

	return keys, nil
}

// principal is the local account a session belongs to.
type principal struct{ subject string }

func (p principal) Subject() string { return p.subject }

// identityKey identifies an external user: the issuer and subject pair is
// the only stable identifier OpenID Connect gives (Core §5.7), and the
// connection keeps two connections to one issuer — two tenants of a
// multi-tenant provider — apart. Never link accounts on the email, which a
// provider may let users change, or assert unverified.
type identityKey struct{ connection, issuer, subject string }

// accounts links external identities to local accounts, creating an
// account at the first login of an identity.
type accounts struct {
	mu         sync.Mutex
	links      map[identityKey]string
	identities map[string][]identityKey
}

func (a *accounts) link(id *oidcclient.Identity) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := identityKey{connection: id.ConnectionID, issuer: id.Issuer, subject: id.Subject}
	if account, ok := a.links[key]; ok {
		return account
	}

	account := fmt.Sprintf("account-%d", len(a.links)+1)
	a.links[key] = account
	a.identities[account] = append(a.identities[account], key)

	return account
}

// linked returns the identities linked to account.
func (a *accounts) linked(account string) []identityKey {
	a.mu.Lock()
	defer a.mu.Unlock()

	return slices.Clone(a.identities[account])
}

// app holds the demo's dependencies.
type app struct {
	connections map[string]*oidcclient.Client
	sessions    *session.Manager
	accounts    *accounts
	limiter     *loginLimiter
}

// orDefault returns n when it is positive, fallback otherwise.
func orDefault(n, fallback int) int {
	if n > 0 {
		return n
	}

	return fallback
}

// newServer discovers every connection's provider and builds the handler.
// It is separate from main so the test drives the same wiring.
func newServer(ctx context.Context, cfg config) (http.Handler, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("BASE_URL: %w", err)
	}

	insecure := base.Scheme == schemeHTTP // local development only

	key := make([]byte, 32)
	_, _ = rand.Read(key) // crypto/rand.Read never fails

	codec, err := session.NewCodec(key)
	if err != nil {
		return nil, fmt.Errorf("session codec: %w", err)
	}

	a := &app{
		connections: make(map[string]*oidcclient.Client, len(cfg.Connections)),
		sessions:    session.NewManager(codec, session.WithSecure(!insecure)),
		accounts:    &accounts{links: make(map[identityKey]string), identities: make(map[string][]identityKey)},
		limiter: newLoginLimiter(orDefault(cfg.LoginStartsPerMinute, defaultLoginStartsPerMinute), maxLimitedPrefixes,
			time.Minute, time.Now),
	}

	// One store serves every connection: a pending login is bound to its
	// connection. With several instances behind a load balancer, use a
	// shared store instead: oidc/client/store/sql or oidc/client/store/redis.
	// Its capacity bounds what a flood of login starts can hold.
	store := memory.New(memory.WithCapacity(orDefault(cfg.MaxPendingLogins, defaultMaxPendingLogins)))

	for _, c := range cfg.Connections {
		method := oidcclient.AuthMethodClientSecretBasic
		if c.ClientSecret.Reveal() == "" {
			method = oidcclient.AuthMethodNone
		}

		client, err := oidcclient.New(ctx, oidcclient.Config{
			ConnectionID:    c.ID,
			Issuer:          c.Issuer,
			ClientID:        c.ClientID,
			ClientSecret:    c.ClientSecret,
			AuthMethod:      method,
			RedirectURL:     cfg.BaseURL + "/oidc/" + c.ID + "/callback",
			Scopes:          []string{"openid", "profile", "email"},
			ResponseMode:    oidcclient.ResponseMode(c.ResponseMode),
			Store:           store,
			TransactionKeys: cfg.TransactionKeys,
			Outbound:        cfg.Outbound,
			InsecureCookies: insecure,
		})
		if err != nil {
			return nil, fmt.Errorf("connection %q: %w", c.ID, err)
		}

		a.connections[c.ID] = client
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.home)
	mux.HandleFunc("POST /login/{connection}", a.login)
	mux.HandleFunc("GET /oidc/{connection}/callback", a.callback)
	mux.HandleFunc("POST /oidc/{connection}/callback", a.callback) // form_post
	mux.HandleFunc("POST /logout", a.logout)

	// Cross-origin POSTs are refused: login starts and logouts come from
	// this origin. The callbacks are exempt — a form_post response is a
	// cross-site POST by design, which the binding cookie defends.
	csrf := http.NewCrossOriginProtection()
	csrf.AddInsecureBypassPattern("POST /oidc/{connection}/callback")

	return csrf.Handler(mux), nil
}

// home renders the signed-in page, or the sign-in page with one button per
// connection.
func (a *app) home(w http.ResponseWriter, r *http.Request) {
	s, err := a.sessions.Get(r.Context(), httpsec.NewCarrier(w, r))
	if err != nil {
		ids := make([]string, 0, len(a.connections))
		for id := range a.connections {
			ids = append(ids, id)
		}

		slices.Sort(ids)

		var b strings.Builder

		b.WriteString("<h1>Sign in</h1>\n")

		for _, id := range ids {
			fmt.Fprintf(&b, "<form method=\"post\" action=\"/login/%s\"><button type=\"submit\">Sign in with %[1]s</button></form>\n",
				html.EscapeString(id))
		}

		_, _ = fmt.Fprint(w, b.String())

		return
	}

	account := s.GetString("sub")

	var b strings.Builder

	fmt.Fprintf(&b, "<h1>Signed in as %s</h1>\n<ul>\n", html.EscapeString(account))

	for _, id := range a.accounts.linked(account) {
		fmt.Fprintf(&b, "<li>%s: %s, subject %s</li>\n",
			html.EscapeString(id.connection), html.EscapeString(id.issuer), html.EscapeString(id.subject))
	}

	fmt.Fprintf(&b, `</ul>
<form method="post" action="/logout">
<input type="hidden" name="csrf_token" value="%s">
<button type="submit">Sign out</button>
</form>`, html.EscapeString(session.CSRFToken(s)))

	_, _ = fmt.Fprint(w, b.String())
}

// login starts a login through the requested connection.
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	client, ok := a.connections[r.PathValue("connection")]
	if !ok {
		http.NotFound(w, r)

		return
	}

	// Each start stores a pending login: limit them per client and per
	// network (the store's capacity bounds them all).
	if !a.limiter.allow(clientAddr(r.RemoteAddr)) {
		w.Header().Set("Retry-After", retryAfter)
		http.Error(w, "too many sign-in attempts, retry in a minute", http.StatusTooManyRequests)

		return
	}

	err := client.StartLogin(w, r, oidcclient.AuthOptions{})

	switch {
	case err == nil:
	case errors.Is(err, memory.ErrFull):
		w.Header().Set("Retry-After", retryAfter)
		http.Error(w, "too many sign-ins in progress, retry in a minute", http.StatusServiceUnavailable)
	default:
		log.Printf("oidc-client: start login: %v", err)
		http.Error(w, "cannot start the sign-in", http.StatusInternalServerError)
	}
}

// callback completes a login: the identity is linked to a local account,
// which gets a fresh session.
func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	client, ok := a.connections[r.PathValue("connection")]
	if !ok {
		http.NotFound(w, r)

		return
	}

	id, err := client.HandleCallback(w, r)
	if err != nil {
		// Log the cause, never show it: the text of a provider's error
		// response is untrusted (an *oidcclient.AuthorizationError prints
		// its code only).
		log.Printf("oidc-client: sign-in failed: %v", err)
		http.Error(w, "sign-in failed", http.StatusBadRequest)

		return
	}

	account := a.accounts.link(id)

	// A new session (a fresh ID defeats session fixation), then 303 to a
	// clean URL: the code leaves the browser history (RFC 9700 §4.3.1).
	if _, err := a.sessions.Login(r.Context(), httpsec.NewCarrier(w, r), principal{subject: account}); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)

		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logout ends the local session after checking the CSRF token.
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	carrier := httpsec.NewCarrier(w, r)

	s, err := a.sessions.Get(r.Context(), carrier)
	if err == nil && !session.VerifyCSRF(s, r.FormValue("csrf_token")) {
		http.Error(w, "bad CSRF token", http.StatusForbidden)

		return
	}

	a.sessions.Logout(r.Context(), carrier)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("oidc-client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	handler, err := newServer(ctx, cfg) // discovers every provider

	cancel()

	if err != nil {
		log.Fatalf("oidc-client: %v", err)
	}

	server := &http.Server{Addr: envOr("ADDR", ":8083"), Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	log.Printf("oidc-client: listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
