// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProvider is a minimal OpenID Provider: discovery, JWK Set, an
// authorization endpoint signing its one user in at once, and a token
// endpoint checking the client, the redirect URI and PKCE.
type fakeProvider struct {
	srv          *httptest.Server
	key          *rsa.PrivateKey
	subject      string
	clientID     string
	clientSecret string
	redirectURI  string

	mu    sync.Mutex
	codes map[string]grant
}

// grant is an authorization code's request.
type grant struct{ challenge, nonce, redirectURI string }

func newFakeProvider(t *testing.T, subject string) *fakeProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	p := &fakeProvider{key: key, subject: subject, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)

	return p
}

func (p *fakeProvider) issuer() string { return p.srv.URL }

func (p *fakeProvider) register(clientID, secret, redirectURI string) {
	p.clientID, p.clientSecret, p.redirectURI = clientID, secret, redirectURI
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (p *fakeProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer(),
		"authorization_endpoint":                p.issuer() + "/authorize",
		"token_endpoint":                        p.issuer() + "/token",
		"jwks_uri":                              p.issuer() + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (p *fakeProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
		"n": b64(p.key.N.Bytes()), "e": b64(big.NewInt(int64(p.key.E)).Bytes()),
	}}})
}

func (p *fakeProvider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.clientID || q.Get("redirect_uri") != p.redirectURI ||
		q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "invalid request", http.StatusBadRequest)

		return
	}

	code := rand.Text()

	p.mu.Lock()
	p.codes[code] = grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirectURI: q.Get("redirect_uri")}
	p.mu.Unlock()

	http.Redirect(w, r, p.redirectURI+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	user, pass, _ := r.BasicAuth()
	id, _ := url.QueryUnescape(user)
	secret, _ := url.QueryUnescape(pass)

	if id != p.clientID || secret != p.clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})

		return
	}

	p.mu.Lock()
	g, ok := p.codes[r.PostFormValue("code")]
	delete(p.codes, r.PostFormValue("code"))
	p.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !ok || r.PostFormValue("grant_type") != "authorization_code" ||
		r.PostFormValue("redirect_uri") != g.redirectURI || b64(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})

		return
	}

	accessToken := rand.Text()
	atHash := sha256.Sum256([]byte(accessToken))
	now := time.Now()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token": p.sign(map[string]any{
			"iss": p.issuer(), "sub": p.subject, "aud": p.clientID, "nonce": g.nonce,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "at_hash": b64(atHash[:16]),
		}),
	})
}

// sign returns claims as a compact RS256 JWS.
func (p *fakeProvider) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])

	return input + "." + b64(sig)
}

func tlsConfig(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// browser is a user agent trusting the test servers, recording the
// callback URLs it visits.
type browser struct {
	*http.Client

	callbacks []string
}

func newBrowser(t *testing.T, pool *x509.CertPool) *browser {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	b := &browser{}
	b.Client = &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: tlsConfig(pool)},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if strings.Contains(req.URL.Path, "/callback") {
				b.callbacks = append(b.callbacks, req.URL.String())
			}

			return nil
		},
	}

	return b
}

// readPage reads a response.
func readPage(resp *http.Response, err error) (int, string, error) {
	if err != nil {
		return 0, "", err
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)

	return resp.StatusCode, string(body), err
}

var csrfField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func TestOIDCClientExample(t *testing.T) {
	t.Parallel()

	acme := newFakeProvider(t, "user-1")
	globex := newFakeProvider(t, "user-1") // the same subject at another provider

	rp := httptest.NewUnstartedServer(nil)
	base := "https://" + rp.Listener.Addr().String()

	acme.register("rp-acme", "acme-secret", base+"/oidc/acme/callback")
	globex.register("rp-globex", "globex-secret", base+"/oidc/globex/callback")

	pool := x509.NewCertPool()
	pool.AddCert(acme.srv.Certificate()) // every httptest TLS server shares one certificate

	handler, err := newServer(t.Context(), config{
		BaseURL: base,
		Connections: []connectionConfig{
			{ID: "acme", Issuer: acme.issuer(), ClientID: "rp-acme", ClientSecret: "acme-secret"},
			{ID: "globex", Issuer: globex.issuer(), ClientID: "rp-globex", ClientSecret: "globex-secret"},
		},
		Outbound:        outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool},
		TransactionKeys: [][]byte{[]byte("an example transaction key of 32+ bytes")},
	})
	require.NoError(t, err)

	rp.Config.Handler = handler
	rp.StartTLS()
	t.Cleanup(rp.Close)

	b := newBrowser(t, pool)

	status, body, err := readPage(b.Get(base + "/"))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, `action="/login/acme"`)
	assert.Contains(t, body, `action="/login/globex"`)

	signIn := func(t *testing.T, connection string) string {
		t.Helper()

		status, body, err := readPage(b.PostForm(base+"/login/"+connection, nil))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, body)

		return body
	}

	signOut := func(t *testing.T, home string) {
		t.Helper()

		csrf := csrfField.FindStringSubmatch(home)
		require.Len(t, csrf, 2)

		status, body, err := readPage(b.PostForm(base+"/logout", url.Values{"csrf_token": {csrf[1]}}))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, body, "Sign in")
	}

	home := signIn(t, "acme")
	assert.Contains(t, home, "Signed in as account-1")
	assert.Contains(t, home, "acme")

	signOut(t, home)

	home = signIn(t, "acme")
	assert.Contains(t, home, "Signed in as account-1", "the same identity, the same account")
	signOut(t, home)

	home = signIn(t, "globex")
	assert.Contains(t, home, "Signed in as account-2", "accounts are linked on (connection, issuer, subject)")
	signOut(t, home)

	t.Run("replayed callback", func(t *testing.T) {
		require.NotEmpty(t, b.callbacks)

		replay := newBrowser(t, pool)
		status, _, err := readPage(replay.Get(b.callbacks[0]))
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("unknown connection", func(t *testing.T) {
		status, _, err := readPage(b.PostForm(base+"/login/initech", nil))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, status)

		status, _, err = readPage(b.Get(base + "/oidc/initech/callback?code=c&state=s"))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("logout without the CSRF token", func(t *testing.T) {
		home := signIn(t, "acme")

		status, _, err := readPage(b.PostForm(base+"/logout", url.Values{"csrf_token": {"forged"}}))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, status)

		signOut(t, home)
	})

	t.Run("cross-origin login start", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/login/acme", nil)
		require.NoError(t, err)
		req.Header.Set("Sec-Fetch-Site", "cross-site")

		status, _, err := readPage(b.Do(req))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, status)
	})

	t.Run("cross-site form_post callback reaches the handler", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/oidc/acme/callback", strings.NewReader("state=x"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "cross-site")

		status, body, err := readPage(b.Do(req))
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, status, "refused by the client, not by the CSRF protection")
		assert.Contains(t, body, "sign-in failed")
	})
}

func TestNewServerRefusesBadConfig(t *testing.T) {
	t.Parallel()

	_, err := newServer(t.Context(), config{BaseURL: "http://localhost:8083", Connections: []connectionConfig{{ID: "acme"}}})
	require.Error(t, err, "a connection without issuer")

	_, err = newServer(t.Context(), config{BaseURL: "://bad"})
	require.Error(t, err)
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("BASE_URL", "")
	t.Setenv("OIDC_CONNECTIONS", "acme, globex")
	t.Setenv("OIDC_ACME_ISSUER", "https://acme.example.com")
	t.Setenv("OIDC_ACME_CLIENT_ID", "rp")
	t.Setenv("OIDC_ACME_CLIENT_SECRET", "s3cr3t")
	t.Setenv("OIDC_GLOBEX_ISSUER", "https://globex.example.com")
	t.Setenv("OIDC_GLOBEX_CLIENT_ID", "rp-public")
	t.Setenv("OIDC_GLOBEX_RESPONSE_MODE", "form_post")

	t.Setenv("OIDC_TRANSACTION_KEYS", "")

	cfg, err := loadConfig()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8083", cfg.BaseURL)
	assert.Equal(t, []connectionConfig{
		{ID: "acme", Issuer: "https://acme.example.com", ClientID: "rp", ClientSecret: "s3cr3t"},
		{ID: "globex", Issuer: "https://globex.example.com", ClientID: "rp-public", ResponseMode: "form_post"},
	}, cfg.Connections)
	require.Len(t, cfg.TransactionKeys, 1, "a random development key when none is configured")
	assert.Len(t, cfg.TransactionKeys[0], 32)

	other, err := loadConfig()
	require.NoError(t, err)
	assert.NotEqual(t, cfg.TransactionKeys, other.TransactionKeys, "drawn at random")

	k1, k2 := strings.Repeat("ab", 32), strings.Repeat("cd", 48)
	t.Setenv("OIDC_TRANSACTION_KEYS", k1+", "+k2)

	cfg, err = loadConfig()
	require.NoError(t, err)
	assert.Equal(t, [][]byte{bytes.Repeat([]byte{0xab}, 32), bytes.Repeat([]byte{0xcd}, 48)}, cfg.TransactionKeys)

	// A malformed key is reported by its position: the decoder's error would
	// echo one of its characters into the log.
	t.Setenv("OIDC_TRANSACTION_KEYS", k1+","+strings.Repeat("ab", 31)+"zQ")

	_, err = loadConfig()
	require.ErrorIs(t, err, errKeyNotHex)
	require.ErrorContains(t, err, "OIDC_TRANSACTION_KEYS: key 2")
	assert.NotContains(t, err.Error(), "z")
	assert.NotContains(t, err.Error(), "U+007A")
}

func TestNewServerRefusesShortTransactionKeys(t *testing.T) {
	t.Parallel()

	_, err := newServer(t.Context(), config{
		BaseURL:         "http://localhost:8083",
		Connections:     []connectionConfig{{ID: "acme", Issuer: "https://acme.example.com", ClientID: "rp", ClientSecret: "s3cr3t"}},
		TransactionKeys: [][]byte{[]byte("too short")},
	})
	require.ErrorIs(t, err, oidcclient.ErrInvalidConfig)
}

// TestDevLoopbackPolicy: OIDC_DEV_ALLOW_LOOPBACK=1 lets the demo reach a
// provider on the loopback interface over plain http — and nothing more:
// plain http elsewhere stays refused. Unset or false, the default policy
// (public https only) applies; another value is a configuration error.
func TestDevLoopbackPolicy(t *testing.T) {
	t.Setenv("OIDC_CONNECTIONS", "")
	t.Setenv("OIDC_TRANSACTION_KEYS", strings.Repeat("ab", 32))

	for _, off := range []string{"", "0", "false"} {
		t.Setenv("OIDC_DEV_ALLOW_LOOPBACK", off)

		cfg, err := loadConfig()
		require.NoError(t, err)
		assert.False(t, cfg.Outbound.AllowHTTP, off)
		assert.Empty(t, cfg.Outbound.AllowedPrefixes, off)
	}

	t.Setenv("OIDC_DEV_ALLOW_LOOPBACK", "maybe")

	_, err := loadConfig()
	require.ErrorContains(t, err, "OIDC_DEV_ALLOW_LOOPBACK")

	t.Setenv("OIDC_DEV_ALLOW_LOOPBACK", "1")

	cfg, err := loadConfig()
	require.NoError(t, err)
	assert.True(t, cfg.Outbound.AllowHTTP)
	assert.Equal(t, outbound.LoopbackPrefixes(), cfg.Outbound.AllowedPrefixes)

	for target, allowed := range map[string]bool{
		"http://localhost:8083/.well-known/openid-configuration": true,
		"http://127.0.0.1:8083/.well-known/openid-configuration": true,
		"http://[::1]:8083/.well-known/openid-configuration":     true,
		"http://op.example.com/.well-known/openid-configuration": false,
		"https://op.example.com/":                                true,
	} {
		u, err := url.Parse(target)
		require.NoError(t, err)

		err = cfg.Outbound.CheckURL(t.Context(), u)
		if allowed {
			require.NoError(t, err, target)
		} else {
			require.ErrorIs(t, err, errHTTPBeyondLoopback, target)
		}
	}

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(provider.Close)

	for name, policy := range map[string]outbound.Policy{"dev": cfg.Outbound, "default": {}} {
		client, err := outbound.NewClient(policy)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, provider.URL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		if name == "default" {
			require.Error(t, err, "the default policy refuses http and loopback")

			continue
		}

		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
}
