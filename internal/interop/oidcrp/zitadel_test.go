// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package oidcrp_test checks that the OpenID Connect Relying Party of
// oidc/client interoperates with an independent OpenID Provider: the
// example server of github.com/zitadel/oidc/v3, run in process over
// loopback TLS. The module holds tests only.
package oidcrp_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/exampleop"
	"github.com/zitadel/oidc/v3/example/server/storage"
)

const (
	rpOrigin     = "https://rp.example.com"
	clientID     = "rp"
	clientSecret = "zitadel-interop-secret"
	// The test user of the example provider.
	userID       = "id1"
	userEmail    = "test-user@zitadel.ch"
	userPassword = "verysecure"
)

func TestMain(m *testing.M) {
	// The example provider logs every request through the default logger.
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

// provider is the zitadel example OpenID Provider on loopback TLS.
type provider struct {
	issuer    string
	host      string
	pool      *x509.CertPool
	tokenHits atomic.Int64
}

// startProvider starts a provider knowing clients.
func startProvider(t *testing.T, clients ...*storage.Client) *provider {
	t.Helper()

	srv := httptest.NewUnstartedServer(nil)
	p := &provider{host: srv.Listener.Addr().String()}
	p.issuer = "https://" + p.host

	registered := make(map[string]*storage.Client, len(clients))
	for _, c := range clients {
		registered[c.GetID()] = c
	}

	op := exampleop.SetupServer(p.issuer, storage.NewStorageWithClients(storage.NewUserStore(p.issuer), registered), nil, false)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			p.tokenHits.Add(1)
		}

		op.ServeHTTP(w, r)
	})
	srv.StartTLS()
	t.Cleanup(srv.Close)

	p.pool = x509.NewCertPool()
	p.pool.AddCert(srv.Certificate())

	return p
}

// transactionKey is the server-held transaction key of the relying
// parties (oidcclient.Config.TransactionKeys).
var transactionKey = []byte("zitadel interop transaction key 32b")

func redirectURL(connection string) string { return rpOrigin + "/oidc/" + connection + "/callback" }

// relyingParty returns the Client of one connection to p.
func (p *provider) relyingParty(t *testing.T, connection string, mutators ...func(*oidcclient.Config)) *oidcclient.Client {
	t.Helper()

	cfg := oidcclient.Config{
		ConnectionID:    connection,
		Issuer:          p.issuer,
		ClientID:        clientID,
		ClientSecret:    clientSecret,
		AuthMethod:      oidcclient.AuthMethodClientSecretBasic,
		RedirectURL:     redirectURL(connection),
		Scopes:          []string{"openid", "profile", "email"},
		Store:           memory.New(),
		TransactionKeys: [][]byte{transactionKey},
		Outbound:        outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: p.pool},
	}

	for _, m := range mutators {
		m(&cfg)
	}

	c, err := oidcclient.New(t.Context(), cfg)
	require.NoError(t, err)

	return c
}

// signIn plays the user agent at the provider: it follows authURL to the
// login page, signs the test user in, and returns the response sending the
// user agent back to the relying party — a redirect, or a form_post page.
func (p *provider) signIn(t *testing.T, authURL string) *http.Response {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	agent := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Host != p.host {
				return http.ErrUseLastResponse // back to the relying party
			}

			return nil
		},
	}

	resp, err := agent.Get(authURL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "the provider's login page")

	id := resp.Request.URL.Query().Get("authRequestID")
	require.NotEmpty(t, id)

	resp, err = agent.PostForm(p.issuer+"/login/username", url.Values{
		"id":       {id},
		"username": {"test-user@" + strings.Split(p.host, ":")[0]},
		"password": {userPassword},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}

var (
	formAction = regexp.MustCompile(`<form method="post" action="([^"]+)">`)
	formInput  = regexp.MustCompile(`<input type="hidden" name="([a-z_]+)" value="([^"]*)"\s*/>`)
)

// callbackRequest is the request the user agent sends to the relying
// party after resp, with the cookies StartLogin set.
func callbackRequest(t *testing.T, resp *http.Response, cookies []*http.Cookie) *http.Request {
	t.Helper()

	var req *http.Request

	switch resp.StatusCode {
	case http.StatusFound, http.StatusSeeOther:
		req = httptest.NewRequest(http.MethodGet, resp.Header.Get("Location"), nil)
	case http.StatusOK: // form_post: the page the user agent submits
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		action := formAction.FindSubmatch(body)
		require.NotNil(t, action, "form_post page")

		form := url.Values{}
		for _, m := range formInput.FindAllSubmatch(body, -1) {
			form.Add(string(m[1]), html.UnescapeString(string(m[2])))
		}

		req = httptest.NewRequest(http.MethodPost, html.UnescapeString(string(action[1])), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	default:
		t.Fatalf("unexpected provider response: %d", resp.StatusCode)
	}

	for _, c := range cookies {
		req.AddCookie(c)
	}

	return req
}

// login runs one login of the test user through rp's net/http helpers and
// returns the identity and the callback request.
func (p *provider) login(t *testing.T, rp *oidcclient.Client) (*oidcclient.Identity, *http.Request, error) {
	t.Helper()

	start := httptest.NewRecorder()
	require.NoError(t, rp.StartLogin(start, httptest.NewRequest(http.MethodGet, rpOrigin+"/login", nil), oidcclient.AuthOptions{}))
	require.Equal(t, http.StatusSeeOther, start.Code)

	req := callbackRequest(t, p.signIn(t, start.Header().Get("Location")), start.Result().Cookies())
	id, err := rp.HandleCallback(httptest.NewRecorder(), req)

	return id, req, err
}

// claimsOf returns the members of a compact JWS payload.
func claimsOf(t *testing.T, jws string) map[string]any {
	t.Helper()

	parts := strings.Split(jws, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))

	return claims
}

// TestZitadelCodeFlow runs the Authorization Code flow with PKCE S256 and
// a nonce against the provider, in both response modes and with every
// client authentication method, then fetches UserInfo.
func TestZitadelCodeFlow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mode   oidcclient.ResponseMode
		method oidcclient.AuthMethod
	}{
		{"query, client_secret_basic", oidcclient.ResponseModeQuery, oidcclient.AuthMethodClientSecretBasic},
		{"form_post, client_secret_basic", oidcclient.ResponseModeFormPost, oidcclient.AuthMethodClientSecretBasic},
		{"query, client_secret_post", oidcclient.ResponseModeQuery, oidcclient.AuthMethodClientSecretPost},
		{"query, public client", oidcclient.ResponseModeQuery, oidcclient.AuthMethodNone},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const connection = "zitadel"

			client := storage.WebClient(clientID, clientSecret, redirectURL(connection))
			if tc.method == oidcclient.AuthMethodNone {
				client = storage.NativeClient(clientID, redirectURL(connection))
			}

			p := startProvider(t, client)
			rp := p.relyingParty(t, connection, func(cfg *oidcclient.Config) {
				cfg.ResponseMode = tc.mode
				cfg.AuthMethod = tc.method

				if tc.method == oidcclient.AuthMethodNone {
					cfg.ClientSecret = ""
				}
			})

			id, _, err := p.login(t, rp)
			require.NoError(t, err)
			assert.Equal(t, connection, id.ConnectionID)
			assert.Equal(t, p.issuer, id.Issuer)
			assert.Equal(t, userID, id.Subject)
			assert.Equal(t, []string{clientID}, id.Audience)
			assert.NotEmpty(t, id.Tokens.AccessToken)
			assert.Contains(t, claimsOf(t, id.Tokens.IDToken), "at_hash", "at_hash was verified")

			var claims struct {
				Email string `json:"email"`
			}

			require.NoError(t, id.DecodeClaims(&claims))

			info, err := rp.UserInfo(t.Context(), id)
			require.NoError(t, err)
			assert.Equal(t, userID, info.Subject)

			require.NoError(t, info.Decode(&claims))
			assert.Equal(t, userEmail, claims.Email)
		})
	}
}

// TestZitadelCallbackReplay replays a callback that completed a login: it
// is refused before the token endpoint.
func TestZitadelCallbackReplay(t *testing.T) {
	t.Parallel()

	p := startProvider(t, storage.WebClient(clientID, clientSecret, redirectURL("zitadel")))
	rp := p.relyingParty(t, "zitadel")

	_, req, err := p.login(t, rp)
	require.NoError(t, err)

	hits := p.tokenHits.Load()

	id, err := rp.HandleCallback(httptest.NewRecorder(), req)
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	assert.Nil(t, id)
	assert.Equal(t, hits, p.tokenHits.Load(), "a replayed callback never reaches the token endpoint")
}
