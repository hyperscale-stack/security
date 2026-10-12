// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingClients is a ClientStore counting its lookups.
type countingClients struct {
	staticClientStore

	loads atomic.Int32
}

func (c *countingClients) LoadClient(ctx context.Context, id string) (oauth2.Client, error) {
	c.loads.Add(1)

	return c.staticClientStore.LoadClient(ctx, id)
}

// authMethodsServer serves the confidential client "machine" and the public
// client "spa" with every client-authentication method.
func authMethodsServer(t *testing.T) (*oauth2.Server, *countingClients) {
	t.Helper()

	clients := &countingClients{staticClientStore: staticClientStore{clients: map[string]oauth2.Client{
		"machine": confidentialClient([]string{oauth2.GrantTypeClientCredentials}, []string{"read"}),
		"spa": &oauth2.DefaultClient{
			IDValue: "spa", TypeValue: oauth2.ClientPublic, GrantTypeValues: []string{oauth2.GrantTypeAuthorizationCode},
		},
	}}}

	store := memory.New()
	gcfg := grant.Config{Storage: store, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Storage: store, ClientStore: clients, IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:     []oauth2.Grant{grant.NewClientCredentials(gcfg)},
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone()},
	})
	require.NoError(t, err)

	return srv, clients
}

// TestOneClientAuthenticationMethodPerRequest pins RFC 6749 §2.3 ("The
// client MUST NOT use more than one authentication method in each request")
// at every endpoint authenticating clients: a request carrying the
// Authorization header and a client_secret in the body, several
// Authorization fields (RFC 9110 §5.3), or a body client_id naming another
// client than the one authenticated is invalid_request (RFC 6749 §5.2:
// "includes multiple credentials, utilizes more than one mechanism for
// authenticating the client") — the first two before any client is loaded.
// An empty occurrence hides nothing (RFC 6749 §3.1): a body credential
// after one counts. A body client_id naming the authenticated client is
// accepted (§3.2.1).
func TestOneClientAuthenticationMethodPerRequest(t *testing.T) {
	t.Parallel()

	endpoints := map[string]struct {
		handler func(*oauth2.Server) http.Handler
		form    url.Values
	}{
		"token":      {(*oauth2.Server).TokenHandler, url.Values{"grant_type": {oauth2.GrantTypeClientCredentials}}},
		"revoke":     {(*oauth2.Server).RevokeHandler, url.Values{"token": {"unknown"}}},
		"introspect": {(*oauth2.Server).IntrospectHandler, url.Values{"token": {"unknown"}}},
	}

	cases := []struct {
		name        string
		basic       []string // the Authorization field values sent
		body        url.Values
		status      int
		description string
		noLookup    bool
	}{
		{"basic and a wrong body secret", []string{basic("machine", "machine-secret")}, url.Values{"client_secret": {"wrong"}},
			http.StatusBadRequest, "more than one client authentication method", true},
		{"basic and the right body secret", []string{basic("machine", "machine-secret")}, url.Values{"client_secret": {"machine-secret"}},
			http.StatusBadRequest, "more than one client authentication method", true},
		{"a wrong basic and a body secret", []string{basic("machine", "wrong")}, url.Values{"client_id": {"machine"}, "client_secret": {"machine-secret"}},
			http.StatusBadRequest, "more than one client authentication method", true},
		{"basic and a body secret after an empty one", []string{basic("machine", "machine-secret")}, url.Values{"client_secret": {"", "wrong"}},
			http.StatusBadRequest, "more than one client authentication method", true},
		{"two Authorization fields", []string{basic("machine", "machine-secret"), basic("machine", "machine-secret")}, url.Values{},
			http.StatusBadRequest, "more than one Authorization header", true},
		{"basic and another body client_id", []string{basic("machine", "machine-secret")}, url.Values{"client_id": {"spa"}},
			http.StatusBadRequest, "client_id does not name the authenticated client", false},
		{"basic and another body client_id after an empty one", []string{basic("machine", "machine-secret")}, url.Values{"client_id": {"", "spa"}},
			http.StatusBadRequest, "client_id does not name the authenticated client", false},
		{"basic and a case variant of its client_id", []string{basic("machine", "machine-secret")}, url.Values{"client_id": {"MACHINE"}},
			http.StatusBadRequest, "client_id does not name the authenticated client", false},
		{"basic and its own body client_id", []string{basic("machine", "machine-secret")}, url.Values{"client_id": {"machine"}},
			http.StatusOK, "", false},
	}

	for endpoint, ep := range endpoints {
		for _, tc := range cases {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				srv, clients := authMethodsServer(t)

				form := url.Values{}
				for k, v := range ep.form {
					form[k] = v
				}

				for k, v := range tc.body {
					form[k] = v
				}

				req := httptest.NewRequest(http.MethodPost, "/oauth2/"+endpoint, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				for _, v := range tc.basic {
					req.Header.Add("Authorization", v)
				}

				rec := httptest.NewRecorder()
				ep.handler(srv).ServeHTTP(rec, req)
				require.Equal(t, tc.status, rec.Code, rec.Body.String())

				if tc.status == http.StatusOK {
					return
				}

				body := jsonBody(t, rec)
				assert.Equal(t, oauth2.CodeInvalidRequest, body["error"])
				assert.Equal(t, tc.description, body["error_description"])
				assert.Empty(t, rec.Header().Get("WWW-Authenticate"), "invalid_request, not invalid_client")

				if tc.noLookup {
					assert.Zero(t, clients.loads.Load(), "refused before any client is loaded")
				}
			})
		}
	}
}

// basic returns the client_secret_basic Authorization value of id:secret.
func basic(id, secret string) string {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.SetBasicAuth(id, secret)

	return req.Header.Get("Authorization")
}
