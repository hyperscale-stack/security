// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"net/url"
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

// missingCredentials is the error_description client_secret_basic and
// client_secret_post answer a missing client_id or an empty secret with.
const missingCredentials = "missing client_id or client_secret"

// emptySecretNow is the instant newEmptySecretServer's clock is pinned to.
var emptySecretNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// emptySecretClients lists the clients newEmptySecretServer registers: one
// with a secret, and one without a secret for each client type.
var emptySecretClients = []string{
	testClientID, "secretless-confidential", "secretless-public", "secretless-untyped",
}

// newEmptySecretServer builds a Profile20BCP server pinned to
// emptySecretNow. It serves /token (client_credentials), /revoke and
// /introspect, authenticates clients with client_secret_basic,
// client_secret_post and none, and holds one active access token, at-<id>,
// issued to each of emptySecretClients.
func newEmptySecretServer(t *testing.T) (*oauth2.Server, *memory.Store) {
	t.Helper()

	store := memory.New()
	clients := &staticClientStore{clients: map[string]oauth2.Client{
		testClientID: &oauth2.DefaultClient{
			IDValue: testClientID, Secret: testClientSecret, TypeValue: oauth2.ClientConfidential,
		},
		"secretless-confidential": &oauth2.DefaultClient{
			IDValue: "secretless-confidential", TypeValue: oauth2.ClientConfidential,
		},
		"secretless-public": &oauth2.DefaultClient{
			IDValue: "secretless-public", TypeValue: oauth2.ClientPublic,
		},
		"secretless-untyped": &oauth2.DefaultClient{IDValue: "secretless-untyped"},
	}}
	gcfg := grant.Config{Storage: store, AccessTokens: token.NewOpaque(32), AccessTTL: time.Hour}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{grant.NewClientCredentials(gcfg)},
		ClientAuth: []oauth2.ClientAuthenticator{
			clientauth.NewBasic(), clientauth.NewPost(), clientauth.NewNone(),
		},
		Now: func() time.Time { return emptySecretNow },
	})
	require.NoError(t, err)

	for _, id := range emptySecretClients {
		require.NoError(t, store.SaveTokenPair(t.Context(), &oauth2.TokenPair{Access: oauth2.AccessToken{
			TokenHash: oauth2.HashToken(nil, "at-"+id), ClientID: id, Subject: id, Scope: "read",
			IssuedAt: emptySecretNow, ExpiresAt: emptySecretNow.Add(time.Hour),
		}}))
	}

	return srv, store
}

// TestEmptyBasicPasswordRefusedAtEveryEndpoint pins that an empty HTTP
// Basic password authenticates no client at /token, /revoke or /introspect
// (#94). Whether the client has a secret, has none — whatever its type — or
// does not exist, the answer is the same 401 invalid_client, so it tells
// nothing about the client, and the client's token is neither revoked nor
// disclosed.
func TestEmptyBasicPasswordRefusedAtEveryEndpoint(t *testing.T) {
	t.Parallel()

	endpoints := []struct {
		name    string
		handler func(*oauth2.Server) http.Handler
		form    func(id string) url.Values
	}{
		{
			name:    "token",
			handler: (*oauth2.Server).TokenHandler,
			form:    func(string) url.Values { return url.Values{"grant_type": {"client_credentials"}} },
		},
		{
			name:    "revoke",
			handler: (*oauth2.Server).RevokeHandler,
			form:    func(id string) url.Values { return url.Values{"token": {"at-" + id}} },
		},
		{
			name:    "introspect",
			handler: (*oauth2.Server).IntrospectHandler,
			form:    func(id string) url.Values { return url.Values{"token": {"at-" + id}} },
		},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			t.Parallel()

			srv, store := newEmptySecretServer(t)
			h := ep.handler(srv)
			path := "/oauth2/" + ep.name

			// The reference answer, for a client that does not exist:
			// RFC 6749 §5.2 invalid_client, with the challenge HTTP Basic
			// calls for.
			ref := serve(h, basicForm(path, ep.form("ghost"), "ghost", ""))
			require.Equal(t, http.StatusUnauthorized, ref.Code)
			assert.Equal(t, `Basic realm="oauth2"`, ref.Header().Get("WWW-Authenticate"))
			assert.JSONEq(t, `{"error":"invalid_client","error_description":"`+missingCredentials+`"}`, ref.Body.String())

			desc, _ := decodeBody(t, ref)["error_description"].(string)
			assert.Regexp(t, descriptionCharset, desc)

			for _, id := range emptySecretClients {
				rec := serve(h, basicForm(path, ep.form(id), id, ""))

				// The same status, headers and bytes as for an unknown
				// client: the answer reveals nothing about the client...
				assert.Equal(t, ref.Code, rec.Code, id)
				assert.Equal(t, ref.Header(), rec.Header(), id)
				assert.Equal(t, ref.Body.Bytes(), rec.Body.Bytes(), id)

				// ...and its token was not revoked.
				_, err := store.LookupAccessToken(t.Context(), oauth2.HashToken(nil, "at-"+id))
				assert.NoError(t, err, id)
			}
		})
	}
}
