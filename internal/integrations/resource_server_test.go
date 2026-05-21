// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package integrations_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localIntrospectVerifier is a [bearer.TokenVerifier] that resolves opaque
// access tokens by hashing them and consulting the [oauth2.AccessTokenStore]
// directly. It is the in-process equivalent of an RFC 7662 introspection
// call — the canonical way to validate opaque tokens when the authorization
// server and the resource server share an address space (single binary or
// shared storage).
type localIntrospectVerifier struct {
	store oauth2.AccessTokenStore
}

// Verify implements [bearer.TokenVerifier]. It hashes the raw token,
// looks it up in storage, and returns an authenticated
// [bearer.Authentication] on success.
func (v *localIntrospectVerifier) Verify(ctx context.Context, token string) (security.Authentication, error) {
	hash := oauth2.HashToken(nil, token)

	at, err := v.store.LookupAccessToken(ctx, hash)
	if err != nil {
		return nil, security.ErrTokenNotFound
	}

	if at.IsExpired(time.Now()) {
		return nil, security.ErrTokenExpired
	}

	return bearer.New(token).WithAuthenticated(tokenPrincipal{sub: at.Subject}, nil, at.Subject), nil
}

type tokenPrincipal struct{ sub string }

func (p tokenPrincipal) Subject() string { return p.sub }

// TestResourceServerHappyPath issues a token via /token, then calls a
// resource server guarded by httpsec.Middleware + bearer.Authenticator.
// The opaque token is validated against the shared storage via the
// in-process introspection verifier.
func TestResourceServerHappyPath(t *testing.T) {
	t.Parallel()

	srv, store := newServer(t)

	// 1. Authorization server hands us an access token via /token.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "api:read")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	accessToken, _ := body["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// 2. Resource server.
	verifier := &localIntrospectVerifier{store: store}
	engine := security.NewEngine(
		security.NewManager(bearer.NewAuthenticator(verifier)),
		bearer.NewExtractor(),
	)

	resource := httpsec.Middleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, _ := security.FromContext(r.Context())
		_, _ = io.WriteString(w, "hello "+auth.Principal().Subject())
	}))

	// 3. Authenticated call -> 200 OK.
	probe := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	probe.Header.Set("Authorization", "Bearer "+accessToken)

	rec = httptest.NewRecorder()
	resource.ServeHTTP(rec, probe)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hello "+clientID, rec.Body.String())

	// 4. Bad token -> 401.
	probe = httptest.NewRequest(http.MethodGet, "/api/me", nil)
	probe.Header.Set("Authorization", "Bearer not-a-real-token")

	rec = httptest.NewRecorder()
	resource.ServeHTTP(rec, probe)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// 5. No token at all -> 401 (deny-by-default).
	rec = httptest.NewRecorder()
	resource.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
