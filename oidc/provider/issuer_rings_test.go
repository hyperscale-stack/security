// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tenantIssuer is a path issuer on the root issuer's host (Discovery §4.1).
const tenantIssuer = testIssuer + "/tenant-b"

// pathIssuer resolves tenantIssuer for the requests under its path and the
// root issuer for the others: both share a host, so only their keys tell
// them apart.
type pathIssuer struct{}

func (pathIssuer) Resolve(_ context.Context, r *http.Request) (string, string, error) {
	if strings.HasPrefix(r.URL.Path, "/tenant-b/") {
		return tenantIssuer, "api", nil
	}

	return testIssuer, "api", nil
}

// TestPathIssuersUseTheirOwnKeyRings: every issuer — a path issuer sharing
// the root issuer's host included — advertises the algorithms of its own
// ring, publishes its own keys, signs its ID Tokens with them and verifies
// an id_token_hint against them only (OIDC Core §3.1.2.1, §10.1; Discovery
// §3, §4.1).
func TestPathIssuersUseTheirOwnKeyRings(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withResolver(pathIssuer{}))
	e.keys.setFor(tenantIssuer, oidcprovider.KeyRing{Signing: []jwtsec.PrivateKey{signingRSAB()}})

	root := discovery(t, e, get("/.well-known/openid-configuration"))
	tenant := discovery(t, e, get("/tenant-b/.well-known/openid-configuration"))
	assert.Equal(t, []any{"RS256", "ES256"}, root["id_token_signing_alg_values_supported"])
	assert.Equal(t, []any{"RS256"}, tenant["id_token_signing_alg_values_supported"])
	assert.Equal(t, []string{"rsa-a", "ec-1"}, kids(jwksKeys(t, e, get("/.well-known/jwks.json"))))
	assert.Equal(t, []string{"rsa-b"}, kids(jwksKeys(t, e, get("/tenant-b/.well-known/jwks.json"))))

	authorize := func(q url.Values) url.Values {
		t.Helper()

		return redirect(t, serve(e.op.AuthorizeHandler(oauth2.AuthorizeConfig{}), get("/tenant-b/oauth2/authorize?"+q.Encode())))
	}

	code := authorize(authorizeQuery()).Get("code")
	require.NotEmpty(t, code)

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {webRedirectURI}, "code_verifier": {pkceVerifier},
	}
	r := httptest.NewRequest(http.MethodPost, "/tenant-b/oauth2/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(webClientID), url.QueryEscape(webClientSecret))

	header, claims := decodeJWT(t, tokens(t, serve(e.op.Server().TokenHandler(), r)).IDToken,
		[]jwtsec.PublicKey{publicOf(signingRSAB())})
	assert.Equal(t, "rsa-b", header["kid"], "signed with the tenant's key")
	assert.Equal(t, tenantIssuer, claims["iss"])

	// A hint naming the tenant issuer verifies against the tenant's keys
	// only: the root issuer's key, on the same host, is another realm's.
	hint := hintClaims()
	hint["iss"] = tenantIssuer

	refused := authorize(with(authorizeQuery(), "id_token_hint", signHint(t, signingRSA(), hint)))
	assert.Equal(t, oauth2.CodeInvalidRequest, refused.Get("error"))

	accepted := authorize(with(authorizeQuery(), "id_token_hint", signHint(t, signingRSAB(), hint)))
	assert.NotEmpty(t, accepted.Get("code"))
}
