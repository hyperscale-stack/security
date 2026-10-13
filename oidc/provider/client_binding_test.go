// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCrossTenantClientNeverReachesTheInteraction: with its clients bound
// to their issuer (oauth2.IssuerBoundClient), a client of tenant A cannot
// send tenant B's end-users to B's login page — the core answers the bare
// 400 of an unknown client before any OpenID processing, the Interaction is
// never called — nor redeem anything at B.
func TestCrossTenantClientNeverReachesTheInteraction(t *testing.T) {
	t.Parallel()

	bound := &oauth2.DefaultClient{
		IDValue: "tenant-a-app", Secret: webClientSecret, TypeValue: oauth2.ClientConfidential,
		RedirectURIValues: []string{webRedirectURI}, ScopeValues: []string{"openid", "profile", "email"},
		GrantTypeValues: webGrantTypes, IssuerValues: []string{testIssuer},
	}
	e := newEnv(t, withClient(bound))
	q := with(authorizeQuery(), "client_id", bound.IDValue)

	r := get("/oauth2/authorize?" + q.Encode())
	r.Host = "tenant-b.example"
	rec := serve(e.op.AuthorizeHandler(oauth2.AuthorizeConfig{}), r)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, rec.Header().Get("Location"))

	interactive, silent := e.interaction.calls()
	assert.Empty(t, interactive, "no login page of tenant B for tenant A's client")
	assert.Empty(t, silent)

	code := e.code(q) // at its own issuer

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {webRedirectURI}, "code_verifier": {pkceVerifier},
	}
	tr := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	tr.Host = "tenant-b.example"
	tr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tr.SetBasicAuth(url.QueryEscape(bound.IDValue), url.QueryEscape(webClientSecret))

	atB := serve(e.op.Server().TokenHandler(), tr)
	require.Equal(t, http.StatusUnauthorized, atB.Code)
	assert.Equal(t, oauth2.CodeInvalidClient, oauthError(t, atB))
	assert.NotContains(t, atB.Body.String(), "id_token")

	assert.NotEmpty(t, tokens(t, e.exchangeAs(code, bound.IDValue)).IDToken, "redeemable at its own issuer")
}
