// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
)

// sessionExtension records, for every authorization, the authentication
// time the application attests, and hands it back on every token response
// derived from it. A real OpenID provider (oidc/provider) signs an ID Token
// with it instead.
type sessionExtension struct{}

// authEvent is the trusted result the application returns in
// Consent.ExtensionResult.
type authEvent struct{ At time.Time }

func (sessionExtension) ValidateAuthorizeRequest(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error) {
	return nil, nil
}

func (sessionExtension) CompleteAuthorization(
	_ context.Context, _ *oauth2.AuthorizeRequest, consent oauth2.Consent, _ time.Time,
) (oauth2.ExtensionGrant, error) {
	event, ok := consent.ExtensionResult.(authEvent)
	if !ok {
		return oauth2.ExtensionGrant{}, oauth2.ErrLoginRequired
	}

	return oauth2.ExtensionGrant{Data: event.At.UTC().Format(time.RFC3339)}, nil
}

func (sessionExtension) ExtendTokenResponse(_ context.Context, ti oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	return oauth2.TokenResponseExtension{IDToken: "authenticated-at:" + ti.Access.ExtensionData}, nil
}

// ExampleExtension plugs an extension into the authorization-code flow:
// the trusted authentication result travels from the ConsentFunc to the
// token response, through the code, without a second /token endpoint.
func ExampleExtension() {
	store := memory.New()
	gcfg := grant.Config{
		Storage: store, AccessTokens: token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour, RefreshTTL: 24 * time.Hour,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Storage: store,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			"app": &oauth2.DefaultClient{
				GrantTypeValues: allGrantTypes,
				IDValue:         "app", Secret: "app-secret", TypeValue: oauth2.ClientConfidential,
				RedirectURIValues: []string{"https://app.example/cb"},
			},
		}},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg)},
		Extension:      sessionExtension{},
	})
	if err != nil {
		panic(err)
	}

	// The application authenticated alice at 9:00 and approves.
	consent := func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		return &oauth2.Consent{
			Approved: true, Subject: "alice",
			ExtensionResult: authEvent{At: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)},
		}, nil
	}

	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	authorize := httptest.NewRecorder()
	srv.AuthorizeHandler(oauth2.AuthorizeConfig{}, consent).ServeHTTP(authorize, httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&client_id=app&redirect_uri=https://app.example/cb"+
			"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", nil))

	location, _ := url.Parse(authorize.Header().Get("Location"))

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("app", "app-secret")

	exchange := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(exchange, req)

	var body struct {
		IDToken string `json:"id_token"`
	}

	_ = json.NewDecoder(exchange.Body).Decode(&body)

	fmt.Println(exchange.Code, body.IDToken)
	// Output: 200 authenticated-at:2026-10-12T09:00:00Z
}
