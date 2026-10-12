// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
)

// ExampleProvider_Paths prints where to mount the handlers of a root issuer
// and of a path issuer: the URLs the discovery document advertises.
func ExampleProvider_Paths() {
	store := memory.New()
	grants := grant.Config{Storage: store, AccessTokens: token.NewOpaque(32)}

	op, err := oidcprovider.New(oauth2.ServerConfig{
		Storage:        store,
		ClientStore:    exampleClients{},
		IssuerResolver: oauth2.StaticIssuer("https://op.example", "https://api.example"),
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(grants)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewNone()},
	}, oidcprovider.Config{Keys: exampleKeys{}, Claims: exampleClaims{}, Interaction: exampleInteraction{}})
	if err != nil {
		panic(err)
	}

	for _, issuer := range []string{"https://op.example", "https://op.example/tenant-a"} {
		paths, err := op.Paths(issuer)
		if err != nil {
			panic(err)
		}

		fmt.Println(paths.Discovery, paths.Metadata, paths.JWKS)
		fmt.Println(paths.Authorize, paths.Token, paths.UserInfo, paths.Revoke, paths.Introspect)
	}

	// Output:
	// /.well-known/openid-configuration /.well-known/oauth-authorization-server /.well-known/jwks.json
	// /oauth2/authorize /oauth2/token /oauth2/userinfo /oauth2/revoke /oauth2/introspect
	// /tenant-a/.well-known/openid-configuration /.well-known/oauth-authorization-server/tenant-a /tenant-a/.well-known/jwks.json
	// /tenant-a/oauth2/authorize /tenant-a/oauth2/token /tenant-a/oauth2/userinfo /tenant-a/oauth2/revoke /tenant-a/oauth2/introspect
}

// The application's side, left out of the example.
type (
	exampleClients     struct{}
	exampleKeys        struct{}
	exampleClaims      struct{}
	exampleInteraction struct{}
)

func (exampleClients) LoadClient(context.Context, string) (oauth2.Client, error) { return nil, nil }

func (exampleKeys) Keys(context.Context, string) (oidcprovider.KeyRing, error) {
	return oidcprovider.KeyRing{}, nil
}

func (exampleClaims) Claims(context.Context, oidcprovider.ClaimsQuery) (map[string]any, error) {
	return nil, oidcprovider.ErrUnknownSubject
}

func (exampleInteraction) Authorize(http.ResponseWriter, *http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error) {
	return &oidcprovider.Decision{}, nil
}

func (exampleInteraction) AuthorizeSilently(*http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error) {
	return &oidcprovider.Decision{Refusal: oauth2.ErrLoginRequired}, nil
}
