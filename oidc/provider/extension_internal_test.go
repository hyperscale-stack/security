// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/require"
)

// TestTokenResponseRefusesAnotherClientsGrant: the provider re-checks the
// TokenIssuance contract — the access token belongs to the authenticated
// client — before it asks for claims or signs an ID Token. The core never
// breaks it, so only a direct call reaches the guard.
func TestTokenResponseRefusesAnotherClientsGrant(t *testing.T) {
	t.Parallel()

	p := &Provider{}
	access := oauth2.AccessToken{ClientID: "web", Scope: ScopeOpenID, ExtensionData: `{"v":1,"auth_time":1760000000}`}

	elsewhere := &oauth2.DefaultClient{IDValue: "web", IssuerValues: []string{"https://other.example"}}
	access.Issuer = "https://op.example"

	for _, client := range []oauth2.Client{nil, &oauth2.DefaultClient{IDValue: "other"}, elsewhere} {
		_, err := p.extendTokenResponse(context.Background(), oauth2.TokenIssuance{
			GrantType: oauth2.GrantTypeAuthorizationCode, Client: client, Access: access,
		})
		require.ErrorIs(t, err, errClientMismatch)
	}
}
