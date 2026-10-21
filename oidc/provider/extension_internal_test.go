// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"errors"
	"net/url"
	"strings"
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

// TestProtocolGuardsBehindTheCore: the provider re-checks the response type
// and the nonce of an OpenID request although the core refuses such requests
// first — no OpenID request gets another response type through (its
// AuthorizeHandler refuses AllowImplicit, and a handler built from Server()
// is not mounted for OpenID requests), and the core bounds the nonce of every
// request — so only a direct call reaches these guards.
func TestProtocolGuardsBehindTheCore(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkProtocol(url.Values{}, &oauth2.AuthorizeRequest{ResponseType: responseTypeCode}))

	err := checkProtocol(url.Values{}, &oauth2.AuthorizeRequest{ResponseType: "token"})
	require.Equal(t, oauth2.CodeUnsupportedResponseType, oauth2.IsCode(err))

	err = checkProtocol(url.Values{}, &oauth2.AuthorizeRequest{ResponseType: responseTypeCode, Nonce: "a\x00b"})
	require.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err))

	require.NoError(t, checkNonce(strings.Repeat("n", MaxNonceLength)))

	for _, nonce := range []string{strings.Repeat("n", MaxNonceLength+1), "a\x00b", "\xff"} {
		require.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(checkNonce(nonce)), "%q", nonce)
	}
}

// TestOfflineAccessNeedsTheCodeFlow pins OpenID Connect Core §11: the
// provider ignores offline_access outside the authorization code flow,
// whatever the decision. Its AuthorizeHandler serves no implicit flow — the
// core refuses any other response type first — and a request approved by
// another ConsentFunc gets no provider rule, so only a direct call reaches
// it.
func TestOfflineAccessNeedsTheCodeFlow(t *testing.T) {
	t.Parallel()

	view := &authRequest{scopes: []string{"read", ScopeOfflineAccess}}

	scope, offline, err := view.offlineScope("read "+ScopeOfflineAccess, OfflineAccessPrompted)
	require.NoError(t, err)
	require.Equal(t, "read", scope)
	require.False(t, offline)

	_, _, err = view.offlineScope(ScopeOfflineAccess, OfflineAccessByPolicy)
	require.Equal(t, oauth2.CodeAccessDenied, oauth2.IsCode(err))

	view.codeFlow = true

	_, offline, err = view.offlineScope("read "+ScopeOfflineAccess, OfflineAccessByPolicy)
	require.NoError(t, err)
	require.True(t, offline, "kept in the code flow")
}

// unusedClients is a ClientStore that must not be asked.
type unusedClients struct{ t *testing.T }

func (u unusedClients) LoadClient(context.Context, string) (oauth2.Client, error) {
	u.t.Error("the ClientStore was asked")

	return nil, errors.New("unusedClients: not asked")
}

// TestTheRequestingClientIsNeverTheAudience: an access-token audience equal
// to the requesting client's ID is refused without asking the ClientStore
// — whatever grants that client declares.
func TestTheRequestingClientIsNeverTheAudience(t *testing.T) {
	t.Parallel()

	p := &Provider{clients: unusedClients{t: t}}
	requester := &oauth2.DefaultClient{IDValue: "web", GrantTypeValues: []string{oauth2.GrantTypePassword}}

	rp, err := p.audienceNamesRP(context.Background(), "web", "https://op.example", requester)
	require.NoError(t, err)
	require.True(t, rp)

	rp, err = p.audienceNamesRP(context.Background(), "", "https://op.example", requester)
	require.NoError(t, err)
	require.False(t, rp, "an empty audience names no client")
}
