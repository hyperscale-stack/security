// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuanceRecorder is an oauth2.Extension recording the issuances it
// extends and answering err, or an id_token naming the grant type.
type issuanceRecorder struct {
	err error

	mu        sync.Mutex
	issuances []oauth2.TokenIssuance
}

func (*issuanceRecorder) ValidateAuthorizeRequest(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error) {
	return nil, nil
}

func (*issuanceRecorder) CompleteAuthorization(
	context.Context, *oauth2.AuthorizeRequest, oauth2.Consent, time.Time,
) (oauth2.ExtensionGrant, error) {
	return oauth2.ExtensionGrant{}, nil
}

func (e *issuanceRecorder) ExtendTokenResponse(_ context.Context, ti oauth2.TokenIssuance) (oauth2.TokenResponseExtension, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.issuances = append(e.issuances, ti)

	if e.err != nil {
		return oauth2.TokenResponseExtension{}, e.err
	}

	return oauth2.TokenResponseExtension{IDToken: "id-" + ti.GrantType}, nil
}

// TestGrantsExtendTheirResponses calls the grants directly — as a custom
// token endpoint would — with an extension on the request: the code
// exchange and both refresh paths hand it the minted access token, the
// grant context and, at the exchange only, the code's nonce, and return
// its id_token.
func TestGrantsExtendTheirResponses(t *testing.T) {
	t.Parallel()

	ext := &issuanceRecorder{}
	store := memory.New()

	req := boundCode(t, store, "extended-code", issuerA, issuerA)
	req.Extension = ext

	code, err := grant.NewAuthorizationCode(grantConfig(store)).Handle(t.Context(), req)
	require.NoError(t, err)
	assert.Equal(t, "id-authorization_code", code.IDToken)

	rotating := refreshRequest(code.Pair.Refresh.Token, issuerA)
	rotating.Extension = ext

	rotated, err := grant.NewRefreshToken(grantConfig(store)).Handle(t.Context(), rotating)
	require.NoError(t, err)
	assert.Equal(t, "id-refresh_token", rotated.IDToken)

	static := refreshRequest(rotated.Pair.Refresh.Token, issuerA)
	static.Extension, static.Profile = ext, oauth2.Profile20

	kept, err := grant.NewRefreshToken(grantConfig(store)).Handle(t.Context(), static)
	require.NoError(t, err)
	assert.Equal(t, "id-refresh_token", kept.IDToken)

	require.Len(t, ext.issuances, 3)

	for i, resp := range []*grant.Response{code, rotated, kept} {
		ti := ext.issuances[i]
		assert.Equal(t, resp.Pair.Access, ti.Access, "the access token about to be persisted")
		assert.Equal(t, grantContext, ti.Access.ExtensionData)
		assert.Equal(t, issuerA, ti.Access.Issuer)
		assert.Equal(t, clientID, ti.Client.ID())
	}

	assert.Equal(t, oauth2.GrantTypeAuthorizationCode, ext.issuances[0].GrantType)
	assert.Empty(t, ext.issuances[0].Nonce, "the seeded code has no nonce")
	assert.Equal(t, oauth2.GrantTypeRefreshToken, ext.issuances[1].GrantType)
	assert.Equal(t, oauth2.GrantTypeRefreshToken, ext.issuances[2].GrantType)
}

// TestCodeExchangeHandsTheNonceToTheExtension: the nonce the code recorded
// reaches the extension at the exchange.
func TestCodeExchangeHandsTheNonceToTheExtension(t *testing.T) {
	t.Parallel()

	store := memory.New()
	now := time.Now()

	require.NoError(t, store.SaveAuthorizationCode(t.Context(), &oauth2.AuthorizationCode{
		Code: "nonce-code", CodeHash: oauth2.HashToken(nil, "nonce-code"),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, Scope: "read:mail",
		Nonce: "n-0S6_WzA2Mj", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Issuer: issuerA,
	}))

	ext := &issuanceRecorder{}
	req := boundCode(t, memory.New(), "unused", issuerA, issuerA)
	req.Form.Set("code", "nonce-code")
	req.Form.Del("code_verifier")
	req.Profile = oauth2.Profile20
	req.Extension = ext

	_, err := grant.NewAuthorizationCode(grantConfig(store)).Handle(t.Context(), req)
	require.NoError(t, err)
	require.Len(t, ext.issuances, 1)
	assert.Equal(t, "n-0S6_WzA2Mj", ext.issuances[0].Nonce)
}

// TestGrantExtensionFailuresPersistNothing: an extension failing the code
// exchange or a refresh answers server_error — invalid_grant passing
// through — and nothing is persisted; the refresh token stays usable.
func TestGrantExtensionFailuresPersistNothing(t *testing.T) {
	t.Parallel()

	errDown := errors.New("signer down")

	for _, tc := range []struct {
		err      error
		wantCode string
	}{
		{errDown, oauth2.CodeServerError},
		{oauth2.ErrInvalidGrant.WithDescription("not an OpenID Connect grant"), oauth2.CodeInvalidGrant},
	} {
		store := &countingStore{Store: memory.New()}
		pair := issueRefresh(t, store, issuerA)
		writes := store.writes.Load()

		ext := &issuanceRecorder{err: tc.err}

		req := boundCode(t, store, "failing-code", issuerA, issuerA)
		req.Extension = ext

		resp, err := grant.NewAuthorizationCode(grantConfig(store)).Handle(t.Context(), req)
		assert.Nil(t, resp)
		assert.Equal(t, tc.wantCode, oauth2.IsCode(err))
		assert.ErrorIs(t, err, tc.err)

		for _, p := range []oauth2.Profile{oauth2.Profile20BCP, oauth2.Profile20} {
			refresh := refreshRequest(pair.Refresh.Token, issuerA)
			refresh.Extension, refresh.Profile = ext, p

			resp, err = grant.NewRefreshToken(grantConfig(store)).Handle(t.Context(), refresh)
			assert.Nil(t, resp)
			assert.Equal(t, tc.wantCode, oauth2.IsCode(err))
		}

		assert.Equal(t, writes, store.writes.Load(), "nothing persisted")

		rt, err := store.LookupRefreshToken(t.Context(), pair.Refresh.TokenHash)
		require.NoError(t, err)
		assert.False(t, rt.Consumed)
	}
}

// TestPasswordGrantNeverCallsTheExtension: no authorization precedes the
// legacy password grant: nothing to extend.
func TestPasswordGrantNeverCallsTheExtension(t *testing.T) {
	t.Parallel()

	ext := &issuanceRecorder{}
	req := refreshRequest("", issuerA)
	req.Form.Set("username", "alice")
	req.Form.Set("password", "pw")
	req.Profile = oauth2.Profile20
	req.Extension = ext

	resp, err := grant.NewLegacyPassword(grantConfig(memory.New()), staticVerifier{}).Handle(t.Context(), req)
	require.NoError(t, err)
	assert.Empty(t, resp.IDToken)
	assert.Empty(t, ext.issuances)
}
