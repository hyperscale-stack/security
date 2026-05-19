// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shared fixtures.
const (
	clientID       = "client-1"
	clientSecret   = "secret-1"
	subject        = "alice"
	redirectURI    = "https://app.example/cb"
	codeVerifier   = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge  = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func newClient() oauth2.Client {
	return &oauth2.DefaultClient{
		IDValue:           clientID,
		Secret:            clientSecret,
		TypeValue:         oauth2.ClientConfidential,
		RedirectURIValues: []string{redirectURI},
		ScopeValues:       []string{"read:mail", "write:mail", "admin"},
	}
}

func newStore() *memory.Store { return memory.New() }

func newAccessGen() token.AccessTokenGenerator {
	return token.NewOpaque([]byte("pepper"), 32)
}

func newRefreshGen() token.RefreshTokenGenerator {
	return token.OpaqueRefreshAdapter{Opaque: token.NewOpaque([]byte("pepper"), 32)}
}

func newAuthCodeReq(ctx context.Context, store *memory.Store, withPKCE bool) (*grant.AuthorizationCode, grant.Request) {
	form := url.Values{}
	form.Set("redirect_uri", redirectURI)

	rawCode := "raw-auth-code-xyz"
	codeHash := oauth2.HashToken(nil, rawCode)
	form.Set("code", rawCode)

	code := &oauth2.AuthorizationCode{
		Code:        rawCode,
		CodeHash:    codeHash,
		ClientID:    clientID,
		Subject:     subject,
		RedirectURI: redirectURI,
		Scope:       "read:mail",
		IssuedAt:    time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 5, 20, 12, 10, 0, 0, time.UTC),
	}

	if withPKCE {
		code.CodeChallenge = codeChallenge
		code.CodeChallengeMethod = string(pkce.MethodS256)
		form.Set("code_verifier", codeVerifier)
	}

	_ = store.SaveAuthorizationCode(ctx, code)

	g := grant.NewAuthorizationCode(grant.Config{
		Storage:       store,
		AccessTokens:  newAccessGen(),
		RefreshTokens: newRefreshGen(),
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		RequirePKCE:   false,
	})
	req := grant.Request{
		Client:   newClient(),
		Form:     form,
		Issuer:   "https://auth.example",
		Audience: "api",
		Now:      time.Date(2026, 5, 20, 12, 5, 0, 0, time.UTC),
	}

	return g, req
}

func TestAuthorizationCodeHappyPath(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, true)

	resp, err := g.Handle(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Pair.Access.Token)
	assert.NotNil(t, resp.Pair.Refresh)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "read:mail", resp.Scope)
}

func TestAuthorizationCodeReuseDetected(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, true)

	_, err := g.Handle(context.Background(), req)
	require.NoError(t, err)

	// Second use must fail.
	_, err = g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, oauth2.ErrCodeAlreadyUsed) || oauth2.IsCode(err) == oauth2.CodeInvalidGrant,
		"replayed code must be refused")
}

func TestAuthorizationCodePKCEMismatch(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, true)
	req.Form.Set("code_verifier", "wrong-verifier")

	_, err := g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestAuthorizationCodeRedirectMismatch(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, true)
	req.Form.Set("redirect_uri", "https://attacker.example/cb")

	_, err := g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestAuthorizationCodeRequiresPKCEWhenConfigured(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, false) // no PKCE on the code

	// Override g with RequirePKCE=true and reuse req. Need a fresh code
	// because newAuthCodeReq already consumed nothing yet.
	gReq := grant.NewAuthorizationCode(grant.Config{
		Storage:       store,
		AccessTokens:  newAccessGen(),
		RefreshTokens: newRefreshGen(),
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		RequirePKCE:   true,
	})

	_, err := gReq.Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	_ = g // silence unused; g is the non-pkce-required version we don't use here
}

func TestClientCredentialsHappyPath(t *testing.T) {
	t.Parallel()

	store := newStore()
	g := grant.NewClientCredentials(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	form := url.Values{}
	form.Set("scope", "read:mail")

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: form, Issuer: "https://auth.example", Audience: "api",
		Now: time.Now(),
	})
	require.NoError(t, err)
	assert.Nil(t, resp.Pair.Refresh, "RFC 6749 §4.4.3 forbids refresh tokens for client_credentials")
	assert.Equal(t, "read:mail", resp.Scope)
}

func TestClientCredentialsRejectsBroadenedScope(t *testing.T) {
	t.Parallel()

	store := newStore()
	g := grant.NewClientCredentials(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	form := url.Values{}
	form.Set("scope", "billing:write")

	_, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: form, Now: time.Now(),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
}

func TestRefreshTokenRotationDetectsReuse(t *testing.T) {
	t.Parallel()

	store := newStore()
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	// Seed an existing refresh token.
	rawRT := "raw-refresh-token-xyz"
	rtHash := oauth2.HashToken(nil, rawRT)
	rt := &oauth2.RefreshToken{
		Token: rawRT, TokenHash: rtHash, ClientID: clientID, Subject: subject,
		Scope: "read:mail", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
		FamilyID: "family-1",
	}
	require.NoError(t, store.SaveRefreshToken(context.Background(), rt))

	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, RotateRefreshTokens: true,
	})

	form := url.Values{}
	form.Set("refresh_token", rawRT)

	req := grant.Request{
		Client: newClient(), Form: form, Issuer: "https://auth.example",
		Audience: "api", Now: now.Add(5 * time.Minute),
	}

	_, err := g.Handle(context.Background(), req)
	require.NoError(t, err, "first rotation must succeed")

	// Replaying with the SAME old refresh token must fail and revoke the family.
	_, err = g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
}
