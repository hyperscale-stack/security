// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrantTypes(t *testing.T) {
	t.Parallel()

	cfg := grant.Config{Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour}

	assert.Equal(t, "authorization_code", grant.NewAuthorizationCode(cfg).Type())
	assert.Equal(t, "client_credentials", grant.NewClientCredentials(cfg).Type())
	assert.Equal(t, "refresh_token", grant.NewRefreshToken(cfg).Type())
}

func TestConstructorsPanicWithoutDeps(t *testing.T) {
	t.Parallel()

	bad := grant.Config{} // no Storage, no AccessTokens

	assert.Panics(t, func() { grant.NewAuthorizationCode(bad) })
	assert.Panics(t, func() { grant.NewClientCredentials(bad) })
	assert.Panics(t, func() { grant.NewRefreshToken(bad) })
}

// --- authorization_code edge cases --------------------------------------

func TestAuthorizationCodeMissingCode(t *testing.T) {
	t.Parallel()

	g, req := newAuthCodeReq(context.Background(), newStore(), true)
	req.Form.Del("code")

	_, err := g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err))
}

func TestAuthorizationCodeExpired(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, true)
	req.Now = time.Date(2026, 5, 20, 13, 0, 0, 0, time.UTC) // past the code's 12:10 expiry

	_, err := g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestAuthorizationCodeClientMismatch(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, true)
	req.Client = &oauth2.DefaultClient{IDValue: "another-client", TypeValue: oauth2.ClientConfidential}

	_, err := g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestAuthorizationCodeGrantTypeNotAllowed(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, true)
	req.Client = &oauth2.DefaultClient{
		IDValue:           clientID,
		TypeValue:         oauth2.ClientConfidential,
		RedirectURIValues: []string{redirectURI},
		GrantTypeValues:   []string{"client_credentials"}, // not authorization_code
	}

	_, err := g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeUnauthorizedClient, oauth2.IsCode(err))
}

func TestAuthorizationCodeMissingVerifier(t *testing.T) {
	t.Parallel()

	store := newStore()
	g, req := newAuthCodeReq(context.Background(), store, true)
	req.Form.Del("code_verifier") // the code carries a challenge but no verifier is sent

	_, err := g.Handle(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

// plainPKCECode seeds a code whose challenge method is empty (the grant
// defaults to "plain", where the verifier equals the challenge verbatim)
// and returns the matching /token form.
func plainPKCECode(t *testing.T, store oauth2.Storage) url.Values {
	t.Helper()

	raw := "raw-plain-code"
	require.NoError(t, store.SaveAuthorizationCode(context.Background(), &oauth2.AuthorizationCode{
		Code: raw, CodeHash: oauth2.HashToken(nil, raw),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, Scope: "read:mail",
		CodeChallenge: "shared-plain-secret", CodeChallengeMethod: "",
		IssuedAt:  time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 5, 20, 12, 10, 0, 0, time.UTC),
	}))

	form := url.Values{}
	form.Set("code", raw)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", "shared-plain-secret")

	return form
}

func TestAuthorizationCodePlainPKCEAcceptedUnderProfile20(t *testing.T) {
	t.Parallel()

	store := newStore()
	form := plainPKCECode(t, store)

	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: form, Profile: oauth2.Profile20,
		Now: time.Date(2026, 5, 20, 12, 5, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Pair.Access.Token)
}

func TestAuthorizationCodePlainPKCERefusedUnderBCP(t *testing.T) {
	t.Parallel()

	store := newStore()
	form := plainPKCECode(t, store)

	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	// Profile20BCP (and 21Draft) mandate S256 — "plain" must be refused.
	_, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: form, Profile: oauth2.Profile20BCP,
		Now: time.Date(2026, 5, 20, 12, 5, 0, 0, time.UTC),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestAuthorizationCodeProfileRequiresPKCE(t *testing.T) {
	t.Parallel()

	store := newStore()
	ctx := context.Background()

	// A code minted with no PKCE challenge at all.
	raw := "raw-no-pkce-code"
	require.NoError(t, store.SaveAuthorizationCode(ctx, &oauth2.AuthorizationCode{
		Code: raw, CodeHash: oauth2.HashToken(nil, raw),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, Scope: "read:mail",
		IssuedAt:  time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 5, 20, 12, 10, 0, 0, time.UTC),
	}))

	// The grant itself does not force PKCE (RequirePKCE false), but the
	// BCP profile does — the request must still be refused.
	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	form := url.Values{}
	form.Set("code", raw)
	form.Set("redirect_uri", redirectURI)

	_, err := g.Handle(ctx, grant.Request{
		Client: newClient(), Form: form, Profile: oauth2.Profile20BCP,
		Now: time.Date(2026, 5, 20, 12, 5, 0, 0, time.UTC),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestAuthorizationCodeWithoutRefreshGenerator(t *testing.T) {
	t.Parallel()

	store := newStore()
	ctx := context.Background()
	_, req := newAuthCodeReq(ctx, store, true)

	// A config with no RefreshTokens generator issues an access token only.
	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	resp, err := g.Handle(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Pair.Access.Token)
	assert.Nil(t, resp.Pair.Refresh, "no refresh token without a RefreshTokens generator")
}

// --- client_credentials edge cases --------------------------------------

func TestClientCredentialsGrantTypeNotAllowed(t *testing.T) {
	t.Parallel()

	g := grant.NewClientCredentials(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	client := &oauth2.DefaultClient{
		IDValue:         clientID,
		TypeValue:       oauth2.ClientConfidential,
		GrantTypeValues: []string{"refresh_token"}, // not client_credentials
	}

	_, err := g.Handle(context.Background(), grant.Request{Client: client, Form: url.Values{}, Now: time.Now()})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeUnauthorizedClient, oauth2.IsCode(err))
}

func TestClientCredentialsNoScopeRestriction(t *testing.T) {
	t.Parallel()

	g := grant.NewClientCredentials(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	// A client with no Scopes() list accepts any requested scope verbatim.
	client := &oauth2.DefaultClient{IDValue: clientID, TypeValue: oauth2.ClientConfidential}
	form := url.Values{}
	form.Set("scope", "anything:goes")

	resp, err := g.Handle(context.Background(), grant.Request{Client: client, Form: form, Now: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, "anything:goes", resp.Scope)
}

func TestClientCredentialsDefaultsToFirstScope(t *testing.T) {
	t.Parallel()

	g := grant.NewClientCredentials(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	// No scope requested + a restricted client -> the first allowed scope.
	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: url.Values{}, Now: time.Now(),
	})
	require.NoError(t, err)
	assert.Equal(t, "read:mail", resp.Scope)
}

// --- refresh_token edge cases -------------------------------------------

// seedRefresh stores a refresh token and returns its raw value.
func seedRefresh(t *testing.T, store interface {
	SaveRefreshToken(context.Context, *oauth2.RefreshToken) error
}, raw, scope string, expiresAt time.Time) {
	t.Helper()

	require.NoError(t, store.SaveRefreshToken(context.Background(), &oauth2.RefreshToken{
		Token: raw, TokenHash: oauth2.HashToken(nil, raw),
		ClientID: clientID, Subject: subject, Scope: scope,
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: expiresAt, FamilyID: "fam-x",
	}))
}

func TestRefreshTokenMissing(t *testing.T) {
	t.Parallel()

	g := grant.NewRefreshToken(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	_, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: url.Values{}, Now: time.Now(),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err))
}

func TestRefreshTokenUnknown(t *testing.T) {
	t.Parallel()

	g := grant.NewRefreshToken(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	form := url.Values{}
	form.Set("refresh_token", "never-issued")

	_, err := g.Handle(context.Background(), grant.Request{Client: newClient(), Form: form, Now: time.Now()})
	require.Error(t, err)
}

func TestRefreshTokenExpired(t *testing.T) {
	t.Parallel()

	store := newStore()
	seedRefresh(t, store, "expired-rt", "read:mail", time.Now().Add(-time.Minute))

	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	form := url.Values{}
	form.Set("refresh_token", "expired-rt")

	_, err := g.Handle(context.Background(), grant.Request{Client: newClient(), Form: form, Now: time.Now()})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestRefreshTokenClientMismatch(t *testing.T) {
	t.Parallel()

	store := newStore()
	seedRefresh(t, store, "other-client-rt", "read:mail", time.Now().Add(time.Hour))

	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	form := url.Values{}
	form.Set("refresh_token", "other-client-rt")

	_, err := g.Handle(context.Background(), grant.Request{
		Client: &oauth2.DefaultClient{IDValue: "intruder", TypeValue: oauth2.ClientConfidential},
		Form:   form, Now: time.Now(),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
}

func TestRefreshTokenNarrowsScope(t *testing.T) {
	t.Parallel()

	store := newStore()
	seedRefresh(t, store, "narrow-rt", "read:mail write:mail", time.Now().Add(time.Hour))

	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, RotateRefreshTokens: true,
	})

	form := url.Values{}
	form.Set("refresh_token", "narrow-rt")
	form.Set("scope", "read:mail") // a subset of the original grant

	resp, err := g.Handle(context.Background(), grant.Request{Client: newClient(), Form: form, Now: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, "read:mail", resp.Scope)
}

func TestRefreshTokenRefusesBroadenedScope(t *testing.T) {
	t.Parallel()

	store := newStore()
	seedRefresh(t, store, "broaden-rt", "read:mail", time.Now().Add(time.Hour))

	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	form := url.Values{}
	form.Set("refresh_token", "broaden-rt")
	form.Set("scope", "read:mail admin") // admin was not in the original grant

	_, err := g.Handle(context.Background(), grant.Request{Client: newClient(), Form: form, Now: time.Now()})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
}

func TestRefreshTokenWithoutRotation(t *testing.T) {
	t.Parallel()

	store := newStore()
	seedRefresh(t, store, "static-rt", "read:mail", time.Now().Add(time.Hour))

	// RotateRefreshTokens defaults to false here: the grant issues a new
	// access token but no replacement refresh token.
	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, RotateRefreshTokens: false,
	})

	form := url.Values{}
	form.Set("refresh_token", "static-rt")

	resp, err := g.Handle(context.Background(), grant.Request{Client: newClient(), Form: form, Now: time.Now()})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Pair.Access.Token)
	assert.Nil(t, resp.Pair.Refresh, "no rotation -> no new refresh token")
}
