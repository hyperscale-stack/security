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
	"github.com/hyperscale-stack/security/oauth2/token"
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
	req.Client = &oauth2.DefaultClient{GrantTypeValues: allGrantTypes, IDValue: "another-client", TypeValue: oauth2.ClientConfidential}

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
	// The presence check answers before the RFC 7636 syntax check.
	assert.ErrorContains(t, err, "missing code_verifier")
}

// plainVerifier is a well-formed RFC 7636 §4.1 verifier (52 characters,
// including ".", "~" and "_") used as a plain PKCE pair.
const plainVerifier = "shared-plain-secret.with~unreserved_chars-0123456789"

// plainPKCECode seeds a code whose challenge method is empty (the grant
// defaults to "plain", where the verifier equals the challenge verbatim)
// bound to verifier, and returns the matching /token form.
func plainPKCECode(t *testing.T, store oauth2.Storage, verifier string) url.Values {
	t.Helper()

	raw := "raw-plain-code"
	require.NoError(t, store.SaveAuthorizationCode(context.Background(), &oauth2.AuthorizationCode{
		Code: raw, CodeHash: oauth2.HashToken(nil, raw),
		ClientID: clientID, Subject: subject, RedirectURI: redirectURI, Scope: "read:mail",
		CodeChallenge: verifier, CodeChallengeMethod: "",
		IssuedAt:  time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 5, 20, 12, 10, 0, 0, time.UTC),
		Issuer:    "https://auth.example",
	}))

	form := url.Values{}
	form.Set("code", raw)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	return form
}

func TestAuthorizationCodePlainPKCEAcceptedUnderProfile20(t *testing.T) {
	t.Parallel()

	store := newStore()
	form := plainPKCECode(t, store, plainVerifier)

	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: form, Profile: oauth2.Profile20, Issuer: "https://auth.example",
		Now: time.Date(2026, 5, 20, 12, 5, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Pair.Access.Token)
}

func TestAuthorizationCodePlainPKCERefusedUnderBCP(t *testing.T) {
	t.Parallel()

	store := newStore()
	// A malformed (too short) plain pair: the profile ban must answer
	// before the RFC 7636 syntax check.
	form := plainPKCECode(t, store, "shared-plain-secret")

	g := grant.NewAuthorizationCode(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	// Profile20BCP (and 21Draft) mandate S256 — "plain" must be refused.
	_, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: form, Profile: oauth2.Profile20BCP, Issuer: "https://auth.example",
		Now: time.Date(2026, 5, 20, 12, 5, 0, 0, time.UTC),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	// RFC 6749 §5.2: the description carries no double quote.
	var oe *oauth2.Error
	require.ErrorAs(t, err, &oe)
	assert.Equal(t, "PKCE method plain is refused by the active profile", oe.Description)
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
		Issuer:    "https://auth.example",
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
		Client: newClient(), Form: form, Profile: oauth2.Profile20BCP, Issuer: "https://auth.example",
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

// TestClientCredentialsEmptyScopeListAllowsNoScope: a client declaring no
// scope may request none — any requested scope is invalid_scope, with
// ErrNoScopesDeclared as cause — and gets the empty scope without one.
func TestClientCredentialsEmptyScopeListAllowsNoScope(t *testing.T) {
	t.Parallel()

	g := grant.NewClientCredentials(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	client := &oauth2.DefaultClient{
		IDValue: clientID, TypeValue: oauth2.ClientConfidential,
		GrantTypeValues: []string{oauth2.GrantTypeClientCredentials},
	}

	_, err := g.Handle(context.Background(), grant.Request{
		Client: client, Form: url.Values{"scope": {"anything:goes"}}, Now: time.Now(),
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
	assert.ErrorIs(t, err, oauth2.ErrNoScopesDeclared)

	resp, err := g.Handle(context.Background(), grant.Request{Client: client, Form: url.Values{}, Now: time.Now()})
	require.NoError(t, err)
	assert.Empty(t, resp.Scope)
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

// seedRefresh stores a refresh token raw in family "fam-x", alongside an
// access token of its family.
func seedRefresh(t *testing.T, store oauth2.Storage, raw, scope string, expiresAt time.Time) {
	t.Helper()

	seedPair(t, store, raw, "fam-x", scope, expiresAt)
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
		Client: &oauth2.DefaultClient{GrantTypeValues: allGrantTypes, IDValue: "intruder", TypeValue: oauth2.ClientConfidential},
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

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: form, Now: time.Now(), Issuer: "https://auth.example",
	})
	require.NoError(t, err)
	assert.Equal(t, "read:mail", resp.Scope)
	assert.Equal(t, "read:mail", resp.Pair.Access.Scope)

	// RFC 6749 §6: narrowing only affects the access token; the rotated
	// refresh token keeps the scope of the one it replaces.
	require.NotNil(t, resp.Pair.Refresh)
	assert.Equal(t, "read:mail write:mail", resp.Pair.Refresh.Scope)

	stored, err := store.LookupRefreshToken(context.Background(), resp.Pair.Refresh.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, "read:mail write:mail", stored.Scope)

	// So the next exchange without a scope gets the whole original grant back.
	next, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: url.Values{"refresh_token": {resp.Pair.Refresh.Token}}, Now: time.Now(),
		Issuer: "https://auth.example",
	})
	require.NoError(t, err)
	assert.Equal(t, "read:mail write:mail", next.Scope)
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

	_, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: form, Now: time.Now(), Issuer: "https://auth.example",
	})
	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
}

func TestRefreshTokenWithoutRotationUnderProfile20(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		gen  token.RefreshTokenGenerator
	}{
		{"with a refresh generator", newRefreshGen()},
		{"without a refresh generator", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newStore()
			seedRefresh(t, store, "static-rt", "read:mail", time.Now().Add(time.Hour))

			// Rotation is opt-in under Profile20 only: with RotateRefreshTokens
			// false the grant issues a new access token but no replacement
			// refresh token, and the presented one stays usable.
			g := grant.NewRefreshToken(grant.Config{
				Storage: store, AccessTokens: newAccessGen(), RefreshTokens: tc.gen,
				AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, RotateRefreshTokens: false,
			})

			form := url.Values{}
			form.Set("refresh_token", "static-rt")

			req := grant.Request{
				Client: newClient(), Form: form, Now: time.Now(), Profile: oauth2.Profile20,
				Issuer: "https://auth.example",
			}

			for range 2 {
				resp, err := g.Handle(context.Background(), req)
				require.NoError(t, err)
				assert.NotEmpty(t, resp.Pair.Access.Token)
				assert.Nil(t, resp.Pair.Refresh, "no rotation -> no new refresh token")
			}

			rt, err := store.LookupRefreshToken(context.Background(), oauth2.HashToken(nil, "static-rt"))
			require.NoError(t, err)
			assert.False(t, rt.Consumed, "a non-rotating refresh never consumes the token")
		})
	}
}
