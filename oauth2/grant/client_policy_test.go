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
	"github.com/hyperscale-stack/security/oauth2/internal/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientCredentialsRefusesNonConfidentialClients pins RFC 6749 §4.4 in
// the grant itself, for a direct call or a decorated grant: a public or an
// untyped client gets unauthorized_client, nothing is persisted.
func TestClientCredentialsRefusesNonConfidentialClients(t *testing.T) {
	t.Parallel()

	for name, typ := range map[string]oauth2.ClientType{"public": oauth2.ClientPublic, "untyped": ""} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: newStore()}
			g := grant.NewClientCredentials(grant.Config{Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour})

			client := &oauth2.DefaultClient{
				IDValue: clientID, TypeValue: typ,
				GrantTypeValues: []string{oauth2.GrantTypeClientCredentials}, ScopeValues: []string{"read:mail"},
			}

			resp, err := g.Handle(context.Background(), grant.Request{Client: client, Form: url.Values{}, Now: time.Now()})
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeUnauthorizedClient, oauth2.IsCode(err))
			assert.Empty(t, store.savedPairs())
		})
	}
}

// noGrantClient is a confidential client declaring no grant type.
func noGrantClient() oauth2.Client {
	return &oauth2.DefaultClient{
		IDValue: clientID, Secret: clientSecret, TypeValue: oauth2.ClientConfidential,
		RedirectURIValues: []string{redirectURI}, ScopeValues: []string{"read:mail", "write:mail", "admin"},
	}
}

// TestEveryGrantRefusesAClientDeclaringNoGrant: each shipped grant checks
// the client's declaration itself too — for a direct call or a decorated
// grant — and refuses a client declaring no grant type with
// unauthorized_client, ErrNoGrantTypesDeclared as cause, nothing issued.
func TestEveryGrantRefusesAClientDeclaringNoGrant(t *testing.T) {
	t.Parallel()

	cfg := func(store oauth2.Storage) grant.Config {
		return grant.Config{
			Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
			AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
		}
	}

	cases := map[string]func(*replayStore) (oauth2.Grant, url.Values){
		oauth2.GrantTypeAuthorizationCode: func(store *replayStore) (oauth2.Grant, url.Values) {
			_, req := newAuthCodeReq(context.Background(), store.Store, true)

			return grant.NewAuthorizationCode(cfg(store)), req.Form
		},
		oauth2.GrantTypeRefreshToken: func(store *replayStore) (oauth2.Grant, url.Values) {
			seedPair(t, store.Store, "declared-nothing-rt", "fam-dn", "read:mail", time.Now().Add(time.Hour))

			return grant.NewRefreshToken(cfg(store)), url.Values{"refresh_token": {"declared-nothing-rt"}}
		},
		oauth2.GrantTypeClientCredentials: func(store *replayStore) (oauth2.Grant, url.Values) {
			return grant.NewClientCredentials(cfg(store)), url.Values{}
		},
		oauth2.GrantTypePassword: func(store *replayStore) (oauth2.Grant, url.Values) {
			return grant.NewLegacyPassword(cfg(store), fakeROVerifier{subject: subject}), passwordForm("alice", "pw", "")
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: newStore()}
			g, form := build(store)

			resp, err := g.Handle(context.Background(), grant.Request{
				Client: noGrantClient(), Form: form, Now: time.Date(2026, 5, 20, 12, 5, 0, 0, time.UTC),
				Issuer: "https://auth.example",
			})
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeUnauthorizedClient, oauth2.IsCode(err))
			assert.True(t, errors.Is(err, oauth2.ErrNoGrantTypesDeclared), "the cause: %v", err)
			assert.Empty(t, store.savedPairs())
		})
	}
}

// TestPasswordGrantIssuesNoRefreshTokenWithoutTheRefreshGrant pins RFC 9700
// §4.14.2 on the legacy password grant: a refresh token only for a client
// declaring refresh_token.
func TestPasswordGrantIssuesNoRefreshTokenWithoutTheRefreshGrant(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		grants  []string
		refresh bool
	}{
		"password only":           {[]string{oauth2.GrantTypePassword}, false},
		"password, refresh_token": {[]string{oauth2.GrantTypePassword, oauth2.GrantTypeRefreshToken}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			g := grant.NewLegacyPassword(grant.Config{
				Storage: newStore(), AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
				AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
			}, fakeROVerifier{subject: subject})

			client := &oauth2.DefaultClient{
				IDValue: clientID, TypeValue: oauth2.ClientConfidential, GrantTypeValues: tc.grants,
				ScopeValues: []string{"read:mail"},
			}

			resp, err := g.Handle(context.Background(), grant.Request{
				Client: client, Form: passwordForm("alice", "pw", ""), Now: time.Now(),
			})
			require.NoError(t, err)
			assert.Equal(t, tc.refresh, resp.Pair.Refresh != nil)
		})
	}
}

// TestRefreshTokenRechecksTheScopeRegistration: the refresh_token grant
// refuses, before anything is minted or consumed, an access-token scope the
// client no longer declares; an empty stored scope needs no declaration.
func TestRefreshTokenRechecksTheScopeRegistration(t *testing.T) {
	t.Parallel()

	g := func(store oauth2.Storage) *grant.RefreshToken {
		return grant.NewRefreshToken(grant.Config{
			Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
			AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
		})
	}
	client := func(scopes ...string) oauth2.Client {
		return &oauth2.DefaultClient{
			IDValue: clientID, TypeValue: oauth2.ClientConfidential,
			GrantTypeValues: []string{oauth2.GrantTypeRefreshToken}, ScopeValues: scopes,
		}
	}

	store := newStore()
	seedRefresh(t, store, "shrunk-rt", "read:mail write:mail", time.Now().Add(time.Hour))

	resp, err := g(store).Handle(context.Background(), grant.Request{
		Client: client("read:mail"), Form: url.Values{"refresh_token": {"shrunk-rt"}},
		Now: time.Now(), Issuer: "https://auth.example",
	})
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
	assert.False(t, errors.Is(err, oauth2.ErrNoScopesDeclared))

	stored, err := store.LookupRefreshToken(context.Background(), oauth2.HashToken(nil, "shrunk-rt"))
	require.NoError(t, err)
	assert.False(t, stored.Consumed, "nothing consumed")

	store = newStore()
	seedRefresh(t, store, "unscoped-rt", "", time.Now().Add(time.Hour))

	resp, err = g(store).Handle(context.Background(), grant.Request{
		Client: client(), Form: url.Values{"refresh_token": {"unscoped-rt"}},
		Now: time.Now(), Issuer: "https://auth.example",
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Scope)
}

// TestAuthorizationCodeRequiresPKCEFromPublicClients pins RFC 9700 §2.1.1 at
// the token endpoint too, under Profile20: a code issued without
// code_challenge — before the authorization endpoint required it, or by
// another authorization path — is refused to a public or untyped client
// with invalid_grant ("PKCE required"), nothing issued; a confidential
// client may still redeem it.
func TestAuthorizationCodeRequiresPKCEFromPublicClients(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		typ    oauth2.ClientType
		issued bool
	}{
		"public":       {oauth2.ClientPublic, false},
		"untyped":      {"", false},
		"confidential": {oauth2.ClientConfidential, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: newStore()}
			req := seedPKCECode(t, store, "", "", "", oauth2.Profile20)
			req.Form.Del("code_verifier")
			req.Client = &oauth2.DefaultClient{
				IDValue: clientID, TypeValue: tc.typ, RedirectURIValues: []string{redirectURI},
				GrantTypeValues: allGrantTypes, ScopeValues: []string{"read:mail"},
			}

			resp, err := newPKCEGrant(store).Handle(context.Background(), req)
			if tc.issued {
				require.NoError(t, err)
				assert.NotEmpty(t, resp.Pair.Access.Token)

				return
			}

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
			assert.ErrorContains(t, err, "PKCE required")
			assert.Empty(t, store.savedPairs())
		})
	}
}

// TestRefreshRotatesForNonConfidentialClientsUnderEveryProfile pins RFC 9700
// §4.14.2 ("Authorization servers MUST utilize one of these methods to
// detect refresh token replay by malicious actors for public clients":
// sender-constrained refresh tokens or rotation) under Profile20 without
// RotateRefreshTokens: the refresh token of a public — or untyped — client
// rotates, its reuse is detected; a confidential client keeps the legacy
// non-rotating refresh.
func TestRefreshRotatesForNonConfidentialClientsUnderEveryProfile(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		typ     oauth2.ClientType
		rotates bool
	}{
		"public":       {oauth2.ClientPublic, true},
		"untyped":      {"", true},
		"confidential": {oauth2.ClientConfidential, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			store := newStore()
			seedRefresh(t, store, "legacy-profile-rt", "read:mail", time.Now().Add(time.Hour))

			g := grant.NewRefreshToken(grant.Config{
				Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
				AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
			})

			req := refreshReq("legacy-profile-rt", oauth2.Profile20)
			req.Client = &oauth2.DefaultClient{
				IDValue: clientID, TypeValue: tc.typ, GrantTypeValues: allGrantTypes, ScopeValues: []string{"read:mail"},
			}

			resp, err := g.Handle(ctx, req)
			require.NoError(t, err)
			assert.Equal(t, tc.rotates, resp.Pair.Refresh != nil, "a replacement refresh token")

			presented, err := store.LookupRefreshToken(ctx, oauth2.HashToken(nil, "legacy-profile-rt"))
			require.NoError(t, err)
			assert.Equal(t, tc.rotates, presented.Consumed, "the presented token is consumed when rotating")

			_, err = g.Handle(ctx, req)
			if tc.rotates {
				require.ErrorIs(t, err, oauth2.ErrRefreshTokenReused, "reuse is detected")

				return
			}

			require.NoError(t, err, "the legacy refresh token stays reusable")
		})
	}
}

// TestNonConfidentialRefreshWithoutAGeneratorFailsClosed: a refresh_token
// grant without a RefreshTokens generator cannot rotate; under Profile20
// NewServer cannot know it will serve public clients, so their refresh
// fails with server_error (ErrRotationRequiresGenerator) before anything is
// minted, while a confidential client's legacy refresh still works.
func TestNonConfidentialRefreshWithoutAGeneratorFailsClosed(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		typ oauth2.ClientType
		ok  bool
	}{
		"public":       {oauth2.ClientPublic, false},
		"confidential": {oauth2.ClientConfidential, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := newStore()
			seedRefresh(t, store, "no-generator-rt", "read:mail", time.Now().Add(time.Hour))

			spy := &spyAccessGen{}
			g := grant.NewRefreshToken(grant.Config{
				Storage: store, AccessTokens: spy, AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
			})
			require.NoError(t, g.ValidateProfile(oauth2.Profile20), "NewServer accepts the wiring")

			req := refreshReq("no-generator-rt", oauth2.Profile20)
			req.Client = &oauth2.DefaultClient{
				IDValue: clientID, TypeValue: tc.typ, GrantTypeValues: allGrantTypes, ScopeValues: []string{"read:mail"},
			}

			resp, err := g.Handle(t.Context(), req)
			if tc.ok {
				require.NoError(t, err)
				assert.Nil(t, resp.Pair.Refresh)

				return
			}

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(err))
			assert.ErrorIs(t, err, grant.ErrRotationRequiresGenerator)
			assert.Zero(t, spy.calls, "nothing minted")
		})
	}
}

// TestRefreshTokenRefusalsCarryTheirCause: a refresh refused because the
// client declares no scope at all carries ErrNoScopesDeclared; a malformed
// narrowing scope carries the scopes sentinel. Neither consumes anything.
func TestRefreshTokenRefusalsCarryTheirCause(t *testing.T) {
	t.Parallel()

	store := newStore()
	seedRefresh(t, store, "cause-rt", "read:mail", time.Now().Add(time.Hour))

	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour,
	})

	undeclared := &oauth2.DefaultClient{
		IDValue: clientID, TypeValue: oauth2.ClientConfidential, GrantTypeValues: []string{oauth2.GrantTypeRefreshToken},
	}

	_, err := g.Handle(context.Background(), grant.Request{
		Client: undeclared, Form: url.Values{"refresh_token": {"cause-rt"}}, Now: time.Now(), Issuer: "https://auth.example",
	})
	assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
	assert.ErrorIs(t, err, oauth2.ErrNoScopesDeclared)

	_, err = g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: url.Values{"refresh_token": {"cause-rt"}, "scope": {"read:mail\tadmin"}},
		Now: time.Now(), Issuer: "https://auth.example",
	})
	assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
	assert.ErrorIs(t, err, scopes.ErrMalformed)

	stored, err := store.LookupRefreshToken(context.Background(), oauth2.HashToken(nil, "cause-rt"))
	require.NoError(t, err)
	assert.False(t, stored.Consumed, "nothing consumed")
}
