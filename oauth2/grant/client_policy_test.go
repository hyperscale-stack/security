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
