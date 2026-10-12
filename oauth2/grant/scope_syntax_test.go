// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grant_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/internal/scopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPasswordGrantScopeSyntax pins RFC 6749 §3.3 on the legacy password
// grant: a malformed or oversized scope is invalid_scope (§5.2), nothing is
// issued, and an accepted one is issued canonical.
func TestPasswordGrantScopeSyntax(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		scope string
		cause error
	}{
		{"tab separator", "read:mail\twrite:mail", scopes.ErrMalformed},
		{"non-ASCII", "read:mail é", scopes.ErrMalformed},
		{"101 tokens", strings.TrimSpace(strings.Repeat("read:mail ", 101)), scopes.ErrTooLarge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &replayStore{Store: newStore()}
			g := grant.NewLegacyPassword(grant.Config{
				Storage: store, AccessTokens: newAccessGen(), AccessTTL: time.Hour,
			}, fakeROVerifier{subject: subject})

			resp, err := g.Handle(context.Background(), grant.Request{
				Client: newClient(), Form: passwordForm("alice", "pw", tc.scope), Now: time.Now(),
			})
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, oauth2.CodeInvalidScope, oauth2.IsCode(err))
			assert.True(t, errors.Is(err, tc.cause), "the cause: %v", err)
			assert.Empty(t, store.savedPairs())
		})
	}

	g := grant.NewLegacyPassword(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	}, fakeROVerifier{subject: subject})

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: passwordForm("alice", "pw", "write:mail  read:mail write:mail"), Now: time.Now(),
	})
	require.NoError(t, err)
	assert.Equal(t, "write:mail read:mail", resp.Scope)
}

// TestClientCredentialsScopeIsCanonical: the scope a client_credentials
// token carries is canonical — single-SP joined, duplicates dropped.
func TestClientCredentialsScopeIsCanonical(t *testing.T) {
	t.Parallel()

	g := grant.NewClientCredentials(grant.Config{
		Storage: newStore(), AccessTokens: newAccessGen(), AccessTTL: time.Hour,
	})

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: url.Values{"scope": {"write:mail  read:mail write:mail"}}, Now: time.Now(),
	})
	require.NoError(t, err)
	assert.Equal(t, "write:mail read:mail", resp.Scope)
}

// TestRefreshKeepsALegacyStoredScope: a refresh token stored before scopes
// were canonical — here with a tab — is never refused for its own scope:
// the server-held value is split leniently, while what the client sends is
// parsed strictly.
func TestRefreshKeepsALegacyStoredScope(t *testing.T) {
	t.Parallel()

	store := newStore()
	seedRefresh(t, store, "legacy-rt", "read:mail\twrite:mail", time.Now().Add(time.Hour))

	g := grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: newAccessGen(), RefreshTokens: newRefreshGen(),
		AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, RotateRefreshTokens: true,
	})

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: newClient(), Form: url.Values{"refresh_token": {"legacy-rt"}, "scope": {"write:mail"}},
		Now: time.Now(), Issuer: "https://auth.example",
	})
	require.NoError(t, err)
	assert.Equal(t, "write:mail", resp.Scope)
	assert.Equal(t, "read:mail\twrite:mail", resp.Pair.Refresh.Scope, "RFC 6749 §6: the refresh token keeps its scope")
}
