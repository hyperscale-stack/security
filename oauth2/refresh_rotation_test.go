// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spyAccessGen is a [token.AccessTokenGenerator] counting its calls, so a
// test can prove that no access token was minted.
type spyAccessGen struct{ calls int }

func (s *spyAccessGen) Generate(context.Context, token.AccessTokenClaims) (string, string, error) {
	s.calls++

	const raw = "spy-access-token"

	return raw, oauth2.HashToken(nil, raw), nil
}

// hiddenGrant wraps a grant the way a metrics or logging decorator would:
// it forwards Type and Handle but none of the optional capabilities the
// wrapped grant implements.
type hiddenGrant struct{ oauth2.Grant }

// seedServerRefresh stores a live refresh token issued to the test client.
func seedServerRefresh(t *testing.T, store oauth2.Storage, raw string) {
	t.Helper()

	require.NoError(t, store.SaveRefreshToken(t.Context(), &oauth2.RefreshToken{
		Token:     raw,
		TokenHash: oauth2.HashToken(nil, raw),
		ClientID:  testClientID,
		Subject:   "alice",
		Scope:     "api:read",
		FamilyID:  "family-rot",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}))
}

// refreshServerConfig is hookServerConfig serving the single grant g under
// profile p.
func refreshServerConfig(p oauth2.Profile, store oauth2.Storage, g oauth2.Grant) oauth2.ServerConfig {
	cfg := hookServerConfig(store)
	cfg.Profile = p
	cfg.Grants = []oauth2.Grant{g}

	return cfg
}

// refreshExchange POSTs a refresh_token grant for raw to /token.
func refreshExchange(t *testing.T, srv *oauth2.Server, raw string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, formRequest("/token",
		url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}}, true))

	return rec
}

// nonRotatingConfig is a refresh-grant configuration with a refresh-token
// generator but RotateRefreshTokens left false.
func nonRotatingConfig(store oauth2.Storage) grant.Config {
	return grant.Config{
		Storage:       store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
	}
}

func TestTokenEndpointRefreshRotationMandatedByProfile(t *testing.T) {
	t.Parallel()

	for _, p := range []oauth2.Profile{oauth2.Profile20BCP, oauth2.Profile21Draft} {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()

			store := memory.New()
			seedServerRefresh(t, store, "server-rt")

			srv, err := oauth2.NewServer(refreshServerConfig(p, store,
				grant.NewRefreshToken(nonRotatingConfig(store))))
			require.NoError(t, err)

			rec := refreshExchange(t, srv, "server-rt")
			require.Equal(t, http.StatusOK, rec.Code)

			var first struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
			}

			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &first))
			require.NotEmpty(t, first.RefreshToken, "the profile mandates a replacement refresh token")
			assert.NotEqual(t, "server-rt", first.RefreshToken)

			// Replaying the presented token is reuse: refused, family revoked.
			rec = refreshExchange(t, srv, "server-rt")
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, oauth2.CodeInvalidGrant, decodeError(t, rec))

			// The revocation took the replacement and its access token along.
			rec = refreshExchange(t, srv, first.RefreshToken)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, oauth2.CodeInvalidGrant, decodeError(t, rec))

			_, err = store.LookupAccessToken(t.Context(), oauth2.HashToken(nil, first.AccessToken))
			assert.Error(t, err, "the family revocation removes the access token of the rotation")
		})
	}
}

func TestTokenEndpointRefreshWithoutRotationUnderProfile20(t *testing.T) {
	t.Parallel()

	store := memory.New()
	seedServerRefresh(t, store, "legacy-rt")

	srv, err := oauth2.NewServer(refreshServerConfig(oauth2.Profile20, store,
		grant.NewRefreshToken(nonRotatingConfig(store))))
	require.NoError(t, err)

	// Rotation is opt-in under Profile20: the same token keeps working and
	// no replacement is ever returned.
	for range 2 {
		rec := refreshExchange(t, srv, "legacy-rt")
		require.Equal(t, http.StatusOK, rec.Code)

		var body map[string]any

		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.NotEmpty(t, body["access_token"])
		assert.NotContains(t, body, "refresh_token")
	}
}

func TestTokenEndpointRefreshFailsClosedWhenRotationUnavailable(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	store := memory.New()
	seedServerRefresh(t, store, "stranded-rt")

	// No RefreshTokens generator under BCP, behind a decorator that hides
	// the grant from any NewServer-time check: only the grant's runtime
	// guard stands between the request and an access token.
	spy := &spyAccessGen{}
	cfg := refreshServerConfig(oauth2.Profile20BCP, store, hiddenGrant{grant.NewRefreshToken(grant.Config{
		Storage: store, AccessTokens: spy, AccessTTL: time.Hour,
	})})
	cfg.OnError = sink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	rec := refreshExchange(t, srv, "stranded-rt")

	// The wire only carries the generic server_error envelope...
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.JSONEq(t, `{"error":"server_error","error_description":"internal server error"}`, rec.Body.String())

	// ...the cause reaches the hook only...
	got := sink.collected()
	require.Len(t, got, 1)
	assert.ErrorIs(t, got[0], grant.ErrRotationRequiresGenerator)

	// ...and nothing was minted or consumed.
	assert.Zero(t, spy.calls, "no access token is minted when the rotation cannot be honored")

	presented, err := store.LookupRefreshToken(t.Context(), oauth2.HashToken(nil, "stranded-rt"))
	require.NoError(t, err)
	assert.False(t, presented.Consumed, "the presented token is left untouched")
}
