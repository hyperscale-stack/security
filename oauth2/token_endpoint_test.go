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
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAccessTTL is the access-token lifetime the clocked servers below are
// configured with; expires_in must advertise exactly this.
const testAccessTTL = time.Hour

// fixedExpiryGrant mints a token whose expiry the test picks, so the
// expires_in edge cases can be driven without waiting for a clock.
type fixedExpiryGrant struct{ expiresAt time.Time }

func (fixedExpiryGrant) Type() string { return "client_credentials" }

func (g fixedExpiryGrant) Handle(_ context.Context, req oauth2.GrantRequest) (*oauth2.GrantResponse, error) {
	return &oauth2.GrantResponse{
		Pair: oauth2.TokenPair{Access: oauth2.AccessToken{
			Token:     "opaque-access-token",
			TokenHash: oauth2.HashToken(nil, "opaque-access-token"),
			ClientID:  req.Client.ID(),
			IssuedAt:  req.Now,
			ExpiresAt: g.expiresAt,
		}},
		TokenType: oauth2.TokenTypeBearer,
	}, nil
}

// newClockedServer builds a /token-capable server pinned to a fixed clock.
// A nil now keeps the default wall clock; a nil grant keeps the real
// client_credentials handler.
func newClockedServer(t *testing.T, now func() time.Time, g oauth2.Grant) *oauth2.Server {
	t.Helper()

	store := memory.New()
	clients := &staticClientStore{clients: map[string]oauth2.Client{
		testClientID: &oauth2.DefaultClient{
			IDValue:   testClientID,
			Secret:    testClientSecret,
			TypeValue: oauth2.ClientConfidential,
		},
	}}

	if g == nil {
		g = grant.NewClientCredentials(grant.Config{
			Storage:      store,
			AccessTokens: token.NewOpaque(32),
			AccessTTL:    testAccessTTL,
		})
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        oauth2.Profile20BCP,
		Storage:        store,
		ClientStore:    clients,
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{g},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		Now:            now,
	})
	require.NoError(t, err)

	return srv
}

// issueToken runs a client_credentials exchange and returns the decoded
// JSON body.
func issueToken(t *testing.T, srv *oauth2.Server) map[string]any {
	t.Helper()

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, formRequest("/token",
		url.Values{"grant_type": {"client_credentials"}}, true))
	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	return body
}

func TestTokenExpiresInHonorsServerClock(t *testing.T) {
	t.Parallel()

	// A clock pinned well in the past: measuring against the wall clock
	// would advertise a large negative lifetime.
	pinned := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	body := issueToken(t, newClockedServer(t, func() time.Time { return pinned }, nil))

	assert.InDelta(t, testAccessTTL.Seconds(), body["expires_in"], 0)
}

func TestTokenExpiresInMatchesTTLOnWallClock(t *testing.T) {
	t.Parallel()

	// The default clock must advertise the configured TTL exactly, not one
	// second short because a millisecond elapsed between two clock reads.
	body := issueToken(t, newClockedServer(t, nil, nil))

	assert.InDelta(t, testAccessTTL.Seconds(), body["expires_in"], 0)
}

func TestTokenExpiresInRoundsToNearestSecond(t *testing.T) {
	t.Parallel()

	pinned := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		ttl  time.Duration
		want float64
	}{
		{"whole seconds", 90 * time.Second, 90},
		{"rounds up", 90*time.Second + 600*time.Millisecond, 91},
		{"rounds down", 90*time.Second + 400*time.Millisecond, 90},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newClockedServer(t, func() time.Time { return pinned },
				fixedExpiryGrant{expiresAt: pinned.Add(tc.ttl)})

			assert.InDelta(t, tc.want, issueToken(t, srv)["expires_in"], 0)
		})
	}
}

func TestTokenExpiresInNeverNegative(t *testing.T) {
	t.Parallel()

	pinned := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		expiresAt time.Time
	}{
		{"already expired", pinned.Add(-time.Hour)},
		{"expiring now", pinned},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newClockedServer(t, func() time.Time { return pinned },
				fixedExpiryGrant{expiresAt: tc.expiresAt})

			// RFC 6749 §5.1: expires_in is a lifetime in seconds, so a
			// negative value is not allowed. It drops off the wire instead.
			body := issueToken(t, srv)
			assert.NotContains(t, body, "expires_in")
			assert.Equal(t, "opaque-access-token", body["access_token"])
		})
	}
}
