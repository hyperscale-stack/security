// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newClientPair returns a pair issued to the test client in family under
// the test servers' issuer: refresh token raw and access token
// raw+"-access", for alice with scope api:read, both valid for an hour.
func newClientPair(raw, family string) *oauth2.TokenPair {
	now := time.Now()

	return &oauth2.TokenPair{
		Access: oauth2.AccessToken{
			Token: raw + "-access", TokenHash: oauth2.HashToken(nil, raw+"-access"),
			ClientID: testClientID, Subject: "alice", Scope: "api:read", Audience: "api",
			FamilyID: family, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "https://auth.example",
		},
		Refresh: &oauth2.RefreshToken{
			Token: raw, TokenHash: oauth2.HashToken(nil, raw),
			ClientID: testClientID, Subject: "alice", Scope: "api:read",
			FamilyID: family, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Issuer: "https://auth.example",
		},
	}
}

// seedPair persists pair straight into store, the way a grant issues it,
// and returns it.
func seedPair(t *testing.T, store oauth2.Storage, pair *oauth2.TokenPair) *oauth2.TokenPair {
	t.Helper()

	require.NoError(t, store.SaveTokenPair(t.Context(), pair))

	return pair
}

// seedRotated persists pair, then rotates its refresh token into next: the
// only way a consumed refresh token comes to exist.
func seedRotated(t *testing.T, store oauth2.Storage, pair, next *oauth2.TokenPair) {
	t.Helper()

	seedPair(t, store, pair)
	require.NoError(t, store.RotateRefreshToken(t.Context(), pair.Refresh.TokenHash, next))
}

func TestTokenPairValidate(t *testing.T) {
	t.Parallel()

	access := func(family string) oauth2.AccessToken {
		return oauth2.AccessToken{TokenHash: "at-hash", ClientID: "c", FamilyID: family}
	}
	refresh := func(family string) *oauth2.RefreshToken {
		return &oauth2.RefreshToken{TokenHash: "rt-hash", ClientID: "c", FamilyID: family}
	}

	maxFamily := strings.Repeat("f", oauth2.MaxFamilyIDLength)
	tooLong := maxFamily + "f"

	cases := []struct {
		name    string
		pair    *oauth2.TokenPair
		wantErr bool
	}{
		{"nil pair", nil, true},
		{"access token without hash", &oauth2.TokenPair{Access: oauth2.AccessToken{FamilyID: "F"}}, true},
		{"access only, no family", &oauth2.TokenPair{Access: access("")}, false},
		{"access only, in a family", &oauth2.TokenPair{Access: access("F")}, false},
		{"access and refresh in one family", &oauth2.TokenPair{Access: access("F"), Refresh: refresh("F")}, false},
		{"family id at the length limit", &oauth2.TokenPair{Access: access(maxFamily), Refresh: refresh(maxFamily)}, false},
		{"family id over the length limit", &oauth2.TokenPair{Access: access(tooLong)}, true},
		{"refresh token without hash", &oauth2.TokenPair{
			Access: access("F"), Refresh: &oauth2.RefreshToken{FamilyID: "F"},
		}, true},
		{"refresh token without family", &oauth2.TokenPair{Access: access(""), Refresh: refresh("")}, true},
		{"refresh token in another family", &oauth2.TokenPair{Access: access("F"), Refresh: refresh("G")}, true},
		{"refresh token already consumed", &oauth2.TokenPair{
			Access: access("F"),
			Refresh: &oauth2.RefreshToken{
				TokenHash: "rt-hash", FamilyID: "F", Consumed: true, ExpiresAt: time.Now().Add(time.Hour),
			},
		}, true},
		{"access and refresh share the grant context", &oauth2.TokenPair{
			Access: oauth2.AccessToken{TokenHash: "at-hash", FamilyID: "F", Issuer: "https://a.example", ExtensionData: "ctx"},
			Refresh: &oauth2.RefreshToken{
				TokenHash: "rt-hash", FamilyID: "F", Issuer: "https://a.example", ExtensionData: "ctx",
			},
		}, false},
		{"refresh token under another issuer", &oauth2.TokenPair{
			Access: oauth2.AccessToken{TokenHash: "at-hash", FamilyID: "F", Issuer: "https://a.example"},
			Refresh: &oauth2.RefreshToken{
				TokenHash: "rt-hash", FamilyID: "F", Issuer: "https://b.example",
			},
		}, true},
		{"refresh token with other extension data", &oauth2.TokenPair{
			Access: oauth2.AccessToken{TokenHash: "at-hash", FamilyID: "F", ExtensionData: "ctx"},
			Refresh: &oauth2.RefreshToken{
				TokenHash: "rt-hash", FamilyID: "F", ExtensionData: "other",
			},
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.pair.Validate()
			if !tc.wantErr {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Equal(t, oauth2.CodeInvalidRequest, oauth2.IsCode(err))
			assert.ErrorIs(t, err, security.ErrInvalidCredentials)

			var oe *oauth2.Error
			require.ErrorAs(t, err, &oe)
			assert.Regexp(t, descriptionCharset, oe.Description)
			assert.True(t, strings.HasPrefix(oe.Description, "storage: "), oe.Description)
		})
	}
}

func TestFamilySentinels(t *testing.T) {
	t.Parallel()

	t.Run("revoked family is invalid_grant", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(oauth2.ErrTokenFamilyRevoked))
		assert.Equal(t, http.StatusBadRequest, oauth2.ErrTokenFamilyRevoked.HTTPStatus())
		assert.ErrorIs(t, oauth2.ErrTokenFamilyRevoked, security.ErrInvalidCredentials)
		assert.Equal(t, "token family revoked", oauth2.ErrTokenFamilyRevoked.Description)
	})

	t.Run("revocation failure never reaches the wire", func(t *testing.T) {
		t.Parallel()

		// A plain sentinel, not an *Error: it carries no OAuth2 code, so a
		// response writer can only ever turn it into a server_error.
		assert.Empty(t, oauth2.IsCode(oauth2.ErrTokenFamilyRevocationFailed))
		assert.EqualError(t, oauth2.ErrTokenFamilyRevocationFailed, "oauth2: token family revocation failed")
	})

	t.Run("reuse no longer claims the family was revoked", func(t *testing.T) {
		t.Parallel()

		// RFC 6749 §5.2 limits error_description to %x20-21 / %x23-5B /
		// %x5D-7E: the former em dash was outside that charset.
		assert.Equal(t, "refresh token reused", oauth2.ErrRefreshTokenReused.Description)
		assert.Regexp(t, descriptionCharset, oauth2.ErrRefreshTokenReused.Description)
		assert.Regexp(t, descriptionCharset, oauth2.ErrTokenFamilyRevoked.Description)
	})

	t.Run("a failed reuse revocation matches both sentinels", func(t *testing.T) {
		t.Parallel()

		// The shape a store returns when it detects reuse but cannot
		// revoke the family: reuse first, so the OAuth2 code stays
		// invalid_grant, with the revocation failure and its cause after.
		cause := errors.New("backend down")
		err := fmt.Errorf("%w: %w", oauth2.ErrRefreshTokenReused,
			fmt.Errorf("store: revoke family %q: %w: %w", "F", oauth2.ErrTokenFamilyRevocationFailed, cause))

		assert.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
		assert.ErrorIs(t, err, oauth2.ErrTokenFamilyRevocationFailed)
		assert.ErrorIs(t, err, cause)
		assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))
	})

	t.Run("retention outlives a revocation recorded before issuance", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 24*time.Hour, oauth2.FamilyRevocationRetention)
		assert.Equal(t, 64, oauth2.MaxFamilyIDLength)
	})
}

// familyRevocationFailure is the error a conforming store returns when it
// cannot record family as revoked.
func familyRevocationFailure(family string) error {
	return fmt.Errorf("store: revoke family %q: %w: %w",
		family, oauth2.ErrTokenFamilyRevocationFailed, errors.New("backend down"))
}

// reuseFailingStore reports, on every rotation, a reuse the store detected
// but could not answer with a family revocation, and fails every
// revocation: the grant's retry fails too.
type reuseFailingStore struct{ *memory.Store }

func (s *reuseFailingStore) RotateRefreshToken(_ context.Context, _ string, next *oauth2.TokenPair) error {
	return fmt.Errorf("%w: %w", oauth2.ErrRefreshTokenReused, familyRevocationFailure(next.Access.FamilyID))
}

func (s *reuseFailingStore) RevokeRefreshFamily(_ context.Context, familyID string) error {
	return familyRevocationFailure(familyID)
}

func TestOnErrorReportsStoreReuseRevocationFailure(t *testing.T) {
	t.Parallel()

	grantSink, serverSink := &errorSink{}, &errorSink{}
	store := &reuseFailingStore{Store: memory.New()}
	seedServerRefresh(t, store, "store-reuse-rt")

	gcfg := nonRotatingConfig(store) // Profile20BCP rotates all the same
	gcfg.OnError = grantSink.hook

	cfg := refreshServerConfig(oauth2.Profile20BCP, store, grant.NewRefreshToken(gcfg))
	cfg.OnError = serverSink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	rec := refreshExchange(t, srv, "store-reuse-rt")

	// The wire carries the reuse refusal, nothing of the failed revocation...
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.JSONEq(t, `{"error":"invalid_grant","error_description":"refresh token reused"}`, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "backend down")

	// ...the grant hook gets one server_error carrying the cause...
	got := grantSink.collected()
	require.Len(t, got, 1)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(got[0]))
	assert.ErrorIs(t, got[0], oauth2.ErrTokenFamilyRevocationFailed)
	assert.ErrorContains(t, errors.Unwrap(got[0]), `revoke family "family-rot"`)
	assert.ErrorContains(t, errors.Unwrap(got[0]), "backend down")

	// ...and the server hook the invalid_grant it answered.
	assert.Equal(t, []string{oauth2.CodeInvalidGrant}, serverSink.codes())
}

func TestRevokeEndpointRevokesWholeFamily(t *testing.T) {
	t.Parallel()

	srv, store := newTestServer(t)
	seedPair(t, store, newClientPair("whole-rt", "fam-whole"))

	rec := refreshExchange(t, srv, "whole-rt")
	require.Equal(t, http.StatusOK, rec.Code)

	var issued struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issued))
	require.NotEmpty(t, issued.RefreshToken)

	rec = httptest.NewRecorder()
	srv.RevokeHandler().ServeHTTP(rec, formRequest("/oauth2/revoke", url.Values{"token": {issued.RefreshToken}}, true))
	require.Equal(t, http.StatusOK, rec.Code)

	// Revoking the newest refresh token revokes the whole family: the
	// access tokens issued before it and alongside it, and the refresh
	// token itself.
	for _, raw := range []string{"whole-rt-access", issued.AccessToken, issued.RefreshToken} {
		assert.False(t, introspect(t, srv, raw)["active"].(bool), raw)
	}

	rec = refreshExchange(t, srv, issued.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidGrant, decodeError(t, rec))
}

func TestIntrospectionPolicyNeverSeesRevokedFamily(t *testing.T) {
	t.Parallel()

	store := memory.New()
	probe := &policyProbe{allow: true}

	cfg := hookServerConfig(store)
	cfg.IntrospectionPolicy = probe.decide

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	seedPair(t, store, newClientPair("policy-revoked", "fam-policy-revoked"))
	require.NoError(t, store.RevokeRefreshFamily(t.Context(), "fam-policy-revoked"))

	for _, raw := range []string{"policy-revoked", "policy-revoked-access"} {
		assert.False(t, introspect(t, srv, raw)["active"].(bool), raw)
	}

	assert.Zero(t, probe.calls.Load(), "a token of a revoked family is inactive before any policy runs")

	seedPair(t, store, newClientPair("policy-live", "fam-policy-live"))
	assert.True(t, introspect(t, srv, "policy-live-access")["active"].(bool))
	assert.Equal(t, int32(1), probe.calls.Load(), "an active token still goes through the policy")
}
