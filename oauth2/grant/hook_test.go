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
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// familyRevokeFailingStore fails the family revocation the reuse-detection
// path runs, so the swallowed error can be observed.
type familyRevokeFailingStore struct {
	*memory.Store

	err error
}

func (s *familyRevokeFailingStore) RevokeRefreshFamily(context.Context, string) error {
	return s.err
}

// consumedRefreshRequest stores an already-consumed refresh token and
// returns the matching /token request — the BCP §8.10.3 reuse case.
func consumedRefreshRequest(ctx context.Context, store oauth2.Storage) grant.Request {
	raw := "reused-refresh-token"

	_ = store.SaveRefreshToken(ctx, &oauth2.RefreshToken{
		Token:     raw,
		TokenHash: oauth2.HashToken(nil, raw),
		ClientID:  clientID,
		Subject:   subject,
		Scope:     "read:mail",
		FamilyID:  "family-1",
		Consumed:  true,
		IssuedAt:  time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC),
	})

	return grant.Request{
		Client:   newClient(),
		Form:     url.Values{"refresh_token": {raw}},
		Issuer:   "https://auth.example",
		Audience: "api",
		Now:      time.Date(2026, 5, 20, 13, 0, 0, 0, time.UTC),
		Profile:  oauth2.Profile20BCP,
	}
}

func TestRefreshTokenOnErrorReportsFamilyRevokeFailure(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := &familyRevokeFailingStore{
		Store: memory.New(),
		err:   errors.New("revocation backend down"),
	}

	var seen []error

	g := grant.NewRefreshToken(grant.Config{
		Storage:             store,
		AccessTokens:        newAccessGen(),
		RefreshTokens:       newRefreshGen(),
		AccessTTL:           time.Hour,
		RefreshTTL:          24 * time.Hour,
		RotateRefreshTokens: true,
		OnError: func(_ context.Context, err error) {
			seen = append(seen, err)
		},
	})

	resp, err := g.Handle(ctx, consumedRefreshRequest(ctx, store))

	// The protocol answer is unchanged: reuse stays invalid_grant.
	assert.Nil(t, resp)
	require.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
	assert.Equal(t, oauth2.CodeInvalidGrant, oauth2.IsCode(err))

	// The failed revocation is only visible through the hook.
	require.Len(t, seen, 1)
	assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(seen[0]))
	assert.ErrorContains(t, seen[0], "revoke refresh family failed after reuse detection")
	assert.ErrorContains(t, errors.Unwrap(seen[0]), "revocation backend down")
}

func TestRefreshTokenOnErrorIsOptional(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := &familyRevokeFailingStore{
		Store: memory.New(),
		err:   errors.New("revocation backend down"),
	}

	g := grant.NewRefreshToken(grant.Config{
		Storage:             store,
		AccessTokens:        newAccessGen(),
		RefreshTokens:       newRefreshGen(),
		AccessTTL:           time.Hour,
		RefreshTTL:          24 * time.Hour,
		RotateRefreshTokens: true,
	})

	req := consumedRefreshRequest(ctx, store)

	assert.NotPanics(t, func() {
		_, err := g.Handle(ctx, req)
		assert.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
	})
}

func TestRefreshTokenOnErrorQuietOnSuccessfulRevoke(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := memory.New()

	var seen []error

	g := grant.NewRefreshToken(grant.Config{
		Storage:             store,
		AccessTokens:        newAccessGen(),
		RefreshTokens:       newRefreshGen(),
		AccessTTL:           time.Hour,
		RefreshTTL:          24 * time.Hour,
		RotateRefreshTokens: true,
		OnError: func(_ context.Context, err error) {
			seen = append(seen, err)
		},
	})

	_, err := g.Handle(ctx, consumedRefreshRequest(ctx, store))
	require.ErrorIs(t, err, oauth2.ErrRefreshTokenReused)
	assert.Empty(t, seen, "a successful family revocation must stay quiet")
}
