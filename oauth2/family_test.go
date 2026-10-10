// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
