// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAccessInfoIsExpiredAt(t *testing.T) {
	t.Parallel()

	origin := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	info := &AccessInfo{
		CreatedAt: origin,
		ExpiresIn: 60, // seconds
	}

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before_creation", origin.Add(-time.Hour), false},
		{"at_creation", origin, false},
		{"mid_window", origin.Add(30 * time.Second), false},
		{"just_at_expiry", origin.Add(60 * time.Second), false},
		{"one_second_after_expiry", origin.Add(61 * time.Second), true},
		{"long_after_expiry", origin.Add(24 * time.Hour), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, info.IsExpiredAt(tc.now))
		})
	}
}

func TestAccessInfoExpireAt(t *testing.T) {
	t.Parallel()

	origin := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	info := &AccessInfo{CreatedAt: origin, ExpiresIn: 90}

	assert.Equal(t, origin.Add(90*time.Second), info.ExpireAt())
}

func TestAuthorizeInfoIsExpiredAt(t *testing.T) {
	t.Parallel()

	origin := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	info := &AuthorizeInfo{
		CreatedAt: origin,
		ExpiresIn: 600,
	}

	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before_creation", origin.Add(-time.Hour), false},
		{"mid_window", origin.Add(5 * time.Minute), false},
		{"at_expiry", origin.Add(10 * time.Minute), false},
		{"after_expiry", origin.Add(10*time.Minute + time.Second), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, info.IsExpiredAt(tc.now))
		})
	}
}

func TestAuthorizeInfoExpireAt(t *testing.T) {
	t.Parallel()

	origin := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	info := &AuthorizeInfo{CreatedAt: origin, ExpiresIn: 300}

	assert.Equal(t, origin.Add(5*time.Minute), info.ExpireAt())
}

// TestIsExpiredUsesWallClock is a coarse sanity check that IsExpired falls
// back on time.Now(). We don't assert equality, only ordering bounds.
func TestIsExpiredUsesWallClock(t *testing.T) {
	t.Parallel()

	// CreatedAt is far in the past, ExpiresIn small: must be expired now.
	pastExpired := &AccessInfo{
		CreatedAt: time.Now().Add(-time.Hour),
		ExpiresIn: 1,
	}
	assert.True(t, pastExpired.IsExpired())

	// CreatedAt is now, long TTL: must not be expired.
	freshLong := &AccessInfo{
		CreatedAt: time.Now(),
		ExpiresIn: 86400,
	}
	assert.False(t, freshLong.IsExpired())
}
