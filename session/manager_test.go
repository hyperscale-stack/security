// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// principal is a tiny security.Principal for the Login tests.
type principal struct{ sub string }

func (p principal) Subject() string { return p.sub }

func newManager(t *testing.T, opts ...session.Option) *session.Manager {
	t.Helper()

	codec, err := session.NewCodec(testKey)
	require.NoError(t, err)

	return session.NewManager(codec, opts...)
}

func TestManagerLoginGetRoundTrip(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	s, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)
	assert.Equal(t, "alice", s.GetString("sub"))

	// Replay the cookie on the next request.
	got, err := mgr.Get(context.Background(), c.replay())
	require.NoError(t, err)
	assert.Equal(t, "alice", got.GetString("sub"))
	assert.Equal(t, s.ID, got.ID)
}

func TestManagerCookieSecurityAttributes(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	assert.True(t, c.hasAttr("HttpOnly"), "cookie must be HttpOnly")
	assert.True(t, c.hasAttr("Secure"), "cookie must be Secure by default")
	assert.True(t, c.hasAttr("SameSite=Lax"), "cookie must default to SameSite=Lax")
}

func TestManagerGetWithoutCookie(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	_, err := mgr.Get(context.Background(), newCarrier())
	assert.ErrorIs(t, err, session.ErrNoSession)
}

func TestManagerLogoutClearsCookie(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	// New carrier carrying the live cookie; Logout writes a deletion cookie.
	live := c.replay()
	mgr.Logout(context.Background(), live)

	// The deletion cookie has Max-Age<0, so replay() drops it: the next
	// request has no session.
	_, err = mgr.Get(context.Background(), live.replay())
	assert.ErrorIs(t, err, session.ErrNoSession)
}

func TestManagerRotateChangesIDKeepsValues(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	original, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	rotated, err := mgr.Rotate(context.Background(), c.replay())
	require.NoError(t, err)

	assert.NotEqual(t, original.ID, rotated.ID, "Rotate must mint a new session ID (anti-fixation)")
	assert.Equal(t, "alice", rotated.GetString("sub"), "Rotate must preserve session values")
	// CreatedAt round-trips through JSON, which drops the monotonic clock —
	// compare instants with time.Time.Equal, not assert.Equal.
	assert.True(t, original.CreatedAt.Equal(rotated.CreatedAt), "Rotate keeps the original creation time")
}

func TestManagerExpiredSessionRejected(t *testing.T) {
	t.Parallel()

	// Clock starts at T; the session lives 1h. We Login at T then Get at
	// T+2h with the same fixed clock advanced.
	base := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	now := base

	mgr := newManager(t,
		session.WithTTL(time.Hour),
		session.WithClock(func() time.Time { return now }),
	)

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	now = base.Add(2 * time.Hour) // past the 1h TTL

	_, err = mgr.Get(context.Background(), c.replay())
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTokenExpired)
}

func TestManagerIdleTimeout(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	now := base

	mgr := newManager(t,
		session.WithTTL(24*time.Hour),
		session.WithIdleTimeout(15*time.Minute),
		session.WithClock(func() time.Time { return now }),
	)

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	now = base.Add(20 * time.Minute) // idle past the 15m window

	_, err = mgr.Get(context.Background(), c.replay())
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTokenExpired)
}

func TestManagerTamperedCookieRejected(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	// Corrupt the stored cookie value.
	replayed := c.replay()
	for name := range replayed.cookies {
		replayed.cookies[name] += "x"
	}

	_, err = mgr.Get(context.Background(), replayed)
	assert.ErrorIs(t, err, session.ErrNoSession, "a tampered cookie must not decode")
}

func TestManagerWithSecureFalseForDevelopment(t *testing.T) {
	t.Parallel()

	mgr := newManager(t, session.WithSecure(false), session.WithSameSite(http.SameSiteStrictMode))

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	assert.False(t, c.hasAttr("Secure"))
	assert.True(t, c.hasAttr("SameSite=Strict"))
}

func TestManagerIsRaceSafe(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			c := newCarrier()
			_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
			assert.NoError(t, err)

			_, err = mgr.Get(context.Background(), c.replay())
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
}
