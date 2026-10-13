// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// clockedManager returns a Manager on the clock *now with the given TTL.
func clockedManager(t *testing.T, now *time.Time, opts ...session.Option) *session.Manager {
	t.Helper()

	return managerWithKeys(t, now, [][]byte{testKey}, opts...)
}

// lastCookie parses the last Set-Cookie staged on c.
func lastCookie(t *testing.T, c *mapCarrier) *http.Cookie {
	t.Helper()

	resp := http.Response{Header: http.Header{"Set-Cookie": {c.lastSetCookie()}}}
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)

	return cookies[0]
}

// Audit CORE-08 (probe TestZZAuditSessionRotateExtendsAbsoluteExpiry): with a
// 1 h TTL and a Rotate every 55 minutes, a session created at 00:00 was still
// alive at 04:35 — Rotate moved ExpiresAt to now+TTL. Decision 10: the
// absolute lifetime CreatedAt+TTL is never extended by Rotate.
func TestRotateNeverExtendsTheAbsoluteLifetime(t *testing.T) {
	t.Parallel()

	now := epoch
	mgr := clockedManager(t, &now, session.WithTTL(time.Hour))

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	browser := c.replay()

	now = now.Add(55 * time.Minute)

	rotated, err := mgr.Rotate(context.Background(), browser)
	require.NoError(t, err)
	assert.True(t, rotated.CreatedAt.Equal(epoch))
	assert.True(t, rotated.ExpiresAt.Equal(epoch.Add(time.Hour)), "ExpiresAt stays CreatedAt+TTL: %s", rotated.ExpiresAt)
	assert.Equal(t, 300, lastCookie(t, browser).MaxAge, "the cookie lives until the deadline only")

	now = now.Add(5*time.Minute + time.Second) // 01:00:01

	_, err = mgr.Rotate(context.Background(), browser.replay())
	require.ErrorIs(t, err, security.ErrTokenExpired)

	_, err = mgr.Get(context.Background(), browser.replay())
	require.ErrorIs(t, err, security.ErrTokenExpired)
}

// Audit CORE-08 (probe TestZZAuditSessionNoRevocation): only the ExpiresAt
// carried in the cookie was checked — a cookie issued with a 30-day TTL kept
// working for 30 days on a manager reconfigured with 15 minutes.
func TestManagerEnforcesItsTTLOnOlderCookies(t *testing.T) {
	t.Parallel()

	now := epoch
	long := clockedManager(t, &now, session.WithTTL(30*24*time.Hour))
	short := clockedManager(t, &now, session.WithTTL(15*time.Minute))

	c := newCarrier()
	_, err := long.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	now = epoch.Add(14 * time.Minute)

	s, err := short.Get(context.Background(), c.replay())
	require.NoError(t, err)
	assert.True(t, s.ExpiresAt.Equal(epoch.Add(15*time.Minute)), "Get reports the enforced deadline: %s", s.ExpiresAt)

	now = epoch.Add(16 * time.Minute)

	_, err = short.Get(context.Background(), c.replay())
	require.ErrorIs(t, err, security.ErrTokenExpired)

	_, err = long.Get(context.Background(), c.replay())
	require.NoError(t, err, "control: the 30-day manager still accepts it")
}

// Raising the TTL never extends an issued session: the cookie's own
// ExpiresAt still applies.
func TestRaisingTheTTLDoesNotExtendIssuedSessions(t *testing.T) {
	t.Parallel()

	now := epoch
	short := clockedManager(t, &now, session.WithTTL(time.Hour))
	long := clockedManager(t, &now, session.WithTTL(48*time.Hour))

	c := newCarrier()
	_, err := short.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	now = epoch.Add(2 * time.Hour)

	_, err = long.Get(context.Background(), c.replay())
	require.ErrorIs(t, err, security.ErrTokenExpired)
}

// Boundaries: a session is valid at exactly its deadline and expired one
// nanosecond later, whichever of CreatedAt+TTL and ExpiresAt comes first.
func TestManagerDeadlineBoundaries(t *testing.T) {
	t.Parallel()

	for name, ttls := range map[string][2]time.Duration{
		"TTL of the reading manager first": {2 * time.Hour, time.Hour},
		"cookie ExpiresAt first":           {time.Hour, 2 * time.Hour},
	} {
		now := epoch
		writer := clockedManager(t, &now, session.WithTTL(ttls[0]))
		reader := clockedManager(t, &now, session.WithTTL(ttls[1]))

		c := newCarrier()
		_, err := writer.Login(context.Background(), c, principal{sub: "alice"})
		require.NoError(t, err)

		now = epoch.Add(time.Hour)

		_, err = reader.Get(context.Background(), c.replay())
		require.NoError(t, err, "%s: valid at exactly the deadline", name)

		now = epoch.Add(time.Hour + time.Nanosecond)

		_, err = reader.Get(context.Background(), c.replay())
		require.ErrorIs(t, err, security.ErrTokenExpired, name)
	}
}

// Review nit 13: the cookie lifetime comes from the deadline, never from an
// ExpiresAt the application moved — and Max-Age is rounded up (in Go,
// MaxAge 0 means "no attribute").
func TestTouchWritesTheDeadline(t *testing.T) {
	t.Parallel()

	now := epoch
	mgr := clockedManager(t, &now, session.WithTTL(time.Hour))

	s, err := mgr.Login(context.Background(), newCarrier(), principal{sub: "alice"})
	require.NoError(t, err)

	s.ExpiresAt = epoch.Add(365 * 24 * time.Hour) // the application tries to extend it

	now = epoch.Add(59*time.Minute + 58*time.Second + 500*time.Millisecond)

	c := newCarrier()
	require.NoError(t, mgr.Touch(context.Background(), c, s))

	cookie := lastCookie(t, c)
	assert.Equal(t, 2, cookie.MaxAge, "1.5 s left, rounded up")
	assert.True(t, cookie.Expires.Equal(epoch.Add(time.Hour)), "Expires is the deadline: %s", cookie.Expires)

	got, err := mgr.Get(context.Background(), c.replay())
	require.NoError(t, err)
	assert.True(t, got.ExpiresAt.Equal(epoch.Add(time.Hour)), "the sealed ExpiresAt is the deadline: %s", got.ExpiresAt)
}

// Touch never writes a session past its deadline — it used to write it with
// Max-Age 1 — and refuses a nil session instead of panicking.
func TestTouchRefusesAnExpiredOrMissingSession(t *testing.T) {
	t.Parallel()

	now := epoch
	mgr := clockedManager(t, &now, session.WithTTL(time.Hour))

	s, err := mgr.Login(context.Background(), newCarrier(), principal{sub: "alice"})
	require.NoError(t, err)

	now = epoch.Add(time.Hour)

	c := newCarrier()
	require.ErrorIs(t, mgr.Touch(context.Background(), c, s), security.ErrTokenExpired, "nothing left to write at the deadline")
	assert.Empty(t, c.setCookies)

	require.ErrorIs(t, mgr.Touch(context.Background(), c, nil), session.ErrNoSession)
	assert.Empty(t, c.setCookies)
}

// Pinned documented behaviour: Get does not slide the idle window, Touch does.
func TestOnlyTouchSlidesTheIdleWindow(t *testing.T) {
	t.Parallel()

	now := epoch
	mgr := clockedManager(t, &now, session.WithIdleTimeout(10*time.Minute))

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	browser := c.replay()

	now = epoch.Add(6 * time.Minute)

	s, err := mgr.Get(context.Background(), browser)
	require.NoError(t, err)

	now = epoch.Add(12 * time.Minute)

	_, err = mgr.Get(context.Background(), browser)
	require.ErrorIs(t, err, security.ErrTokenExpired, "Get alone does not slide the window")

	now = epoch.Add(6 * time.Minute)

	touched := newCarrier()
	require.NoError(t, mgr.Touch(context.Background(), touched, s))

	now = epoch.Add(12 * time.Minute)

	_, err = mgr.Get(context.Background(), touched.replay())
	require.NoError(t, err, "Touch slid it")
}

// At exactly its deadline a session is still read, but nothing is left to
// rotate into.
func TestRotateAtTheDeadline(t *testing.T) {
	t.Parallel()

	now := epoch
	mgr := clockedManager(t, &now, session.WithTTL(time.Hour))

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	now = epoch.Add(time.Hour)

	_, err = mgr.Rotate(context.Background(), c.replay())
	require.ErrorIs(t, err, security.ErrTokenExpired)
}

// Session.IsExpired checks the ExpiresAt the session carries (the Manager
// also enforces CreatedAt + TTL).
func TestSessionIsExpired(t *testing.T) {
	t.Parallel()

	s := &session.Session{ExpiresAt: epoch}

	assert.False(t, s.IsExpired(epoch))
	assert.True(t, s.IsExpired(epoch.Add(time.Nanosecond)))
}

// The cookie name is length-prefixed in the associated data: absurdly long
// names are a configuration error.
func TestNewManagerRefusesAnOverlongCookieName(t *testing.T) {
	t.Parallel()

	codec, err := session.NewCodec(testKey)
	require.NoError(t, err)

	assert.Panics(t, func() { session.NewManager(codec, session.WithCookieName(strings.Repeat("n", 257))) })
	assert.NotPanics(t, func() { session.NewManager(codec, session.WithCookieName(strings.Repeat("n", 256))) })
}

// A session issued under a shorter TTL keeps its own deadline through a
// Rotate on a Manager whose TTL was raised since.
func TestRotateKeepsTheShorterDeadlineAfterATTLIncrease(t *testing.T) {
	t.Parallel()

	now := epoch
	short := clockedManager(t, &now, session.WithTTL(time.Hour))
	long := clockedManager(t, &now, session.WithTTL(48*time.Hour))

	c := newCarrier()
	_, err := short.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	now = epoch.Add(30 * time.Minute)

	browser := c.replay()

	rotated, err := long.Rotate(context.Background(), browser)
	require.NoError(t, err)
	assert.True(t, rotated.ExpiresAt.Equal(epoch.Add(time.Hour)), "deadline kept: %s", rotated.ExpiresAt)
	assert.Equal(t, 1800, lastCookie(t, browser).MaxAge)
}
