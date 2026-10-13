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

// Audit CORE-I8 and decision Q1: the default cookie name is __Host-session
// — Secure, Path=/, no Domain, so a sibling host cannot plant a cookie
// that shadows it (draft-ietf-httpbis-rfc6265bis §4.1.3.2) — and falls back
// to __Secure-session or session when the configuration cannot satisfy the
// prefix. It is computed after every option, whatever their order.
func TestDefaultCookieName(t *testing.T) {
	t.Parallel()

	codec, err := session.NewCodec(testKey)
	require.NoError(t, err)

	for want, opts := range map[string][][]session.Option{
		"__Host-session": {nil, {session.WithPath("/")}, {session.WithSecure(true)}},
		"__Secure-session": {
			{session.WithDomain("example.com")},
			{session.WithPath("/app")},
			{session.WithDomain("example.com"), session.WithPath("/app")},
		},
		"session": {
			{session.WithSecure(false)},
			{session.WithSecure(false), session.WithDomain("example.com")},
		},
	} {
		for _, o := range opts {
			assert.Equal(t, want, session.NewManager(codec, o...).CookieName(), "%d options", len(o))

			reversed := make([]session.Option, len(o))
			for i := range o {
				reversed[i] = o[len(o)-1-i]
			}

			assert.Equal(t, want, session.NewManager(codec, reversed...).CookieName(), "options reversed")
		}
	}

	c := newCarrier()
	_, err = session.NewManager(codec).Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	cookie := lastCookie(t, c)
	assert.Equal(t, "__Host-session", cookie.Name)
	assert.Equal(t, "/", cookie.Path)
	assert.Empty(t, cookie.Domain)
	assert.True(t, cookie.Secure)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
}

// Audit CORE-I8 (probe TestZZAuditSessionCookieAttributes): a __Host- name
// with Domain and Path was emitted although browsers reject it, and an
// invalid name produced an empty Set-Cookie while Login reported success.
// The configuration is now checked at construction (prefixes matched
// case-insensitively, like user agents do — rfc6265bis §5.4).
func TestNewManagerRefusesInvalidCookieConfiguration(t *testing.T) {
	t.Parallel()

	codec, err := session.NewCodec(testKey)
	require.NoError(t, err)

	cases := map[string]struct {
		codec *session.Codec
		opts  []session.Option
		msg   string
	}{
		"nil codec":                    {nil, nil, "nil Codec"},
		"name with a space":            {codec, []session.Option{session.WithCookieName("my session")}, "cookie name"},
		"empty name":                   {codec, []session.Option{session.WithCookieName("")}, "cookie name"},
		"__Host- with a Domain":        {codec, []session.Option{session.WithCookieName("__Host-sid"), session.WithDomain("example.com")}, "__Host-"},
		"__Host- with another Path":    {codec, []session.Option{session.WithCookieName("__Host-sid"), session.WithPath("/app")}, "__Host-"},
		"__Host- without Secure":       {codec, []session.Option{session.WithCookieName("__host-sid"), session.WithSecure(false)}, "__Host-"},
		"__Secure- without Secure":     {codec, []session.Option{session.WithCookieName("__SECURE-sid"), session.WithSecure(false)}, "__Secure-"},
		"relative path":                {codec, []session.Option{session.WithPath("app")}, "path"},
		"path with a semicolon":        {codec, []session.Option{session.WithPath("/a;b")}, "path"},
		"over-long path":               {codec, []session.Option{session.WithPath("/" + strings.Repeat("p", 1024))}, "path"},
		"invalid domain":               {codec, []session.Option{session.WithDomain("exa mple.com")}, "domain"},
		"SameSite=None without Secure": {codec, []session.Option{session.WithSameSite(http.SameSiteNoneMode), session.WithSecure(false)}, "SameSite=None"},
		"zero TTL":                     {codec, []session.Option{session.WithTTL(0)}, "TTL"},
		"negative TTL":                 {codec, []session.Option{session.WithTTL(-time.Hour)}, "TTL"},
		"negative idle timeout":        {codec, []session.Option{session.WithIdleTimeout(-time.Minute)}, "idle"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				r := recover()
				require.NotNil(t, r, "NewManager must panic")
				assert.Contains(t, r, c.msg)
			}()

			session.NewManager(c.codec, c.opts...)
		})
	}

	for name, opts := range map[string][]session.Option{
		"explicit __Host-":               {session.WithCookieName("__Host-sid")},
		"explicit __Secure- with Domain": {session.WithCookieName("__Secure-sid"), session.WithDomain("example.com")},
		"plain name over plain HTTP":     {session.WithCookieName("sid"), session.WithSecure(false)},
		"SameSite=None with Secure":      {session.WithSameSite(http.SameSiteNoneMode)},
		"strict":                         {session.WithSameSite(http.SameSiteStrictMode)},
	} {
		assert.NotPanics(t, func() { session.NewManager(codec, opts...) }, name)
	}
}

// Audit CORE-I8: an oversized session (8 500 bytes) was emitted silently and
// dropped by browsers (name + value over 4096 octets, rfc6265bis §5.6). The
// write now fails with ErrCookieTooLarge and nothing is staged.
func TestManagerRefusesOversizedCookies(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	s, err := mgr.Login(context.Background(), newCarrier(), principal{sub: "alice"})
	require.NoError(t, err)

	fits := func(blob int) error {
		s.Values["blob"] = strings.Repeat("x", blob)

		c := newCarrier()
		err := mgr.Touch(context.Background(), c, s)

		if err != nil {
			assert.Empty(t, c.setCookies, "nothing staged on failure")

			return err
		}

		cookie := lastCookie(t, c)
		assert.LessOrEqual(t, len(cookie.Name)+len(cookie.Value), session.MaxCookieSize)

		return nil
	}

	require.ErrorIs(t, fits(6000), session.ErrCookieTooLarge)

	// Find the boundary: the largest blob that fits gives a cookie of at
	// most 4096 octets, one more byte does not fit.
	lo, hi := 0, 6000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if fits(mid) == nil {
			lo = mid
		} else {
			hi = mid - 1
		}
	}

	require.NoError(t, fits(lo))
	require.ErrorIs(t, fits(lo+3), session.ErrCookieTooLarge, "3 more bytes of plaintext always grow the base64 value")

	// The limit is inclusive: some blob gives exactly 4096 octets of name
	// and value, and that cookie is written.
	exact := false

	for blob := lo - 8; blob <= lo; blob++ {
		s.Values["blob"] = strings.Repeat("x", blob)

		c := newCarrier()
		if mgr.Touch(context.Background(), c, s) == nil {
			cookie := lastCookie(t, c)
			exact = exact || len(cookie.Name)+len(cookie.Value) == session.MaxCookieSize
		}
	}

	assert.True(t, exact, "a cookie of exactly 4096 octets is accepted")

	_, err = mgr.Login(context.Background(), newCarrier(), principal{sub: strings.Repeat("s", 5000)})
	require.ErrorIs(t, err, session.ErrCookieTooLarge, "Login too")
}

// Decision Q1 and review nit 12: several cookies with the session's name — a
// cookie tossed by a sibling host or a more specific path, or a stale one —
// make the request ambiguous when more than one is a valid session: the
// request has no session (fail closed: a tossed cookie can deny a session,
// never swap it). Invalid or expired ones do not count.
func TestManagerRefusesAmbiguousSessionCookies(t *testing.T) {
	t.Parallel()

	now := epoch
	mgr := clockedManager(t, &now, session.WithTTL(time.Hour))
	name := mgr.CookieName()

	valid := func(sub string) string {
		c := newCarrier()
		_, err := mgr.Login(context.Background(), c, principal{sub: sub})
		require.NoError(t, err)

		return c.replay().cookies[name]
	}

	victim, attacker := valid("victim"), valid("attacker")

	now = epoch.Add(-2 * time.Hour)
	stale := valid("stale") // expired at epoch-1h
	now = epoch

	request := func(values ...string) (*session.Session, error) {
		c := newCarrier()
		c.cookies[name] = values[0]
		c.more = map[string][]string{name: values[1:]}

		return mgr.Get(context.Background(), c)
	}

	_, err := request(attacker, victim)
	require.ErrorIs(t, err, session.ErrNoSession, "two valid sessions: ambiguous")

	_, err = request(victim, attacker)
	require.ErrorIs(t, err, session.ErrNoSession, "in either order")

	for name, values := range map[string][]string{
		"garbage first":       {"garbage", victim},
		"garbage last":        {victim, "garbage"},
		"expired first":       {stale, victim},
		"another key's first": {v2Cookie(t, randomKey(t), 2, 2, name, "", samplePayload(t, now)), victim},
	} {
		s, err := request(values...)
		require.NoError(t, err, name)
		assert.Equal(t, "victim", s.GetString("sub"), name)
	}

	_, err = request(stale)
	require.ErrorIs(t, err, security.ErrTokenExpired, "a single expired session still reports its expiry")

	_, err = request("")
	require.ErrorIs(t, err, session.ErrNoSession, "an empty cookie is no session")

	_, err = request("garbage", "garbage", "garbage", "garbage", victim)
	require.ErrorIs(t, err, session.ErrNoSession, "more than four cookies of one name are not inspected")
}

// Audit §9 surviving mutant: the deletion cookie's Max-Age was never
// checked (the test passed because the value was empty). It must carry
// Max-Age=0 and the same Path, Domain and attributes as the session cookie,
// or the browser keeps the session cookie (and rejects a __Host- deletion).
func TestLogoutDeletesTheCookie(t *testing.T) {
	t.Parallel()

	codec, err := session.NewCodec(testKey)
	require.NoError(t, err)

	for _, mgr := range []*session.Manager{
		session.NewManager(codec),
		session.NewManager(codec, session.WithDomain("example.com"), session.WithPath("/app"), session.WithSameSite(http.SameSiteStrictMode)),
	} {
		login := newCarrier()
		_, err := mgr.Login(context.Background(), login, principal{sub: "alice"})
		require.NoError(t, err)

		issued := lastCookie(t, login)

		logout := login.replay()
		mgr.Logout(context.Background(), logout)

		require.Len(t, logout.setCookies, 1)
		assert.Contains(t, logout.setCookies[0], "Max-Age=0")

		deletion := lastCookie(t, logout)
		assert.Equal(t, issued.Name, deletion.Name)
		assert.Empty(t, deletion.Value)
		assert.Negative(t, deletion.MaxAge)
		assert.Equal(t, issued.Path, deletion.Path)
		assert.Equal(t, issued.Domain, deletion.Domain)
		assert.Equal(t, issued.Secure, deletion.Secure)
		assert.Equal(t, issued.HttpOnly, deletion.HttpOnly)
		assert.Equal(t, issued.SameSite, deletion.SameSite)
	}
}

// Audit §9 surviving mutants: VerifyCSRF reduced to the first byte, and its
// empty-token guard removed.
func TestVerifyCSRFComparesTheWholeToken(t *testing.T) {
	t.Parallel()

	s := &session.Session{CSRFToken: "abcdefghijklmnop"}

	assert.True(t, session.VerifyCSRF(s, "abcdefghijklmnop"))
	assert.False(t, session.VerifyCSRF(s, "abcdefghijklmnoq"), "last character differs")
	assert.False(t, session.VerifyCSRF(s, "abcdefghijklmno"), "prefix")
	assert.False(t, session.VerifyCSRF(s, "a"), "first character only")
}

func TestVerifyCSRFRefusesEmptyTokens(t *testing.T) {
	t.Parallel()

	assert.False(t, session.VerifyCSRF(&session.Session{}, ""), "no token minted, none presented")
	assert.False(t, session.VerifyCSRF(&session.Session{}, "x"))
	assert.False(t, session.VerifyCSRF(&session.Session{CSRFToken: "x"}, ""))
}

// A validator that cannot check one of the cookies ends the search: the
// request might be ambiguous, so it is answered as unavailable (503), not
// with the other session.
func TestAmbiguityCheckStopsAtAnUnavailableValidator(t *testing.T) {
	t.Parallel()

	var down string

	mgr := newManager(t, session.WithValidator(func(_ context.Context, s *session.Session) error {
		if s.ID == down {
			return security.ErrUnavailable
		}

		return nil
	}))
	name := mgr.CookieName()

	login := func(sub string) (string, string) {
		c := newCarrier()
		s, err := mgr.Login(context.Background(), c, principal{sub: sub})
		require.NoError(t, err)

		return s.ID, c.replay().cookies[name]
	}

	unchecked, first := login("alice")
	_, second := login("bob")
	down = unchecked

	c := newCarrier()
	c.cookies[name] = first
	c.more = map[string][]string{name: {second}}

	_, err := mgr.Get(context.Background(), c)
	require.ErrorIs(t, err, security.ErrUnavailable)
}
