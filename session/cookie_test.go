// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// headerOnlyCarrier is a security.Carrier without cookie access: Get and
// Values answer the same value for every field.
type headerOnlyCarrier struct{ value string }

func (c headerOnlyCarrier) Get(string) string      { return c.value }
func (c headerOnlyCarrier) Values(string) []string { return []string{c.value} }
func (headerOnlyCarrier) Set(string, string)       {}
func (headerOnlyCarrier) Add(string, string)       {}

// loginValue mints a session for sub and returns its cookie value.
func loginValue(t *testing.T, mgr *session.Manager, sub string) string {
	t.Helper()

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: sub})
	require.NoError(t, err)

	value := c.replay().cookies[mgr.CookieName()]
	require.NotEmpty(t, value)

	return value
}

// Audit CORE-02 / decision 6 (probe TestZZAuditSessionFromQueryAndHeader):
// the Manager read its cookie through Carrier.Get, so a session was accepted
// from ?session=… and from a "Session" header, which even beat the victim's
// real cookie — login CSRF and session swapping.
func TestManagerReadsTheSessionFromItsCookieOnly(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)
	attacker := loginValue(t, mgr, "attacker")
	victim := loginValue(t, mgr, "victim")

	headerOnly := newCarrier()
	headerOnly.headers[mgr.CookieName()] = attacker
	headerOnly.headers["Session"] = attacker

	_, err := mgr.Get(context.Background(), headerOnly)
	require.ErrorIs(t, err, session.ErrNoSession, "a header named like the cookie is not the cookie")

	both := newCarrier()
	both.cookies[mgr.CookieName()] = victim
	both.headers["Session"] = attacker
	both.headers[mgr.CookieName()] = attacker

	s, err := mgr.Get(context.Background(), both)
	require.NoError(t, err)
	assert.Equal(t, "victim", s.GetString("sub"))
}

func TestManagerFailsClosedWithoutCookieReader(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	_, err := mgr.Get(context.Background(), headerOnlyCarrier{value: loginValue(t, mgr, "attacker")})

	require.ErrorIs(t, err, session.ErrNoSession)
	assert.Contains(t, err.Error(), "carrier")
}

func TestRotateAndExtractIgnoreASessionOutsideTheCookie(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)
	carrier := newCarrier()
	carrier.headers[mgr.CookieName()] = loginValue(t, mgr, "attacker")

	_, err := mgr.Rotate(context.Background(), carrier)
	require.ErrorIs(t, err, session.ErrNoSession)

	auth, err := session.NewExtractor(mgr).Extract(context.Background(), carrier)
	require.NoError(t, err)
	assert.Nil(t, auth)
}
