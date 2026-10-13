// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errRevoked = errors.New("session revoked")

// denyList is a server-side revocation list keyed by session ID.
type denyList struct {
	mu      sync.Mutex
	revoked map[string]bool
	down    bool
	seen    []*session.Session
}

func (d *denyList) check(_ context.Context, s *session.Session) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.seen = append(d.seen, s)

	switch {
	case d.down:
		return fmt.Errorf("deny-list store: %w", security.ErrUnavailable)
	case d.revoked[s.ID]:
		return errRevoked
	}

	return nil
}

// Review decision Q4 (audit CORE-08, "logout is client-side only"): a
// stateless session could not be revoked before its cookie expired; a stolen
// copy outlived Logout. WithValidator lets the application check every
// decoded session against its own store (a deny-list written at logout,
// "sessions created before T" after a password change).
func TestWithValidatorRevokesSessions(t *testing.T) {
	t.Parallel()

	list := &denyList{revoked: map[string]bool{}}
	mgr := newManager(t, session.WithValidator(list.check))

	c := newCarrier()
	s, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	stolen := c.replay()

	got, err := mgr.Get(context.Background(), stolen)
	require.NoError(t, err, "not revoked yet")
	assert.Equal(t, "alice", got.GetString("sub"))

	list.revoked[s.ID] = true

	_, err = mgr.Get(context.Background(), stolen)
	require.ErrorIs(t, err, session.ErrNoSession)
	require.ErrorIs(t, err, errRevoked, "the cause stays in the chain")

	_, err = mgr.Rotate(context.Background(), stolen)
	require.ErrorIs(t, err, errRevoked, "a revoked session cannot be rotated into a fresh one")

	auth, err := session.NewExtractor(mgr).Extract(context.Background(), stolen)
	require.NoError(t, err)
	assert.Nil(t, auth, "a revoked session authenticates nobody")

	require.Len(t, list.seen, 4)
	assert.Equal(t, s.ID, list.seen[0].ID, "the validator sees the decoded session")
	assert.True(t, list.seen[0].CreatedAt.Equal(s.CreatedAt))
}

// Review finding 8: an outage of the revocation store must not log every
// user out silently: the error wraps security.ErrUnavailable and the
// transports answer 503.
func TestWithValidatorUnavailableIsNotALogout(t *testing.T) {
	t.Parallel()

	list := &denyList{down: true}
	mgr := newManager(t, session.WithValidator(list.check))

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	_, err = mgr.Get(context.Background(), c.replay())
	require.ErrorIs(t, err, security.ErrUnavailable)
	assert.NotErrorIs(t, err, session.ErrNoSession)

	auth, err := session.NewExtractor(mgr).Extract(context.Background(), c.replay())
	require.ErrorIs(t, err, security.ErrUnavailable, "the extractor reports the outage instead of 'no session'")
	assert.Nil(t, auth)

	engine := security.NewEngine(security.NewManager(session.NewAuthenticator(stubLoader{})), session.NewExtractor(mgr))

	_, out, err := engine.Process(context.Background(), c.replay())
	require.Error(t, err)
	assert.Equal(t, security.ErrorClassUnavailable, security.ErrorClass(err), "HTTP 503 / gRPC Unavailable")
	assert.False(t, out.IsAuthenticated())
}

// The validator runs after the expiry checks: an expired session never
// reaches it.
func TestWithValidatorRunsOnLiveSessionsOnly(t *testing.T) {
	t.Parallel()

	now := epoch
	list := &denyList{revoked: map[string]bool{}}
	mgr := clockedManager(t, &now, session.WithTTL(time.Hour), session.WithValidator(list.check))

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	now = epoch.Add(2 * time.Hour)

	_, err = mgr.Get(context.Background(), c.replay())
	require.ErrorIs(t, err, security.ErrTokenExpired)
	assert.Empty(t, list.seen)
}

func TestWithValidatorRefusesNil(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { session.WithValidator(nil) })
}
