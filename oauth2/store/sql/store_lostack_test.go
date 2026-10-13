// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	sqlstore "github.com/hyperscale-stack/security/oauth2/store/sql"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// errLostAcknowledgement is what a COMMIT whose acknowledgement was lost
// reports: the transaction is committed, the caller cannot tell.
var errLostAcknowledgement = errors.New("connection lost after COMMIT")

// lostAckConnector serves connections of the SQLite driver whose next
// COMMIT, once lose is set, commits and then reports
// errLostAcknowledgement.
type lostAckConnector struct {
	drv  driver.Driver
	dsn  string
	lose *atomic.Bool
}

func (c lostAckConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.drv.Open(c.dsn)
	if err != nil {
		return nil, err
	}

	return lostAckConn{Conn: conn, lose: c.lose}, nil
}

func (c lostAckConnector) Driver() driver.Driver { return c.drv }

// lostAckConn wraps the transactions of its connection.
type lostAckConn struct {
	driver.Conn
	lose *atomic.Bool
}

func (c lostAckConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, errors.New("lostack: the driver has no BeginTx")
	}

	tx, err := beginner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}

	return lostAckTx{Tx: tx, lose: c.lose}, nil
}

// lostAckTx commits, then loses the acknowledgement when lose is set.
type lostAckTx struct {
	driver.Tx
	lose *atomic.Bool
}

func (t lostAckTx) Commit() error {
	if err := t.Tx.Commit(); err != nil {
		return err
	}

	if t.lose.CompareAndSwap(true, false) {
		return errLostAcknowledgement
	}

	return nil
}

// TestRotationWithALostCommitAcknowledgement pins what the I3 wording of
// oauth2.Storage states: a rotation whose COMMIT succeeded but whose
// acknowledgement was lost fails although every write was applied — an
// unknown outcome is never a partial one — and the client's retry of the
// refresh, which presents the same refresh token, is then a reuse: it
// revokes the family, the replacement issued by the "failed" rotation
// included.
func TestRotationWithALostCommitAcknowledgement(t *testing.T) {
	t.Parallel()

	base, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	lose := new(atomic.Bool)
	db := sql.OpenDB(lostAckConnector{drv: base.Driver(), dsn: ":memory:", lose: lose})
	db.SetMaxOpenConns(1)

	t.Cleanup(func() { _ = db.Close(); _ = base.Close() })

	store, err := sqlstore.New(db, sqlstore.SQLite)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(t.Context()))

	ctx := t.Context()
	first := testPair("lost-0", "fam-lost", time.Hour)
	require.NoError(t, store.SaveTokenPair(ctx, first))

	next := testPair("lost-1", "fam-lost", time.Hour)

	lose.Store(true)
	require.ErrorIs(t, store.RotateRefreshToken(ctx, first.Refresh.TokenHash, next), errLostAcknowledgement)

	// Applied whole: the presented token consumed, its replacement stored.
	rt, err := store.LookupRefreshToken(ctx, first.Refresh.TokenHash)
	require.NoError(t, err)
	require.True(t, rt.Consumed)

	_, err = store.LookupAccessToken(ctx, next.Access.TokenHash)
	require.NoError(t, err)

	rt, err = store.LookupRefreshToken(ctx, next.Refresh.TokenHash)
	require.NoError(t, err)
	require.False(t, rt.Consumed)

	// The client retries with the token it presented: a reuse.
	retry := testPair("lost-2", "fam-lost", time.Hour)
	require.ErrorIs(t, store.RotateRefreshToken(ctx, first.Refresh.TokenHash, retry), oauth2.ErrRefreshTokenReused)

	_, err = store.LookupAccessToken(ctx, next.Access.TokenHash)
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)
}
