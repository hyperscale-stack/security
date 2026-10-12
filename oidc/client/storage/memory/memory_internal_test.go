// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func internalTransaction(seed string, created time.Time, ttl time.Duration) *oidcclient.Transaction {
	sum := func(s string) string {
		h := sha256.Sum256([]byte(s))

		return hex.EncodeToString(h[:])
	}

	return &oidcclient.Transaction{
		StateHash: sum("state-" + seed), BindingHash: sum("binding-" + seed), Integrity: sum("integrity-" + seed),
		ConnectionID: "acme", Issuer: "https://idp.example.com", ClientID: "client-1",
		RedirectURI: "https://rp.example.com/callback", ResponseMode: oidcclient.ResponseModeQuery,
		MaxAge: oidcclient.NoMaxAge, CreatedAt: created, ExpiresAt: created.Add(ttl),
	}
}

// TestFullStoreRefusesWithoutWalking checks that a store full of live
// transactions — the flood WithCapacity is about — refuses in constant
// time: neither the refusals nor the periodic sweep walk the map while no
// transaction can have expired, and the first save past the earliest
// expiry walks it exactly once.
func TestFullStoreRefusesWithoutWalking(t *testing.T) {
	t.Parallel()

	const capacity = 100

	s := New(WithCapacity(capacity))
	start := time.Unix(1_800_000_000, 0).UTC()

	for i := range capacity {
		require.NoError(t, s.Save(context.Background(), internalTransaction("live-"+strconv.Itoa(i), start, 10*time.Minute)))
	}

	for i := range 1_000 {
		err := s.Save(context.Background(), internalTransaction("flood-"+strconv.Itoa(i), start.Add(time.Minute), 10*time.Minute))
		require.ErrorIs(t, err, ErrFull)
	}

	assert.Zero(t, s.sweeps, "no walk while nothing can have expired")

	require.NoError(t, s.Save(context.Background(), internalTransaction("later", start.Add(10*time.Minute), 10*time.Minute)),
		"past the earliest expiry, the expired transactions make room")
	assert.Equal(t, 1, s.sweeps, "one walk")
	assert.Equal(t, 1, s.Len())
}

// TestNextExpiryFollowsTheRemainingTransactions checks that a sweep sets
// the next expiry from the transactions it keeps: a full store drops each
// of them as soon as it expires.
func TestNextExpiryFollowsTheRemainingTransactions(t *testing.T) {
	t.Parallel()

	s := New(WithCapacity(3))
	t0 := time.Unix(1_800_000_000, 0).UTC()

	require.NoError(t, s.Save(context.Background(), internalTransaction("x1", t0, time.Minute)))
	require.NoError(t, s.Save(context.Background(), internalTransaction("x2", t0, 5*time.Minute)))
	require.NoError(t, s.Save(context.Background(), internalTransaction("x3", t0, 3*time.Minute)))

	require.NoError(t, s.Save(context.Background(), internalTransaction("y", t0.Add(time.Minute), 10*time.Minute)),
		"x1 expired: dropped")
	require.ErrorIs(t, s.Save(context.Background(), internalTransaction("early", t0.Add(2*time.Minute), 10*time.Minute)), ErrFull)
	require.NoError(t, s.Save(context.Background(), internalTransaction("z", t0.Add(3*time.Minute), 10*time.Minute)),
		"x3 expired: dropped, although y expires later")
	assert.Equal(t, 2, s.sweeps)
}
