// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package memory_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

func transaction(seed string, created time.Time, ttl time.Duration) *oidcclient.Transaction {
	return &oidcclient.Transaction{
		StateHash:    hash("state-" + seed),
		BindingHash:  hash("binding-" + seed),
		ConnectionID: "acme",
		Issuer:       "https://idp.example.com",
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/callback",
		ResponseMode: oidcclient.ResponseModeQuery,
		MaxAge:       oidcclient.NoMaxAge,
		CreatedAt:    created,
		ExpiresAt:    created.Add(ttl),
	}
}

// TestSweepExpired checks that abandoned logins do not accumulate: expired
// transactions are swept while new ones are saved, without any Consume.
func TestSweepExpired(t *testing.T) {
	t.Parallel()

	s := memory.New()
	start := time.Unix(1_800_000_000, 0).UTC()

	for i := range 200 {
		require.NoError(t, s.Save(context.Background(), transaction("old-"+strconv.Itoa(i), start, time.Minute)))
	}

	later := start.Add(time.Hour)

	for i := range 200 {
		require.NoError(t, s.Save(context.Background(), transaction("new-"+strconv.Itoa(i), later, time.Minute)))
	}

	assert.LessOrEqual(t, s.Len(), 264, "the expired transactions are swept by later saves")
	assert.GreaterOrEqual(t, s.Len(), 200, "live transactions are kept")
}

// TestSaveKeepsACopy checks that the store does not alias the caller's
// transaction.
func TestSaveKeepsACopy(t *testing.T) {
	t.Parallel()

	s := memory.New()
	now := time.Unix(1_800_000_000, 0).UTC()
	tx := transaction("copy", now, time.Minute)

	require.NoError(t, s.Save(context.Background(), tx))

	tx.ConnectionID = "tampered"

	got, err := s.Consume(context.Background(), hash("state-copy"), hash("binding-copy"), now)
	require.NoError(t, err)
	assert.Equal(t, "acme", got.ConnectionID)
}
