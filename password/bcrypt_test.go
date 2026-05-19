// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package password_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/hyperscale-stack/security/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBCryptRoundTrip(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4) // MinCost for fast tests

	encoded, err := h.Hash(context.Background(), "p4ssw0rd")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(encoded, "$2"), "got %q", encoded)

	ok, err := h.Verify(context.Background(), encoded, "p4ssw0rd")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBCryptMismatchReturnsFalseNilError(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4)
	encoded, _ := h.Hash(context.Background(), "correct")

	ok, err := h.Verify(context.Background(), encoded, "wrong")
	require.NoError(t, err, "mismatch must not surface as an error")
	assert.False(t, ok)
}

func TestBCryptVerifyRejectsNonBCryptHash(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4)

	_, err := h.Verify(context.Background(), "not-a-bcrypt", "anything")
	assert.ErrorIs(t, err, password.ErrUnsupportedAlgorithm)
}

func TestBCryptNeedsRehash(t *testing.T) {
	t.Parallel()

	lo := password.NewBCryptHasher(4)
	hi := password.NewBCryptHasher(6)

	encodedLo, _ := lo.Hash(context.Background(), "x")

	assert.False(t, lo.NeedsRehash(encodedLo), "same cost, no rehash needed")
	assert.True(t, hi.NeedsRehash(encodedLo), "stored cost < hi.cost, rehash needed")

	assert.True(t, lo.NeedsRehash("$argon2id$v=19$m=...$xx$yy"),
		"different algorithm always triggers rehash")
	assert.True(t, lo.NeedsRehash("garbage"))
}

func TestBCryptCostClamps(t *testing.T) {
	t.Parallel()

	cases := []struct {
		give, want int
	}{
		{0, 10},  // bcrypt.DefaultCost (x/crypto/bcrypt)
		{3, 4},   // clamp to MinCost
		{50, 31}, // clamp to MaxCost
		{7, 7},
	}
	for _, c := range cases {
		got := password.NewBCryptHasher(c.give).Cost()
		assert.Equal(t, c.want, got, "input %d", c.give)
	}
}

func TestBCryptContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := password.NewBCryptHasher(4).Hash(ctx, "x")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestBCryptIsRaceSafe(t *testing.T) {
	t.Parallel()

	h := password.NewBCryptHasher(4)
	encoded, _ := h.Hash(context.Background(), "x")

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)

		go func() {
			defer wg.Done()
			ok, err := h.Verify(context.Background(), encoded, "x")
			assert.NoError(t, err)
			assert.True(t, ok)
		}()
	}

	wg.Wait()
}
