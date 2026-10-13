// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"encoding/json"
	"math"
	"testing"

	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTrip writes s with Touch and reads it back from the cookie.
func roundTrip(t *testing.T, mgr *session.Manager, s *session.Session) *session.Session {
	t.Helper()

	c := newCarrier()
	require.NoError(t, mgr.Touch(context.Background(), c, s))

	got, err := mgr.Get(context.Background(), c.replay())
	require.NoError(t, err)

	return got
}

// Audit CORE-14 (probe TestZZAuditSessionNumericValues): session values were
// decoded into float64, so 1234567890123456789 came back as
// 1234567890123456768 — a 64-bit user ID mapped to another account. Decision
// 10: numbers are decoded without precision loss (json.Number).
func TestSessionValuesKeepIntegerPrecision(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	s, err := mgr.Login(context.Background(), newCarrier(), principal{sub: "alice"})
	require.NoError(t, err)

	s.Values["uid"] = int64(1234567890123456789)
	s.Values["max"] = int64(math.MaxInt64)
	s.Values["min"] = int64(math.MinInt64)
	s.Values["ratio"] = 1.5
	s.Values["nested"] = map[string]any{"ids": []any{int64(9007199254740993)}}

	got := roundTrip(t, mgr, s)

	assert.Equal(t, json.Number("1234567890123456789"), got.Values["uid"])
	assert.Equal(t, json.Number("1.5"), got.Values["ratio"])

	for key, want := range map[string]int64{"uid": 1234567890123456789, "max": math.MaxInt64, "min": math.MinInt64} {
		n, ok := got.GetInt64(key)
		require.True(t, ok, key)
		assert.Equal(t, want, n, key)
	}

	nested, ok := got.Values["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{json.Number("9007199254740993")}, nested["ids"], "2^53+1 survives at any depth")

	again := roundTrip(t, mgr, got)
	n, ok := again.GetInt64("uid")
	require.True(t, ok)
	assert.Equal(t, int64(1234567890123456789), n, "a json.Number is written back verbatim")
}

func TestGetInt64(t *testing.T) {
	t.Parallel()

	s := &session.Session{Values: map[string]any{
		"int":      42,
		"int8":     int8(-1),
		"int16":    int16(-2),
		"int32":    int32(8),
		"int64":    int64(-7),
		"uint":     uint(11),
		"uint8":    uint8(3),
		"uint16":   uint16(4),
		"uint32":   uint32(9),
		"uint64":   uint64(10),
		"hugeU":    uint(math.MaxUint64),
		"hugeU64":  uint64(math.MaxUint64),
		"number":   json.Number("123"),
		"float":    json.Number("1.5"),
		"overflow": json.Number("9223372036854775808"),
		"string":   "123",
		"float64":  2.0,
	}}

	for key, want := range map[string]int64{
		"int": 42, "int8": -1, "int16": -2, "int32": 8, "int64": -7,
		"uint": 11, "uint8": 3, "uint16": 4, "uint32": 9, "uint64": 10, "number": 123,
	} {
		got, ok := s.GetInt64(key)
		assert.True(t, ok, key)
		assert.Equal(t, want, got, key)
	}

	for _, key := range []string{"absent", "hugeU", "hugeU64", "float", "overflow", "string", "float64"} {
		_, ok := s.GetInt64(key)
		assert.False(t, ok, key)
	}

	var empty session.Session

	_, ok := empty.GetInt64("x")
	assert.False(t, ok)
}

// A decoded session always has a Values map the application can write to.
func TestDecodedSessionHasValues(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	_, err := mgr.Login(context.Background(), c, nil)
	require.NoError(t, err)

	got, err := mgr.Get(context.Background(), c.replay())
	require.NoError(t, err)
	require.NotNil(t, got.Values)

	got.Values["k"] = "v" // no panic
}

// A value encoding/json cannot serialize (a channel, a function) fails the
// write: nothing is staged.
func TestTouchReportsAnUnserializableValue(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	s, err := mgr.Login(context.Background(), newCarrier(), principal{sub: "alice"})
	require.NoError(t, err)

	s.Values["bad"] = make(chan int)

	c := newCarrier()
	require.Error(t, mgr.Touch(context.Background(), c, s))
	assert.Empty(t, c.setCookies)
}
