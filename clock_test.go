// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/assert"
)

func TestSystemClockReturnsCurrentTime(t *testing.T) {
	t.Parallel()

	clock := security.SystemClock{}
	before := time.Now()
	got := clock.Now()
	after := time.Now()

	assert.False(t, got.Before(before), "Now() must not predate the call site")
	assert.False(t, got.After(after), "Now() must not postdate the call site")
}

// Audit I-32: DefaultClock was an exported variable — the default clock of
// jwtsec — that a leaked test override froze process-wide. It is gone: the
// zero SystemClock is the default, and a value type cannot be reassigned.
func TestSystemClockIsAValue(t *testing.T) {
	t.Parallel()

	var clock security.Clock = security.SystemClock{}

	_, ok := clock.(security.SystemClock)
	assert.True(t, ok)
}
