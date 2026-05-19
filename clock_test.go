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

func TestDefaultClockIsSystemClock(t *testing.T) {
	t.Parallel()

	_, ok := security.DefaultClock.(security.SystemClock)
	assert.True(t, ok, "DefaultClock should be a SystemClock value")
}
