// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import "time"

// Clock abstracts time.Now to make time-sensitive code (expiry checks, TTLs,
// token rotation windows) deterministic in tests. Implementations MUST be
// safe for concurrent use.
type Clock interface {
	Now() time.Time
}

// SystemClock is the default Clock returning time.Now().
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

// DefaultClock is the package-level Clock used when none is supplied via
// configuration. It is a value, not a pointer, so it is safe to copy.
var DefaultClock Clock = SystemClock{}
