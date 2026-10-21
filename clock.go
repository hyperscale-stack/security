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

// SystemClock is the Clock returning time.Now(): the default of every
// component that takes a Clock. Its zero value is ready to use; there is no
// package-level Clock variable a test could replace for the whole process.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }
