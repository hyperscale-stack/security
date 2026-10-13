// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import "time"

// SetRemoteJWKSClock replaces the clock of a provider built by
// NewRemoteJWKS. Call it before the provider's first use.
func SetRemoteJWKSClock(p JWKSProvider, now func() time.Time) { p.(*remoteJWKS).now = now }

// SetRemoteJWKSFetchTimeout replaces the fetch timeout of a provider built
// by NewRemoteJWKS. Call it before the provider's first use.
func SetRemoteJWKSFetchTimeout(p JWKSProvider, d time.Duration) { p.(*remoteJWKS).timeout = d }

// RemoteJWKSIdle reports whether no fetch of p is in flight.
func RemoteJWKSIdle(p JWKSProvider) bool {
	r, _ := p.(*remoteJWKS)

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.inflight == nil
}

// TypedNilVerifier is a nil *verifier in a Verifier: only the package can
// build one.
var TypedNilVerifier Verifier = (*verifier)(nil)
