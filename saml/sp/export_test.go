// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

// WaitMetadataFetch waits for the fetch s has in flight, if any: a test
// can then observe a refresh that IdentityProvider started without waiting.
func WaitMetadataFetch(s *MetadataSource) {
	s.mu.Lock()
	call := s.inflight
	s.mu.Unlock()

	if call != nil {
		<-call.done
	}
}
