// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

// Carrier abstracts a transport-level message (an HTTP request, gRPC metadata,
// a queue envelope) from which credentials can be read and security artifacts
// (challenges, cookies, headers) can be written.
//
// The interface mimics http.Header semantics so that the HTTP adapter is a
// thin wrapper. For transports that do not naturally support multi-valued
// keys (e.g. websocket frames), implementations MAY collapse Values() to a
// single-element slice and treat Add() as Set().
//
// Implementations MUST be safe for concurrent reads but MAY require external
// synchronization for writes — adapters are expected to wrap a request scope,
// which is serial by construction.
type Carrier interface {
	// Get returns the first value associated with the given key, or the
	// empty string if absent. Keys are case-insensitive in the HTTP sense.
	Get(key string) string

	// Values returns all values associated with the given key, or a nil
	// slice if absent. The caller MUST NOT mutate the returned slice.
	Values(key string) []string

	// Set replaces all values associated with the given key.
	Set(key, value string)

	// Add appends a value to the list associated with the given key.
	Add(key, value string)
}
