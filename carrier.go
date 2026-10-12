// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import "fmt"

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
//
// Get and Values read the transport's header fields (HTTP headers, gRPC
// metadata) and nothing else: an implementation MUST NOT fall back to the
// URL query string or to cookies, so that a credential is accepted only from
// the field its scheme defines and never leaks through URLs (RFC 6750 §5.3).
type Carrier interface {
	// Get returns the first value of the header field key, or the empty
	// string if absent. Keys are case-insensitive in the HTTP sense.
	Get(key string) string

	// Values returns all values of the header field key, or a nil slice if
	// absent. The caller MUST NOT mutate the returned slice.
	Values(key string) []string

	// Set replaces all values associated with the given key.
	Set(key, value string)

	// Add appends a value to the list associated with the given key.
	Add(key, value string)
}

// SingleValue returns the value of the singleton header field key carried by
// c — "" when the field is absent — and an error wrapping [ErrInvalidRequest]
// when the field occurs more than once. RFC 9110 §5.3 forbids a sender to
// repeat a field that is not a list, such as Authorization (§11.6.2), and
// §5.5 notes that detecting such errors improves interoperability; reading
// the first value instead would let a second credential slip past a
// component that checked the other one. Extractors read singleton credential
// fields through it.
func SingleValue(c Carrier, key string) (string, error) {
	values := c.Values(key)

	switch len(values) {
	case 0:
		return "", nil
	case 1:
		return values[0], nil
	default:
		return "", fmt.Errorf("security: header field %q occurs %d times: %w", key, len(values), ErrInvalidRequest)
	}
}
