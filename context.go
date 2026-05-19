// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import "context"

// authCtxKey is the private key used to store an [Authentication] in a
// context.Context. The unexported type guarantees that no other package can
// shadow or read the value without going through the accessors below.
type authCtxKey struct{}

// WithAuthentication returns a copy of ctx with auth attached. Subsequent
// calls overwrite the previous value; this is the expected behavior when an
// authenticator promotes an unauthenticated value to an authenticated one.
//
// Passing a nil Authentication clears the slot — useful for "logout"
// middlewares.
func WithAuthentication(ctx context.Context, auth Authentication) context.Context {
	return context.WithValue(ctx, authCtxKey{}, auth)
}

// FromContext returns the [Authentication] stored in ctx and a boolean
// indicating whether one was present. When the slot is empty, it returns
// the anonymous authentication (see [Anonymous]) so callers can rely on a
// non-nil value without a nil check.
func FromContext(ctx context.Context) (Authentication, bool) {
	v, ok := ctx.Value(authCtxKey{}).(Authentication)
	if !ok || v == nil {
		return Anonymous(), false
	}

	return v, true
}
