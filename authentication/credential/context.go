// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package credential

import "context"

type credentialCtxKey struct{}

// FromContext returns the Credential associated with the ctx.
func FromContext(ctx context.Context) Credential {
	if c, ok := ctx.Value(credentialCtxKey{}).(Credential); ok {
		return c
	}

	return nil
}

// ToContext returns new context with Credential
func ToContext(ctx context.Context, creds Credential) context.Context {
	return context.WithValue(ctx, credentialCtxKey{}, creds)
}
