// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import "context"

/*
// Context struct
type Context struct {
	authentications []Authentication
}

// NewContext constructor
func NewContext() *Context {
	return &Context{
		authentications: []Authentication{},
	}
}

// AddAuthentication to context
func (c *Context) AddAuthentication(authentication Authentication) {
	c.authentications = append(c.authentications, authentication)
}
*/

type authenticationCtxKey struct{}

// FromContext returns the Authentication associated with the ctx.
func FromContext(ctx context.Context) Authentication {
	if a, ok := ctx.Value(authenticationCtxKey{}).(Authentication); ok {
		return a
	}

	return nil
}

// ToContext returns new context with Authentication
func ToContext(ctx context.Context, authentication Authentication) context.Context {
	return context.WithValue(ctx, authenticationCtxKey{}, authentication)
}
