// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"time"
)

type AccessToken interface {
	GetClient() Client
	GetToken() string
	IsExpired() bool
	GetUserID() string
}

type accessCtxKey struct{}

// AccessTokenFromContext returns the Access Token info associated with the ctx.
func AccessTokenFromContext(ctx context.Context) *AccessInfo {
	if a, ok := ctx.Value(accessCtxKey{}).(*AccessInfo); ok {
		return a
	}

	return nil
}

// AccessTokenToContext returns new context with Access Token info.
func AccessTokenToContext(ctx context.Context, access *AccessInfo) context.Context {
	return context.WithValue(ctx, accessCtxKey{}, access)
}

// AccessInfo represents an access grant (tokens, expiration, client, etc).
type AccessInfo struct {
	// Client information
	Client Client

	// Authorize data, for authorization code
	AuthorizeData *AuthorizeInfo

	// Previous access data, for refresh token
	AccessInfo *AccessInfo

	// Access token
	AccessToken string

	// Refresh Token. Can be blank
	RefreshToken string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect URI from request
	RedirectURI string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

// IsExpired returns true if access expired.
func (i *AccessInfo) IsExpired() bool {
	return i.IsExpiredAt(time.Now())
}

// IsExpiredAt returns true if access expires at time 't'.
func (i *AccessInfo) IsExpiredAt(t time.Time) bool {
	return i.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date.
func (i *AccessInfo) ExpireAt() time.Time {
	return i.CreatedAt.Add(time.Duration(i.ExpiresIn) * time.Second)
}
