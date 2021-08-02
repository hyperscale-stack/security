// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "time"

// AccessInfo represents an access grant (tokens, expiration, client, etc)
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

// IsExpired returns true if access expired
func (i *AccessInfo) IsExpired() bool {
	return i.IsExpiredAt(time.Now())
}

// IsExpiredAt returns true if access expires at time 't'
func (i *AccessInfo) IsExpiredAt(t time.Time) bool {
	return i.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (i *AccessInfo) ExpireAt() time.Time {
	return i.CreatedAt.Add(time.Duration(i.ExpiresIn) * time.Second)
}
