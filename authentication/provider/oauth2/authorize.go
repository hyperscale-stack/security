// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "time"

// AuthorizeInfo info.
type AuthorizeInfo struct {
	// Client information
	Client Client

	// Authorization code
	Code string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectURI string

	// State data from request
	State string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// Optional code_challenge as described in rfc7636
	CodeChallenge string

	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}

// IsExpired is true if authorization expired.
func (i *AuthorizeInfo) IsExpired() bool {
	return i.IsExpiredAt(time.Now())
}

// IsExpired is true if authorization expires at time 't'.
func (i *AuthorizeInfo) IsExpiredAt(t time.Time) bool {
	return i.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date.
func (i *AuthorizeInfo) ExpireAt() time.Time {
	return i.CreatedAt.Add(time.Duration(i.ExpiresIn) * time.Second)
}
