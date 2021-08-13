// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"net/http"
	"regexp"
	"time"
)

// AuthorizeRequestType is the type for OAuth param `response_type`
type AuthorizeRequestType string

const (
	CODE  AuthorizeRequestType = "code"
	TOKEN AuthorizeRequestType = "token"

	PKCE_PLAIN = "plain"
	PKCE_S256  = "S256"
)

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
)

// Authorize request information
type AuthorizeRequest struct {
	Type        AuthorizeRequestType
	Client      Client
	Scope       string
	RedirectUri string
	State       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default.
	// If type = TOKEN, this expiration will be for the ACCESS token.
	Expiration int32

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request

	// Optional code_challenge as described in rfc7636
	CodeChallenge string
	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string
}

// AuthorizeData info.
type AuthorizeData struct {
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
func (i *AuthorizeData) IsExpired() bool {
	return i.IsExpiredAt(time.Now())
}

// IsExpired is true if authorization expires at time 't'.
func (i *AuthorizeData) IsExpiredAt(t time.Time) bool {
	return i.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date.
func (i *AuthorizeData) ExpireAt() time.Time {
	return i.CreatedAt.Add(time.Duration(i.ExpiresIn) * time.Second)
}
