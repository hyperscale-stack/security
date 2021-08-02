// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import "crypto/subtle"

// Client information
type Client interface {
	// Client ID
	GetID() string

	// Client secret
	GetSecret() string

	// Base client URI
	GetRedirectURI() string

	// Data to be passed to storage. Not used by the library.
	GetUserData() interface{}
}

// ClientSecretMatcher is an optional interface clients can implement
// which allows them to be the one to determine if a secret matches.
// If a Client implements ClientSecretMatcher, the framework will never call GetSecret
type ClientSecretMatcher interface {
	// SecretMatches returns true if the given secret matches
	SecretMatches(secret string) bool
}

// DefaultClient stores all data in struct variables
type DefaultClient struct {
	ID          string
	Secret      string
	RedirectURI string
	UserData    interface{}
}

func (d *DefaultClient) GetID() string {
	return d.ID
}

func (d *DefaultClient) GetSecret() string {
	return d.Secret
}

func (d *DefaultClient) GetRedirectURI() string {
	return d.RedirectURI
}

func (d *DefaultClient) GetUserData() interface{} {
	return d.UserData
}

// Implement the ClientSecretMatcher interface
func (d *DefaultClient) ClientSecretMatches(secret string) bool {
	return subtle.ConstantTimeCompare([]byte(d.Secret), []byte(secret)) == 1
}

func (d *DefaultClient) CopyFrom(client Client) {
	d.ID = client.GetID()
	d.Secret = client.GetSecret()
	d.RedirectURI = client.GetRedirectURI()
	d.UserData = client.GetUserData()
}
