// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package clientauth

import (
	"context"
	"net/http"

	"github.com/hyperscale-stack/security/oauth2"
)

// NewBasic returns a client_secret_basic authenticator. The client_id and
// client_secret are read from the HTTP Basic Authorization header per
// RFC 6749 §2.3.1.
func NewBasic() ClientAuthenticator { return basicAuth{} }

type basicAuth struct{}

// Method implements [ClientAuthenticator].
func (basicAuth) Method() string { return "client_secret_basic" }

// Match implements [ClientAuthenticator].
func (basicAuth) Match(r *http.Request) bool {
	if r == nil {
		return false
	}

	header := r.Header.Get("Authorization")
	if len(header) < 6 {
		return false
	}

	// Case-insensitive prefix check.
	return header[0] == 'B' || header[0] == 'b'
}

// Authenticate implements [ClientAuthenticator].
func (basicAuth) Authenticate(ctx context.Context, r *http.Request, store oauth2.ClientStore) (oauth2.Client, error) {
	id, secret, ok := decodeBasic(r.Header.Get("Authorization"))
	if !ok {
		return nil, oauth2.ErrInvalidClient.WithDescription("malformed Basic Authorization header")
	}

	client, err := store.LoadClient(ctx, id)
	if err != nil {
		return nil, errInvalid(err)
	}

	if client == nil {
		return nil, oauth2.ErrInvalidClient.WithDescription("unknown client")
	}

	if !allowsMethod(client, "client_secret_basic") {
		return nil, oauth2.ErrInvalidClient.WithDescription("method not allowed for client")
	}

	matcher, ok := client.(oauth2.SecretMatcher)
	if !ok {
		return nil, oauth2.ErrInvalidClient.WithDescription("client cannot verify secret")
	}

	if !matcher.SecretMatches(secret) {
		return nil, errInvalid(errSecretMismatch)
	}

	return client, nil
}
