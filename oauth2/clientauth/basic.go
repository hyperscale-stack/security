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
// RFC 6749 §2.3.1: each is form-urlencoded by the client (Appendix B) and
// form-decoded here — "+" is a space, "%XX" a byte — so a client sending a
// secret holding "%" or "+" unencoded is answered invalid_client, and
// malformed encoding is refused before the client is loaded.
//
// A header whose decoded client_id or client_secret is empty, such as
// Basic base64("<client_id>:"), is refused with invalid_client before the
// client is loaded, as [NewPost] refuses an empty client_secret. A public
// client authenticates with [NewNone] instead (RFC 7591 §2: "none" is the
// method of a public client that has no secret).
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

	// A missing client_id or an empty password is no credential: refuse it
	// before the store is consulted, like client_secret_post, so the answer
	// does not depend on the client existing (RFC 6749 §2.3 lets the server
	// choose the client authentication it accepts).
	if id == "" || secret == "" {
		return nil, oauth2.ErrInvalidClient.WithDescription("missing client_id or client_secret")
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
