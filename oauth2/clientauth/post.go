// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package clientauth

import (
	"context"
	"net/http"

	"github.com/hyperscale-stack/security/oauth2"
)

// NewPost returns a client_secret_post authenticator. The client_id and
// client_secret are read from the form body per RFC 6749 §2.3.1
// (the variant some legacy clients use instead of HTTP Basic).
//
// The form MUST have been parsed by the time Authenticate runs; the
// OAuth2 server calls ParseForm before consulting any authenticator.
func NewPost() ClientAuthenticator { return postAuth{} }

type postAuth struct{}

// Method implements [ClientAuthenticator].
func (postAuth) Method() string { return "client_secret_post" }

// Match implements [ClientAuthenticator]. We claim the request when
// client_id+client_secret are present in the form and no Authorization
// header is set; this lets Basic take precedence when both are supplied.
func (postAuth) Match(r *http.Request) bool {
	if r == nil {
		return false
	}

	if r.Header.Get("Authorization") != "" {
		return false
	}

	return r.PostFormValue("client_id") != "" && r.PostFormValue("client_secret") != ""
}

// Authenticate implements [ClientAuthenticator].
func (postAuth) Authenticate(ctx context.Context, r *http.Request, store oauth2.ClientStore) (oauth2.Client, error) {
	id := r.PostFormValue("client_id")
	secret := r.PostFormValue("client_secret")

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

	if !allowsMethod(client, "client_secret_post") {
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
