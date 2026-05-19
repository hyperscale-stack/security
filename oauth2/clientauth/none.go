// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package clientauth

import (
	"context"
	"net/http"

	"github.com/hyperscale-stack/security/oauth2"
)

// NewNone returns the "none" client-authentication method (OpenID Connect
// Core §9). The client identifies itself via the client_id form parameter
// but presents no secret; authentication relies on PKCE alone. This method
// is meant for public clients (browser apps, native mobile apps).
//
// The server MUST reject confidential clients trying to use "none"; the
// grant handler enforces PKCE separately.
func NewNone() ClientAuthenticator { return noneAuth{} }

type noneAuth struct{}

// Method implements [ClientAuthenticator].
func (noneAuth) Method() string { return "none" }

// Match implements [ClientAuthenticator]. A bare client_id in the form
// without a secret is the signal.
func (noneAuth) Match(r *http.Request) bool {
	if r == nil {
		return false
	}

	if r.Header.Get("Authorization") != "" {
		return false
	}

	return r.PostFormValue("client_id") != "" && r.PostFormValue("client_secret") == ""
}

// Authenticate implements [ClientAuthenticator].
func (noneAuth) Authenticate(ctx context.Context, r *http.Request, store oauth2.ClientStore) (oauth2.Client, error) {
	id := r.PostFormValue("client_id")
	if id == "" {
		return nil, oauth2.ErrInvalidClient.WithDescription("missing client_id")
	}

	client, err := store.LoadClient(ctx, id)
	if err != nil {
		return nil, errInvalid(err)
	}

	if client == nil {
		return nil, oauth2.ErrInvalidClient.WithDescription("unknown client")
	}

	if client.Type() != oauth2.ClientPublic {
		return nil, oauth2.ErrInvalidClient.WithDescription(`"none" reserved to public clients`)
	}

	if !allowsMethod(client, "none") {
		return nil, oauth2.ErrInvalidClient.WithDescription("method not allowed for client")
	}

	return client, nil
}
