// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package clientauth ships the client-authentication methods supported by
// the OAuth2 server's /token endpoint per RFC 6749 §2.3 and OpenID Connect
// Core §9.
//
// Methods shipped:
//
//   - client_secret_basic — RFC 6749 §2.3.1 (HTTP Basic)
//   - client_secret_post  — RFC 6749 §2.3.1 (form parameters)
//   - none                — public clients (PKCE-only authentication)
//
// Adding private_key_jwt requires the JWT module; it lives behind a small
// adapter in the jwt sub-module so this package stays JOSE-free.
package clientauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/hyperscale-stack/security/oauth2"
)

// ClientAuthenticator authenticates the OAuth2 client behind an HTTP
// request. The server consults the configured methods in order and uses the
// first one whose Match returns true.
//
// Authenticate MUST return:
//   - (client, nil)                  on success.
//   - (nil, oauth2.ErrInvalidClient) on credential mismatch.
//   - (nil, other)                   on storage / unexpected errors.
type ClientAuthenticator interface {
	// Method returns the RFC 6749 / OIDC method identifier
	// ("client_secret_basic", "client_secret_post", "none",
	// "private_key_jwt"). Used by the server for OTel attribution and
	// metadata publication.
	Method() string

	// Match reports whether r looks like a request intended for this
	// method. Implementations MUST be fast (header inspection); they MUST
	// NOT perform I/O.
	Match(r *http.Request) bool

	// Authenticate runs the method against r and returns the client on
	// success or oauth2.ErrInvalidClient on failure.
	Authenticate(ctx context.Context, r *http.Request, store oauth2.ClientStore) (oauth2.Client, error)
}

// Compile-time guard so future ClientAuthenticator additions never grow a
// nil interface.
var _ ClientAuthenticator = (*basicAuth)(nil)

// allowsMethod reports whether the client is configured for the method.
// An empty AuthMethods() list means "any method".
func allowsMethod(c oauth2.Client, method string) bool {
	all := c.AuthMethods()
	if len(all) == 0 {
		return true
	}

	for _, m := range all {
		if strings.EqualFold(m, method) {
			return true
		}
	}

	return false
}

// errInvalid is a small helper to wrap the storage / matcher error inside
// oauth2.ErrInvalidClient while preserving the cause for telemetry.
func errInvalid(cause error) error {
	if cause == nil {
		return oauth2.ErrInvalidClient
	}

	return oauth2.ErrInvalidClient.WithCause(cause)
}

// decodeBasic decodes a "Basic base64(id:secret)" Authorization header.
// Returns (id, secret, true) on success, ("", "", false) on any malformed
// input; the caller decides what error to surface.
func decodeBasic(header string) (string, string, bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}

	raw, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}

	colon := strings.IndexByte(string(raw), ':')
	if colon < 0 {
		return "", "", false
	}

	return string(raw[:colon]), string(raw[colon+1:]), true
}

// errSecretMismatch is the typed error returned by secret-matcher
// implementations on cleartext or hashed-secret mismatch. It is wrapped in
// oauth2.ErrInvalidClient before being returned to the caller.
var errSecretMismatch = errors.New("clientauth: secret mismatch")
