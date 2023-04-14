// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/http/header"
)

var (
	ErrInvalidAuthorizationHeader  = errors.New("invalid authorization header")
	ErrInvalidAuthorizationMessage = errors.New("invalid authorization message")
	ErrClientAuthenticationNotSent = errors.New("Client authentication not sent")
)

// Parse basic authentication header.
type BasicAuth struct {
	Username string
	Password string
}

// Parse bearer authentication header.
type BearerAuth struct {
	Code string
}

// CheckClientSecret determines whether the given secret matches a secret held by the client.
// Public clients return true for a secret of "".
func CheckClientSecret(client Client, secret string) bool {
	switch client := client.(type) {
	case ClientSecretMatcher:
		// Prefer the more secure method of giving the secret to the client for comparison
		return client.SecretMatches(secret)
	default:
		// Fallback to the less secure method of extracting the plain text secret from the client for comparison
		return subtle.ConstantTimeCompare([]byte(client.GetSecret()), []byte(secret)) == 1
	}
}

// Return authorization header data.
func CheckBasicAuth(r *http.Request) (*BasicAuth, error) {
	if r.Header.Get("Authorization") == "" {
		return nil, nil
	}

	b64, ok := header.ExtractAuthorizationValue("Basic", r.Header.Get("Authorization"))
	if !ok {
		return nil, ErrInvalidAuthorizationHeader
	}

	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode basic auth failed: %w", err)
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return nil, ErrInvalidAuthorizationMessage
	}

	// Decode the client_id and client_secret pairs as per
	// https://tools.ietf.org/html/rfc6749#section-2.3.1

	username, err := url.QueryUnescape(pair[0])
	if err != nil {
		return nil, fmt.Errorf("unescape username failed: %w", err)
	}

	password, err := url.QueryUnescape(pair[1])
	if err != nil {
		return nil, fmt.Errorf("unescape password failed: %w", err)
	}

	return &BasicAuth{Username: username, Password: password}, nil
}

// Return "Bearer" token from request. The header has precedence over query string.
func CheckBearerAuth(r *http.Request) *BearerAuth {
	authHeader := r.Header.Get("Authorization")
	authForm := r.FormValue("code")

	if authHeader == "" && authForm == "" {
		return nil
	}

	token := authForm

	if authHeader != "" {
		v, ok := header.ExtractAuthorizationValue("Bearer", authHeader)
		if !ok {
			return nil
		}

		token = v
	}

	return &BearerAuth{Code: token}
}

// getClientAuth checks client basic authentication in params if allowed,
// otherwise gets it from the header.
// Sets an error on the response if no auth is present or a server error occurs.
func (s Server) getClientAuth(w *Response, r *http.Request, allowQueryParams bool) *credential.UsernamePasswordCredential {
	ctx := r.Context()

	// creds := credential.FromContext(ctx)

	if allowQueryParams {
		// Allow for auth without password
		if _, hasSecret := r.Form["client_secret"]; hasSecret {
			auth := credential.NewUsernamePasswordCredential(
				r.FormValue("client_id"),
				r.FormValue("client_secret"),
			)

			if auth.GetPrincipal() != "" {
				return auth
			}
		}
	}

	auth := credential.FromContext(ctx)
	if auth == nil {
		s.setErrorAndLog(w, E_INVALID_REQUEST, ErrClientAuthenticationNotSent, "get_client_auth=%s", "client authentication not sent")

		return nil
	}

	return auth.(*credential.UsernamePasswordCredential)
}
