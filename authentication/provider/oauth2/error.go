// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

type DefaultErrorID string

func (e DefaultErrorID) String() string {
	return string(e)
}

const (
	E_INVALID_REQUEST           DefaultErrorID = "invalid_request"
	E_UNAUTHORIZED_CLIENT       DefaultErrorID = "unauthorized_client"
	E_ACCESS_DENIED             DefaultErrorID = "access_denied"
	E_UNSUPPORTED_RESPONSE_TYPE DefaultErrorID = "unsupported_response_type"
	E_INVALID_SCOPE             DefaultErrorID = "invalid_scope"
	E_SERVER_ERROR              DefaultErrorID = "server_error"
	E_TEMPORARILY_UNAVAILABLE   DefaultErrorID = "temporarily_unavailable"
	E_UNSUPPORTED_GRANT_TYPE    DefaultErrorID = "unsupported_grant_type"
	E_INVALID_GRANT             DefaultErrorID = "invalid_grant"
	E_INVALID_CLIENT            DefaultErrorID = "invalid_client"
)

var (
	deferror *DefaultErrors = NewDefaultErrors()
)

// Default errors and messages
type DefaultErrors struct {
	errormap map[DefaultErrorID]string
}

// NewDefaultErrors initializes OAuth2 error codes and descriptions.
// http://tools.ietf.org/html/rfc6749#section-4.1.2.1
// http://tools.ietf.org/html/rfc6749#section-4.2.2.1
// http://tools.ietf.org/html/rfc6749#section-5.2
// http://tools.ietf.org/html/rfc6749#section-7.2
func NewDefaultErrors() *DefaultErrors {
	r := &DefaultErrors{
		errormap: make(map[DefaultErrorID]string),
	}

	r.errormap[E_INVALID_REQUEST] = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
	r.errormap[E_UNAUTHORIZED_CLIENT] = "The client is not authorized to request a token using this method."
	r.errormap[E_ACCESS_DENIED] = "The resource owner or authorization server denied the request."
	r.errormap[E_UNSUPPORTED_RESPONSE_TYPE] = "The authorization server does not support obtaining a token using this method."
	r.errormap[E_INVALID_SCOPE] = "The requested scope is invalid, unknown, or malformed."
	r.errormap[E_SERVER_ERROR] = "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."
	r.errormap[E_TEMPORARILY_UNAVAILABLE] = "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."
	r.errormap[E_UNSUPPORTED_GRANT_TYPE] = "The authorization grant type is not supported by the authorization server."
	r.errormap[E_INVALID_GRANT] = "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
	r.errormap[E_INVALID_CLIENT] = "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."

	return r
}

func (e *DefaultErrors) Get(id DefaultErrorID) string {
	if m, ok := e.errormap[id]; ok {
		return m
	}

	return id.String()
}
