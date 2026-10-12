// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

// Protocol parameter names and values (RFC 6749, RFC 7636, RFC 9207,
// OpenID Connect Core 1.0).
const (
	paramResponseType        = "response_type"
	paramClientID            = "client_id"
	paramClientSecret        = "client_secret"
	paramRedirectURI         = "redirect_uri"
	paramScope               = "scope"
	paramState               = "state"
	paramNonce               = "nonce"
	paramCode                = "code"
	paramCodeChallenge       = "code_challenge"
	paramCodeChallengeMethod = "code_challenge_method"
	paramCodeVerifier        = "code_verifier"
	paramResponseMode        = "response_mode"
	paramGrantType           = "grant_type"
	paramError               = "error"
	paramErrorDescription    = "error_description"
	paramErrorURI            = "error_uri"
	paramIssuer              = "iss"

	responseTypeCode       = "code"
	grantAuthorizationCode = "authorization_code"
	methodS256             = "S256"
	schemeHTTPS            = "https"
	schemeHTTP             = "http"
	jsonNull               = "null"
)
