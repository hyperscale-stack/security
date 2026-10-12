// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

// The request parameters several endpoints read.
const (
	paramClientID     = "client_id"
	paramClientSecret = "client_secret"
	paramRedirectURI  = "redirect_uri"
	paramResponseMode = "response_mode"
	paramScope        = "scope"
)

// The request parameters each endpoint reads itself (RFC 6749 §3.1, §3.2):
// read single-valued — an empty occurrence is omitted — and refused when
// included more than once with a value. Any other parameter is left to the
// callbacks: the server ignores what it does not recognize.
var (
	// authorizeParameters are the parameters of an authorization request
	// (RFC 6749 §4.1.1, §4.2.1; RFC 7636 §4.3; the response_mode of the
	// OAuth 2.0 Multiple Response Type Encoding Practices; the OpenID
	// Connect nonce the core records). The unredirectableParameters come
	// first: param.SingleValued reports the first repeated name in this
	// order, so a request repeating one of them is refused with a bare 400
	// whatever else it repeats.
	authorizeParameters = []string{
		paramClientID, paramRedirectURI, paramResponseMode, "response_type", paramScope, "state",
		"code_challenge", "code_challenge_method", "nonce",
	}
	// unredirectableParameters, repeated, leave the client, the redirection
	// target or the encoding of the answer ambiguous: such a request is
	// refused with a bare 400, never redirected (RFC 6749 §4.1.2.1).
	unredirectableParameters = []string{paramClientID, paramRedirectURI, paramResponseMode}
	// tokenParameters are the parameters of an access-token request (RFC
	// 6749 §2.3.1, §4.1.3, §4.3.2, §4.4.2, §6; RFC 7636 §4.5).
	tokenParameters = []string{
		"grant_type", "code", paramRedirectURI, "code_verifier", "refresh_token",
		paramScope, "username", "password", paramClientID, paramClientSecret,
	}
	// clientAuthParameters are the client credentials a request body may
	// carry (RFC 6749 §2.3.1), at every endpoint authenticating clients.
	clientAuthParameters = []string{paramClientID, paramClientSecret}
	// tokenLookupParameters are the parameters of a revocation (RFC 7009
	// §2.1) or an introspection (RFC 7662 §2.1) request.
	tokenLookupParameters = []string{"token", "token_type_hint"}
)

// repeatedParameter is the invalid_request answering a request that
// includes name more than once (RFC 6749 §4.1.2.1, §5.2).
func repeatedParameter(name string) *Error {
	return ErrInvalidRequest.WithDescription("repeated " + name)
}
