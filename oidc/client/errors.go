// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hyperscale-stack/security"
)

// Sentinel errors. Errors returned by the package wrap one of them with %w:
// match them with errors.Is, never with ==. They never carry a state, code,
// binding, nonce, verifier or token, and the provider-controlled or input
// text they echo — an issuer, a media type, a redirect target, a JOSE
// header member, a parameter name — is quoted and cut to a few hundred
// bytes. The errors that mean "this login is not authentic" also match
// security.ErrInvalidCredentials, so transport error mappers classify them
// as authentication failures.
var (
	// ErrInvalidConfig reports a Config New refuses.
	ErrInvalidConfig = errors.New("oidcclient: invalid configuration")
	// ErrDiscovery reports provider metadata that could not be retrieved:
	// network or policy failure, unexpected status or content type,
	// oversized body.
	ErrDiscovery = errors.New("oidcclient: provider metadata unavailable")
	// ErrInvalidMetadata reports provider metadata that was retrieved but
	// cannot be used: malformed JSON, a REQUIRED member missing, a member
	// of the wrong type, a non-https endpoint, or a capability the
	// configuration needs that the provider does not offer.
	ErrInvalidMetadata = errors.New("oidcclient: invalid provider metadata")
	// ErrIssuerMismatch reports a discovery document whose issuer is not
	// byte-for-byte the configured issuer (OpenID Connect Discovery 1.0
	// §4.3): nothing from it is used.
	ErrIssuerMismatch = errors.New("oidcclient: provider metadata issuer mismatch")
	// ErrInvalidAuthRequest reports AuthOptions Begin refuses.
	ErrInvalidAuthRequest = errors.New("oidcclient: invalid authorization request")
	// ErrInvalidCallback reports a malformed authorization response, or
	// one received on another URL or in another response mode than the
	// connection's: no transaction is touched.
	ErrInvalidCallback = errors.New("oidcclient: invalid callback")

	// ErrTransactionNotFound reports a login transaction that does not
	// exist: never started, already consumed (a replayed callback), or
	// expired.
	ErrTransactionNotFound = fmt.Errorf("oidcclient: login transaction not found: %w", security.ErrInvalidCredentials)
	// ErrBindingMismatch reports a callback whose user agent did not
	// present the browser binding of the transaction (cross-site request
	// forgery, login CSRF, code injection): the transaction is left intact.
	ErrBindingMismatch = fmt.Errorf("oidcclient: browser binding mismatch: %w", security.ErrInvalidCredentials)
	// ErrTransactionExists reports a TransactionStore.Save for a state
	// hash already stored: a store never overwrites a transaction.
	ErrTransactionExists = errors.New("oidcclient: login transaction already exists")
	// ErrInvalidTransaction reports a Transaction that Validate refuses.
	ErrInvalidTransaction = errors.New("oidcclient: invalid login transaction")
	// ErrTransactionMismatch reports a transaction started by another
	// connection, issuer, client, redirect URI or response mode than the
	// Client completing it (mix-up, RFC 9700 §4.4): it is consumed and the
	// code is never redeemed.
	ErrTransactionMismatch = fmt.Errorf("oidcclient: login transaction of another connection: %w", security.ErrInvalidCredentials)
	// ErrTransactionIntegrity reports a transaction whose fields do not
	// match its integrity MAC under the binding the user agent presented:
	// it was altered in the store. It is consumed and the code is never
	// redeemed.
	ErrTransactionIntegrity = fmt.Errorf("oidcclient: login transaction altered in the store: %w", security.ErrInvalidCredentials)
	// ErrTransactionExpired reports a transaction past its expiry.
	ErrTransactionExpired = fmt.Errorf("oidcclient: login transaction expired: %w", security.ErrInvalidCredentials)
	// ErrIssuerParameter reports an authorization response whose RFC 9207
	// iss parameter is missing while the provider advertises it, or does
	// not equal the provider's issuer.
	ErrIssuerParameter = fmt.Errorf("oidcclient: authorization response issuer mismatch: %w", security.ErrInvalidCredentials)
	// ErrAuthorizationFailed is matched by every *AuthorizationError: the
	// provider answered the authorization request with an error.
	ErrAuthorizationFailed = errors.New("oidcclient: authorization failed")

	// ErrTokenEndpoint reports a failed token request: network or policy
	// failure, unexpected status, or a *TokenError from the provider.
	ErrTokenEndpoint = errors.New("oidcclient: token request failed")
	// ErrInvalidTokenResponse reports a successful token response that
	// cannot be used (RFC 6749 §5.1, OpenID Connect Core §3.1.3.3).
	ErrInvalidTokenResponse = errors.New("oidcclient: invalid token response")
	// ErrKeySet reports a provider JWK Set that could not be retrieved or
	// is unusable.
	ErrKeySet = errors.New("oidcclient: provider JWK Set unavailable")

	// ErrInvalidIDToken is matched by every ID Token validation failure
	// (OpenID Connect Core §3.1.3.7).
	ErrInvalidIDToken = fmt.Errorf("oidcclient: invalid ID token: %w", security.ErrInvalidCredentials)
	// ErrIDTokenMalformed reports an ID Token that is not a JWS Compact
	// Serialization of a strict JSON claims set, or whose JOSE header is not
	// a strict JSON object of at most 4 KiB or carries a jwk, x5c, jku or
	// x5u member (refused before the token is parsed).
	ErrIDTokenMalformed = idTokenError("malformed")
	// ErrIDTokenAlgorithm reports a signature algorithm outside the
	// effective allow-list ("none" and HMAC algorithms are never allowed):
	// Config.Algorithms, RS256 by default — a provider signing with another
	// algorithm needs it set to the algorithm registered for the client.
	ErrIDTokenAlgorithm = idTokenError("algorithm not allowed (Config.Algorithms)")
	// ErrIDTokenType reports a JOSE header naming another kind of token
	// (typ, e.g. an RFC 9068 at+jwt access token), a nested JWT (cty) or an
	// extension (crit, b64).
	ErrIDTokenType = idTokenError("not an ID token")
	// ErrUnknownSigningKey reports an ID Token whose key is not in the
	// provider's JWK Set, even after a bounded refresh, or that does not
	// designate a single key.
	ErrUnknownSigningKey = idTokenError("unknown signing key")
	// ErrIDTokenSignature reports an invalid signature.
	ErrIDTokenSignature = idTokenError("invalid signature")
	// ErrIDTokenIssuer reports an iss claim other than the issuer.
	ErrIDTokenIssuer = idTokenError("issuer mismatch")
	// ErrIDTokenAudience reports an aud claim that does not contain the
	// client ID, or contains an untrusted audience.
	ErrIDTokenAudience = idTokenError("audience mismatch")
	// ErrIDTokenAuthorizedParty reports an azp claim other than the
	// client ID.
	ErrIDTokenAuthorizedParty = idTokenError("authorized party mismatch")
	// ErrIDTokenExpired reports an expired ID Token.
	ErrIDTokenExpired = idTokenError("expired")
	// ErrIDTokenIssuedAt reports an iat in the future or before the
	// authorization request.
	ErrIDTokenIssuedAt = idTokenError("issued at an impossible time")
	// ErrIDTokenNotYetValid reports an nbf in the future.
	ErrIDTokenNotYetValid = idTokenError("not yet valid")
	// ErrIDTokenNonce reports a missing or foreign nonce.
	ErrIDTokenNonce = idTokenError("nonce mismatch")
	// ErrIDTokenMissingClaim reports a REQUIRED claim that is absent or
	// malformed (sub, exp, iat, auth_time when max_age was sent).
	ErrIDTokenMissingClaim = idTokenError("missing or malformed claim")
	// ErrIDTokenAuthTime reports an authentication older than the max_age
	// sent, or in the future.
	ErrIDTokenAuthTime = idTokenError("authentication too old")
	// ErrIDTokenACR reports an acr claim that is missing or not one of the
	// acr_values sent.
	ErrIDTokenACR = idTokenError("authentication context not satisfied")
	// ErrAccessTokenHash reports an at_hash claim that does not match the
	// access token (OpenID Connect Core §3.1.3.8): access-token
	// substitution.
	ErrAccessTokenHash = idTokenError("access token hash mismatch")

	// ErrUserInfo reports a failed UserInfo request.
	ErrUserInfo = errors.New("oidcclient: UserInfo request failed")
	// ErrUserInfoSubject reports UserInfo claims about another subject than
	// the identity (OpenID Connect Core §5.3.2): they are not returned.
	ErrUserInfoSubject = fmt.Errorf("oidcclient: UserInfo subject mismatch: %w", security.ErrInvalidCredentials)
	// ErrUserInfoUnsupported reports a signed or encrypted UserInfo
	// response (application/jwt), which this package does not support.
	ErrUserInfoUnsupported = errors.New("oidcclient: unsupported UserInfo response format")
)

func idTokenError(msg string) error {
	return fmt.Errorf("oidcclient: ID token %s: %w", msg, ErrInvalidIDToken)
}

// AuthorizationError is the error response of the authorization endpoint
// (RFC 6749 §4.1.2.1, OpenID Connect Core §3.1.2.6), returned by Complete
// once the response was matched to its transaction. Code, Description and
// URI are untrusted input from the front channel — when the provider does
// not support RFC 9207, nothing proves the authorization server produced
// them (RFC 9207 §2.4): never render URI as a trusted link. Code is
// guaranteed to be 1 to 256 characters of the RFC 6749 error charset;
// Description and URI are dropped when outside their charsets.
type AuthorizationError struct {
	Code        string
	Description string
	URI         string
}

// Error reports the error code only.
func (e *AuthorizationError) Error() string {
	return "oidcclient: authorization failed: " + e.Code
}

// Unwrap returns ErrAuthorizationFailed.
func (e *AuthorizationError) Unwrap() error { return ErrAuthorizationFailed }

// TokenError is an error response of the token endpoint (RFC 6749 §5.2):
// the HTTP status and the error code, description and URI the provider
// sent. Code is 1 to 256 characters of the RFC 6749 error charset;
// Description and URI are dropped when outside their charsets. All three
// are provider-controlled text: log them, never render them as trusted
// content (a tenant-configured provider can be hostile).
type TokenError struct {
	StatusCode  int
	Code        string
	Description string
	URI         string
}

// Error reports the status and the error code only.
func (e *TokenError) Error() string {
	return fmt.Sprintf("oidcclient: token request failed: %d %s", e.StatusCode, e.Code)
}

// Unwrap returns ErrTokenEndpoint.
func (e *TokenError) Unwrap() error { return ErrTokenEndpoint }

// maxEchoLength bounds the bytes of untrusted text an error echoes, per
// value.
const maxEchoLength = 256

// clip bounds untrusted text echoed into an error: invalid UTF-8 is
// replaced, then text longer than maxEchoLength keeps its first and last
// maxEchoLength/2 bytes — the beginning names the operation, the end the
// cause — around "...", cut on rune boundaries.
func clip(s string) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	if len(s) <= maxEchoLength {
		return s
	}

	head, tail := maxEchoLength/2, len(s)-maxEchoLength/2
	for i := 0; i < utf8.UTFMax && !utf8.RuneStart(s[head]); i++ {
		head--
	}

	for i := 0; i < utf8.UTFMax && !utf8.RuneStart(s[tail]); i++ {
		tail++
	}

	return s[:head] + "..." + s[tail:]
}

// quoted renders untrusted text for an error: Go-quoted — control
// characters and invalid UTF-8 escaped — then clipped, so that escaping
// cannot inflate it past the bound.
func quoted(s string) string { return clip(strconv.Quote(s)) }

// clippedError bounds the text of a wrapped error that may echo
// provider-controlled data — a redirect target in a *url.Error, a JOSE
// header member, a certificate's names; errors.Is and errors.As still
// reach the original.
type clippedError struct{ err error }

// Error returns the original text, clipped.
func (e *clippedError) Error() string { return clip(e.err.Error()) }

// Unwrap returns the original error.
func (e *clippedError) Unwrap() error { return e.err }

// clipped returns err with its text bounded; nil and short errors are
// returned as they are.
func clipped(err error) error {
	if err == nil || len(err.Error()) <= maxEchoLength {
		return err
	}

	return &clippedError{err: err}
}
