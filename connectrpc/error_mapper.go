// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
)

// defaultChallengeScheme is the WWW-Authenticate scheme used when none is
// configured — RFC 6750 bearer tokens.
const defaultChallengeScheme = "Bearer"

// DefaultRealm is the realm of the default challenges when none is
// configured: RFC 7617 §2 requires one in a Basic challenge, and RFC 6750 §3
// requires an auth-param after Bearer.
const DefaultRealm = "api"

// ErrorMapper translates a security error into a Connect error. Custom
// mappers can localize messages or attach metadata; they should classify
// the error with [security.ErrorClass], as the default mapper does.
//
// Implementations MUST be safe for concurrent use.
type ErrorMapper interface {
	// Map returns the Connect error for err. It MUST return a non-nil error
	// (callers only invoke it on a failure path).
	Map(ctx context.Context, err error) error
}

// DefaultErrorMapper returns the canonical mapper. It answers from
// [security.ErrorClass](err) with one fixed message per code — the message
// never says why authentication failed — and, as a Connect unary error
// travels as an HTTP response, with the WWW-Authenticate challenge of
// scheme S and realm R in the error's metadata (sent as response headers):
//
//	class                                       code (HTTP)             challenge
//	invalid_request                             InvalidArgument (400)   Bearer realm=R; + bearer token sent: error="invalid_request"
//	unavailable                                 Unavailable (503)       Bearer realm=R
//	too_many_attempts                           ResourceExhausted (429) Bearer realm=R
//	token_expired, token_not_found,
//	client_secret_mismatch, invalid_credentials Unauthenticated (401)   S realm=R; Bearer + bearer token sent: error="invalid_token"
//	authentication_required,
//	unsupported_credential                      Unauthenticated (401)   S realm=R (no error code)
//	insufficient_scope, access_denied           PermissionDenied (403)  S realm=R; Bearer + bearer token sent: error="insufficient_scope"
//	no_extractor, _OTHER                        Internal (500)          Bearer realm=R
//
// A Bearer resource challenges every refusal (RFC 6750 §3); another scheme
// the Unauthenticated and PermissionDenied answers. A throttled attempt
// ([security.ErrTooManyAttempts]) also carries Cache-Control: no-store and,
// when the [*security.TooManyAttemptsError] knows the delay — the first one
// of the error chain —, Retry-After in whole seconds rounded up (RFC 6585
// §4, RFC 9110 §10.2.3). A Basic challenge also
// carries charset="UTF-8" (RFC 7617 §2.1). Whether the request carried a
// bearer token is told by the interceptors; without them no RFC 6750 code
// is sent. An empty scheme means "Bearer" and an
// empty realm [DefaultRealm]. DefaultErrorMapper panics when scheme is not
// an RFC 9110 token or realm holds a character a quoted-string cannot
// carry: a challenge configuration is static, so it fails at startup.
func DefaultErrorMapper(scheme, realm string) ErrorMapper {
	if scheme == "" {
		scheme = defaultChallengeScheme
	}

	if realm == "" {
		realm = DefaultRealm
	}

	if !isToken(scheme) {
		panic(fmt.Sprintf("connectrpcsec: challenge scheme %q is not an RFC 9110 token", scheme))
	}

	quoted, ok := quoteString(realm)
	if !ok {
		panic(fmt.Sprintf("connectrpcsec: realm %q is not printable ASCII (RFC 9110 §5.6.4 quoted-string)", realm))
	}

	params := "realm=" + quoted
	if strings.EqualFold(scheme, "Basic") {
		params += `, charset="UTF-8"`
	}

	return &defaultErrorMapper{
		challenge: scheme + " " + params,
		bearer:    strings.EqualFold(scheme, defaultChallengeScheme),
	}
}

type defaultErrorMapper struct {
	// challenge is the scheme followed by its realm (and charset) auth-params.
	challenge string
	// bearer reports a Bearer challenge, which takes the RFC 6750 codes.
	bearer bool
}

// Map implements [ErrorMapper]. The returned Connect error is the final wire
// value — not a wrapping of err.
func (m *defaultErrorMapper) Map(ctx context.Context, err error) error {
	o := outcomeOf(security.ErrorClass(err))
	ce := connect.NewError(o.code, errors.New(o.message))

	if challenge := m.challengeFor(o, bearerTokenSent(ctx)); challenge != "" {
		ce.Meta().Set("WWW-Authenticate", challenge)
	}

	if o.code == connect.CodeResourceExhausted {
		setRetryAfter(ce.Meta(), err)
	}

	return ce
}

// setRetryAfter sets the fields of a throttled answer: Cache-Control:
// no-store — RFC 6585 §4: a 429 "MUST NOT be stored by a cache" — and, when
// err tells the delay, Retry-After in delay-seconds (RFC 9110 §10.2.3).
func setRetryAfter(h http.Header, err error) {
	h.Set("Cache-Control", "no-store")

	var tooMany *security.TooManyAttemptsError
	if errors.As(err, &tooMany) && tooMany.RetryAfter > 0 {
		h.Set("Retry-After", strconv.FormatInt(security.RetryAfterSeconds(tooMany.RetryAfter), 10))
	}
}

// challengeFor returns the WWW-Authenticate value of an outcome, or "". A
// Bearer resource challenges every refusal — RFC 6750 §3: the request
// carried no access token enabling access — with the §3.1 error code only
// for a request that carried a bearer token; another scheme challenges the
// Unauthenticated (HTTP 401) and PermissionDenied (403) answers.
func (m *defaultErrorMapper) challengeFor(o outcome, bearerSent bool) string {
	switch {
	case m.bearer && o.oauthCode != "" && bearerSent:
		return m.challenge + `, error="` + o.oauthCode + `", error_description="` + o.description + `"`
	case m.bearer || o.challenge:
		return m.challenge
	default:
		return ""
	}
}

// outcome is the Connect answer to an error class.
type outcome struct {
	code    connect.Code
	message string
	// challenge reports an answer (401, 403) that always carries a challenge.
	challenge bool
	// oauthCode and description are the RFC 6750 §3.1 error of a Bearer
	// challenge, for a request that carried a bearer token.
	oauthCode   string
	description string
}

// msgUnauthenticated is the one message of every Unauthenticated answer: it
// never says why authentication failed.
const msgUnauthenticated = "unauthenticated"

// RFC 6750 §3.1 error_description strings: fixed and generic.
const (
	descInvalidRequest    = "The request is malformed."
	descInvalidToken      = "The access token is invalid or has expired."
	descInsufficientScope = "The request requires higher privileges than provided by the access token."
)

// outcomeOf maps a [security.ErrorClass] to its Connect answer.
func outcomeOf(class string) outcome {
	switch class {
	case security.ErrorClassInvalidRequest:
		return outcome{connect.CodeInvalidArgument, "invalid request", false, "invalid_request", descInvalidRequest}
	case security.ErrorClassUnavailable:
		return outcome{code: connect.CodeUnavailable, message: "authentication unavailable"}
	case security.ErrorClassTooManyAttempts:
		return outcome{code: connect.CodeResourceExhausted, message: "too many attempts"}
	case security.ErrorClassTokenExpired, security.ErrorClassTokenNotFound,
		security.ErrorClassClientSecretMismatch, security.ErrorClassInvalidCredentials:
		return outcome{connect.CodeUnauthenticated, msgUnauthenticated, true, "invalid_token", descInvalidToken}
	case security.ErrorClassAuthenticationRequired, security.ErrorClassUnsupportedCredential:
		return outcome{code: connect.CodeUnauthenticated, message: msgUnauthenticated, challenge: true}
	case security.ErrorClassInsufficientScope, security.ErrorClassAccessDenied:
		return outcome{connect.CodePermissionDenied, "permission denied", true, "insufficient_scope", descInsufficientScope}
	default:
		return outcome{code: connect.CodeInternal, message: "internal error"}
	}
}
