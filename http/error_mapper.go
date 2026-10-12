// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperscale-stack/security"
)

// defaultChallengeScheme is the WWW-Authenticate scheme used when none is
// configured — RFC 6750 bearer tokens.
const defaultChallengeScheme = "Bearer"

// DefaultRealm is the realm of the default challenges when none is
// configured: RFC 7617 §2 requires one in a Basic challenge, and RFC 6750 §3
// requires an auth-param after Bearer. It is a protection-space label only;
// set your own with [WithRealm].
const DefaultRealm = "api"

// ErrorMapper translates a security error into an HTTP response. Custom
// mappers can produce structured (JSON, ProtoBuf) error bodies or emit
// transport-specific challenges; they should classify the error with
// [security.ErrorClass], as the default mapper does.
//
// Implementations MUST be safe for concurrent use and MUST write the
// response status before any body bytes.
type ErrorMapper interface {
	Map(w http.ResponseWriter, r *http.Request, err error)
}

// DefaultErrorMapper returns the canonical mapper used by the [Middleware]
// when WithErrorMapper is not supplied. It answers from
// [security.ErrorClass](err), with challenge scheme S and realm R:
//
//	class                                 status  WWW-Authenticate
//	invalid_request                       400     Bearer + bearer token sent: error="invalid_request"
//	unavailable                           503     —
//	token_expired, token_not_found,
//	client_secret_mismatch,
//	invalid_credentials                   401     S realm=R; Bearer + bearer token sent: error="invalid_token"
//	authentication_required,
//	unsupported_credential                401     S realm=R (no error code, RFC 6750 §3.1)
//	insufficient_scope, access_denied     403     S realm=R; Bearer + bearer token sent: error="insufficient_scope"
//	no_extractor, _OTHER                  500     —
//
// A 401 always carries a challenge (RFC 9110 §11.6.1); a Basic challenge
// also carries charset="UTF-8" (RFC 7617 §2.1). The RFC 6750 error codes are
// sent only when the request carried a bearer token in its Authorization
// field: invalid_token for every failed check of the token (RFC 9068 §4),
// insufficient_scope for a valid token refused by the access decision.
// An unavailable dependency is not a failed check: 503, no error code. The
// error_description is a fixed, generic string per code — the error chain
// is never reflected into the response.
//
// An empty scheme means "Bearer" and an empty realm [DefaultRealm].
// DefaultErrorMapper panics when scheme is not an RFC 9110 token or realm
// holds a character a quoted-string cannot carry (control characters, DEL,
// non-ASCII): a challenge configuration is static, so it fails at startup.
func DefaultErrorMapper(scheme, realm string) ErrorMapper {
	if scheme == "" {
		scheme = defaultChallengeScheme
	}

	if realm == "" {
		realm = DefaultRealm
	}

	if !isToken(scheme) {
		panic(fmt.Sprintf("httpsec: challenge scheme %q is not an RFC 9110 token", scheme))
	}

	quoted, ok := quoteString(realm)
	if !ok {
		panic(fmt.Sprintf("httpsec: realm %q is not printable ASCII (RFC 9110 §5.6.4 quoted-string)", realm))
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

// Map implements [ErrorMapper].
func (m *defaultErrorMapper) Map(w http.ResponseWriter, r *http.Request, err error) {
	o := outcomeOf(security.ErrorClass(err))

	if challenge := m.challengeFor(o, r); challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}

	http.Error(w, http.StatusText(o.status), o.status)
}

// challengeFor returns the WWW-Authenticate value of an outcome, or "".
func (m *defaultErrorMapper) challengeFor(o outcome, r *http.Request) string {
	withCode := m.bearer && o.code != "" && r != nil && bearerTokenSent(r.Header.Values("Authorization"))

	switch o.status {
	case http.StatusUnauthorized, http.StatusForbidden:
		if withCode {
			return m.challenge + `, error="` + o.code + `", error_description="` + o.description + `"`
		}

		return m.challenge
	case http.StatusBadRequest:
		if withCode {
			return m.challenge + `, error="` + o.code + `", error_description="` + o.description + `"`
		}

		return ""
	default:
		return ""
	}
}

// outcome is the HTTP answer to an error class, with the RFC 6750 §3.1
// error code (and its fixed description) a Bearer challenge carries.
type outcome struct {
	status      int
	code        string
	description string
}

// RFC 6750 §3.1 error_description strings. Fixed and generic: a verbatim
// error message would leak internal wrapping context (timestamps, package
// names, consumer-supplied store errors) to the client.
const (
	descInvalidRequest    = "The request is malformed."
	descInvalidToken      = "The access token is invalid or has expired."
	descInsufficientScope = "The request requires higher privileges than provided by the access token."
)

// outcomeOf maps a [security.ErrorClass] to its HTTP answer.
func outcomeOf(class string) outcome {
	switch class {
	case security.ErrorClassInvalidRequest:
		return outcome{http.StatusBadRequest, "invalid_request", descInvalidRequest}
	case security.ErrorClassUnavailable:
		return outcome{status: http.StatusServiceUnavailable}
	case security.ErrorClassTokenExpired, security.ErrorClassTokenNotFound,
		security.ErrorClassClientSecretMismatch, security.ErrorClassInvalidCredentials:
		return outcome{http.StatusUnauthorized, "invalid_token", descInvalidToken}
	case security.ErrorClassAuthenticationRequired, security.ErrorClassUnsupportedCredential:
		return outcome{status: http.StatusUnauthorized}
	case security.ErrorClassInsufficientScope, security.ErrorClassAccessDenied:
		return outcome{http.StatusForbidden, "insufficient_scope", descInsufficientScope}
	default:
		return outcome{status: http.StatusInternalServerError}
	}
}
