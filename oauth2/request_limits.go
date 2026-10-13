// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
)

// DefaultMaxRequestBytes is the bound [ServerConfig.MaxRequestBytes]
// applies when it is zero or negative: 64 KiB.
const DefaultMaxRequestBytes = 64 << 10

// Bounds on the request values the server looks up, keeps or echoes. RFC
// 6749 leaves them unbounded; the authorization endpoint echoes the state in
// every response to the client and records the nonce with the code, so both
// are bounded before anything else uses them.
const (
	// MaxNonceLength is the longest nonce, in bytes, an authorization
	// request may carry: a longer one — or one that is not valid UTF-8 or
	// holds NUL — is refused with invalid_request, so no store is ever
	// handed more (OpenID Connect Core §3.1.2.1 leaves it unbounded; the
	// rule is the one oidc/provider applies to OpenID requests).
	MaxNonceLength = 512
	// MaxStateLength is the longest state, in bytes, an authorization
	// request may carry. A longer one — or one outside VSCHAR, RFC 6749
	// Appendix A.5 — is refused with invalid_request, without the state:
	// echoing it would defeat the bound (RFC 6749 §10.14: the state MUST be
	// validated).
	MaxStateLength = 4096
	// MaxClientIDLength is the longest client identifier, in bytes, the
	// server looks up (RFC 6749 §2.2: the authorization server documents
	// the size of the identifiers it issues; the SQL stores keep them in a
	// VARCHAR(255) column): a longer one is an unknown client, refused
	// without consulting the [ClientStore].
	MaxClientIDLength = 255
)

// errRequestTooLarge is the cause of a request refused for its size.
var errRequestTooLarge = errors.New("oauth2: request larger than ServerConfig.MaxRequestBytes")

// errTooLarge answers a request over the bound: invalid_request (RFC 6749
// §5.2 answers 400 unless specified otherwise).
var errTooLarge = ErrInvalidRequest.WithDescription("request too large")

// maxRequestBytes returns the request-size bound of the server.
func (s *Server) maxRequestBytes() int64 {
	if s.cfg.MaxRequestBytes > 0 {
		return s.cfg.MaxRequestBytes
	}

	return DefaultMaxRequestBytes
}

// parseRequestForm parses the query and the body of r (http.Request
// ParseForm) within s.maxRequestBytes(): a query — or a body whose declared
// length is — longer than the bound is refused before anything is read, and
// a body of unknown length is read through http.MaxBytesReader. A refusal
// for size wraps errRequestTooLarge (and the *http.MaxBytesError of a body
// found too long while reading it). A request whose form a middleware
// already parsed keeps it: only its query is checked.
func (s *Server) parseRequestForm(w http.ResponseWriter, r *http.Request) error {
	limit := s.maxRequestBytes()
	if int64(len(r.URL.RawQuery)) > limit || r.ContentLength > limit {
		return errRequestTooLarge
	}

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}

	if err := r.ParseForm(); err != nil {
		if tooLarge := (*http.MaxBytesError)(nil); errors.As(err, &tooLarge) {
			return errors.Join(errRequestTooLarge, err)
		}

		return fmt.Errorf("oauth2: parse request: %w", err)
	}

	return nil
}

// formRefusal is the invalid_request answering a request parseRequestForm
// refused: "request too large", or the sentinel's "the request is
// malformed"; the cause reaches the [ErrorHook].
func formRefusal(err error) *Error {
	if errors.Is(err, errRequestTooLarge) {
		return errTooLarge.WithCause(err)
	}

	return ErrInvalidRequest.WithCause(err)
}

// validState reports whether state may be echoed: at most MaxStateLength
// bytes of VSCHAR, %x20-7E (RFC 6749 Appendix A.5). An empty state is an
// omitted one (RFC 6749 §3.1).
func validState(state string) bool {
	if len(state) > MaxStateLength {
		return false
	}

	for i := range len(state) {
		if state[i] < 0x20 || state[i] > 0x7E {
			return false
		}
	}

	return true
}

// validNonce reports whether nonce may be recorded: at most MaxNonceLength
// bytes of valid UTF-8 without NUL — what every store keeps byte-exact.
func validNonce(nonce string) bool {
	return len(nonce) <= MaxNonceLength && utf8.ValidString(nonce) && strings.IndexByte(nonce, 0) < 0
}

// The invalid_request answers of an invalid state or nonce. They never echo
// the request.
var (
	errMalformedState = ErrInvalidRequest.WithDescription("the state is too long or malformed")
	errMalformedNonce = ErrInvalidRequest.WithDescription("the nonce is too long or not valid UTF-8")
)
