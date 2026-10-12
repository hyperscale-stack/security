// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Authorization response bounds.
const (
	maxCodeLength             = 8192
	maxErrorCodeLength        = 256
	maxErrorDescriptionLength = 1024
)

// Callback is an authorization response as the callback endpoint received
// it. It prints, logs and encodes to JSON without its secrets (String,
// LogValue, MarshalJSON): the binding secret, the parameter values (code,
// state) and the query of URL.
type Callback struct {
	// Mode is how Params arrived: ResponseModeQuery for the query string
	// of a GET, ResponseModeFormPost for the form body of a POST.
	Mode ResponseMode
	// URL is the URL the response was received on, as the user agent
	// addressed it: scheme, host (and port), path and query. Complete
	// requires it to be the connection's RedirectURL (RFC 9700 §4.4.2.2
	// mix-up defense): same scheme, host and port — case-insensitively, a
	// missing port being the scheme's default — same path, and the
	// RedirectURL's query parameters with their values. Build it from the
	// request, never from the response; behind a reverse proxy, it is the
	// public URL.
	URL *url.URL
	// Params are the response parameters (url.ParseQuery or r.PostForm).
	Params url.Values
	// Binding is the browser-binding secret the user agent presented (the
	// AuthRequest.Binding of the login, read from its cookie).
	Binding string
}

// String implements fmt.Stringer without the binding secret, the parameter
// values nor the URL's query, which carries the response in query mode.
func (cb Callback) String() string {
	return fmt.Sprintf("oidcclient.Callback{Mode: %s, URL: %q, Params: %d, Binding: REDACTED}", cb.Mode, withoutQuery(cb.URL), len(cb.Params))
}

// GoString implements fmt.GoStringer like String.
func (cb Callback) GoString() string { return cb.String() }

// LogValue implements slog.LogValuer like String.
func (cb Callback) LogValue() slog.Value {
	return slog.GroupValue(slog.String("mode", string(cb.Mode)), slog.String("url", withoutQuery(cb.URL)),
		slog.String("binding", redactedMark))
}

// MarshalJSON implements json.Marshaler like String: the mode, the URL
// without its query, the number of parameters, never their values nor the
// binding secret — log/slog's JSON handler encodes a nested Callback with
// encoding/json. A struct embedding Callback is promoted this method and
// encodes as the Callback alone: name the field instead of embedding it.
func (cb Callback) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct { //nolint:wrapcheck // strings and an int only: never fails
		Mode    ResponseMode
		URL     string
		Params  int
		Binding string
	}{cb.Mode, withoutQuery(cb.URL), len(cb.Params), redactedMark})
}

// withoutQuery renders u without its query and fragment.
func withoutQuery(u *url.URL) string {
	if u == nil {
		return ""
	}

	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}).String()
}

// authorizationResponse is a well-formed authorization response.
type authorizationResponse struct {
	state    string
	code     string
	errCode  string
	errDesc  string
	errURI   string
	iss      string
	hasIss   bool
	hasError bool
}

// Complete finishes a login. In order, and without touching the store
// before step 3:
//
//  1. the response is checked: mode and redirect URI of the connection,
//     every parameter at most once (RFC 6749 §3.1), well-formed state,
//     code or error, iss — else ErrInvalidCallback;
//  2. the binding secret is checked for form — else ErrBindingMismatch;
//  3. the transaction is consumed atomically with the binding's hash (a
//     wrong binding leaves it stored), then its integrity MAC is verified
//     with the binding and the transaction keys before any of its fields is
//     used — else ErrTransactionIntegrity;
//  4. it must belong to this connection, issuer, client, redirect URI and
//     response mode — else ErrTransactionMismatch — and be unexpired;
//  5. the RFC 9207 iss parameter must be the issuer when present, and is
//     required when the provider advertises it — else ErrIssuerParameter;
//  6. an error response becomes an *AuthorizationError;
//  7. the code is redeemed with the PKCE verifier (RFC 7636 §4.5), the
//     token response parsed strictly, the ID Token validated (OpenID Connect
//     Core §3.1.3.7) against the nonce, with at_hash when present.
//
// Any failure returns a nil Identity: no token of a failed login is ever
// exposed (RFC 9700 §4.5.3.2). A consumed transaction is never restored;
// the user starts over.
func (c *Client) Complete(ctx context.Context, cb Callback) (*Identity, error) {
	resp, err := c.parseCallback(cb)
	if err != nil {
		return nil, err
	}

	secret, ok := decodeSecret(cb.Binding)
	if !ok {
		return nil, fmt.Errorf("%w: missing or malformed binding", ErrBindingMismatch)
	}

	now := c.now()

	tx, err := c.cfg.Store.Consume(ctx, stateHashFor(resp.state), bindingHashFor(secret), now)
	if err != nil {
		return nil, fmt.Errorf("oidcclient: consume login transaction: %w", err)
	}

	if tx == nil { // a store breaking its contract
		return nil, fmt.Errorf("oidcclient: consume login transaction: %w", ErrTransactionNotFound)
	}

	if !verifyIntegrity(c.cfg.TransactionKeys, secret, tx) {
		return nil, ErrTransactionIntegrity
	}

	if err := c.checkTransaction(tx, now); err != nil {
		return nil, err
	}

	if err := c.checkIssuerParameter(resp); err != nil {
		return nil, err
	}

	if resp.hasError {
		return nil, &AuthorizationError{Code: resp.errCode, Description: resp.errDesc, URI: resp.errURI}
	}

	tokens, err := c.exchange(ctx, resp.code, verifierFor(secret))
	if err != nil {
		return nil, err
	}

	return c.verifyLogin(ctx, tokens, tx, nonceFor(secret))
}

// parseCallback checks the shape of the response.
func (c *Client) parseCallback(cb Callback) (authorizationResponse, error) {
	if cb.Mode != c.cfg.ResponseMode {
		return authorizationResponse{}, fmt.Errorf("%w: response mode %s, connection uses %s", ErrInvalidCallback, quoted(string(cb.Mode)), c.cfg.ResponseMode)
	}

	if !c.receivedOnRedirect(cb.URL) {
		return authorizationResponse{}, fmt.Errorf("%w: received on another URL than the connection's redirect URI", ErrInvalidCallback)
	}

	values := make(map[string]string, len(responseParams))

	for _, name := range responseParams {
		switch v := cb.Params[name]; len(v) {
		case 0:
		case 1:
			values[name] = v[0]
		default:
			return authorizationResponse{}, fmt.Errorf("%w: parameter %s repeated", ErrInvalidCallback, name)
		}
	}

	resp := authorizationResponse{
		state:    values[paramState],
		code:     values[paramCode],
		iss:      values[paramIssuer],
		hasIss:   values[paramIssuer] != "", // a parameter without value is omitted (RFC 6749 §3.1)
		hasError: values[paramError] != "",
	}

	if _, ok := decodeSecret(resp.state); !ok {
		return authorizationResponse{}, fmt.Errorf("%w: missing or malformed state", ErrInvalidCallback)
	}

	if resp.hasIss && !isASCII(resp.iss, visibleASCII, maxURILength) {
		return authorizationResponse{}, fmt.Errorf("%w: malformed iss", ErrInvalidCallback)
	}

	if err := resp.parseOutcome(values); err != nil {
		return authorizationResponse{}, err
	}

	return resp, nil
}

// receivedOnRedirect reports whether u is the connection's redirect URI
// (RFC 9700 §4.4.2.2): same scheme, host and port, compared
// case-insensitively with a missing port meaning the scheme's default, same
// path (empty meaning "/"), and the redirect URI's query parameters
// present with exactly their values.
func (c *Client) receivedOnRedirect(u *url.URL) bool {
	if u == nil || !strings.EqualFold(u.Scheme, c.redirect.Scheme) ||
		!strings.EqualFold(u.Hostname(), c.redirect.Hostname()) || effectivePort(u) != effectivePort(c.redirect) ||
		pathOrRoot(u.Path) != pathOrRoot(c.redirect.Path) {
		return false
	}

	received := u.Query()

	for name, values := range c.redirectQuery {
		if !slices.Equal(received[name], values) {
			return false
		}
	}

	return true
}

// effectivePort is the port of u, or the default port of its scheme.
func effectivePort(u *url.URL) string {
	switch {
	case u.Port() != "":
		return u.Port()
	case strings.EqualFold(u.Scheme, schemeHTTP):
		return "80"
	default:
		return "443"
	}
}

func pathOrRoot(path string) string {
	if path == "" {
		return "/"
	}

	return path
}

// parseOutcome checks the code, or the error, of the response (RFC 6749
// §4.1.2, §4.1.2.1, Appendix A).
func (r *authorizationResponse) parseOutcome(values map[string]string) error {
	if !r.hasError {
		if !isASCII(r.code, printableASCII, maxCodeLength) {
			return fmt.Errorf("%w: missing or malformed code", ErrInvalidCallback)
		}

		return nil
	}

	if r.code != "" {
		return fmt.Errorf("%w: both code and error", ErrInvalidCallback)
	}

	r.errCode = values[paramError]
	if !isErrorText(r.errCode, maxErrorCodeLength) {
		return fmt.Errorf("%w: malformed error code", ErrInvalidCallback)
	}

	if isErrorText(values[paramErrorDescription], maxErrorDescriptionLength) {
		r.errDesc = values[paramErrorDescription]
	}

	if isErrorURI(values[paramErrorURI]) {
		r.errURI = values[paramErrorURI]
	}

	return nil
}

// checkTransaction refuses a transaction of another connection, issuer,
// client, redirect URI or response mode (RFC 9700 §4.4.2: the stored
// issuer and the distinct redirect URI tie the response to its provider),
// or an expired one.
func (c *Client) checkTransaction(tx *Transaction, now time.Time) error {
	if tx.ConnectionID != c.cfg.ConnectionID || tx.Issuer != c.md.Issuer || tx.ClientID != c.cfg.ClientID ||
		tx.RedirectURI != c.cfg.RedirectURL || tx.ResponseMode != c.cfg.ResponseMode {
		return ErrTransactionMismatch
	}

	if !now.Before(tx.ExpiresAt) {
		return ErrTransactionExpired
	}

	return nil
}

// checkIssuerParameter applies RFC 9207 §2.4: when present, iss must be
// the issuer (simple string comparison), errors included; it is required
// when the provider advertises authorization_response_iss_parameter_supported.
// A matching iss from a provider that does not advertise it is accepted —
// the local policy §2.4 leaves open.
func (c *Client) checkIssuerParameter(resp authorizationResponse) error {
	if resp.hasIss {
		if resp.iss != c.md.Issuer {
			return fmt.Errorf("%w: iss of another issuer", ErrIssuerParameter)
		}

		return nil
	}

	if c.md.AuthorizationResponseIssParameterSupported {
		return fmt.Errorf("%w: iss missing although the provider sends it", ErrIssuerParameter)
	}

	return nil
}

// isErrorText reports whether s is 1 to maxLen characters of the RFC 6749
// error and error_description charset: %x20-21 / %x23-5B / %x5D-7E.
func isErrorText(s string, maxLen int) bool {
	if !isASCII(s, printableASCII, maxLen) {
		return false
	}

	return !slices.ContainsFunc([]byte(s), func(b byte) bool { return b == '"' || b == '\\' })
}

// isErrorURI reports whether s fits the RFC 6749 error_uri charset:
// %x21 / %x23-5B / %x5D-7E.
func isErrorURI(s string) bool {
	return isErrorText(s, maxURILength) && !slices.Contains([]byte(s), ' ')
}
