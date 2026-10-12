// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/oauth2"
)

// maxUserInfoBody bounds a form-encoded UserInfo request body, in bytes.
const maxUserInfoBody = 16 << 10

// paramAccessToken is the form-encoded body parameter of RFC 6750 §2.2.
const paramAccessToken = "access_token"

// RFC 6750 §3.1 error codes.
const (
	codeInvalidToken      = "invalid_token"
	codeInsufficientScope = "insufficient_scope"
)

// The UserInfo refusals (RFC 6750 §3.1). The client gets the code and the
// fixed description in the Bearer challenge; the ErrorHook gets the error
// with its cause — never the token.
var (
	errBearerRequest = &oauth2.Error{
		Code: oauth2.CodeInvalidRequest, Description: "The request does not carry exactly one well-formed bearer token.",
		Cause: security.ErrInvalidCredentials,
	}
	errBearerToken = &oauth2.Error{
		Code: codeInvalidToken, Description: "The access token is invalid, expired or revoked.",
		Cause: security.ErrInvalidCredentials,
	}
	errBearerScope = &oauth2.Error{
		Code: codeInsufficientScope, Description: "The access token does not grant the openid scope.",
		Cause: security.ErrInsufficientScope,
	}
)

// Why a UserInfo request is refused, or fails.
var (
	errTokenMethods  = errors.New("oidcprovider: the bearer token is sent more than once")
	errTokenMissing  = errors.New("oidcprovider: a bearer token method without a token")
	errTokenBody     = errors.New("oidcprovider: unreadable or oversized form body")
	errTokenSyntax   = errors.New("oidcprovider: the bearer token is not a b64token")
	errTokenIssuer   = errors.New("oidcprovider: the access token belongs to another issuer")
	errTokenContext  = errors.New("oidcprovider: the access token carries no OpenID grant context")
	errNoAccessToken = errors.New("oidcprovider: the store returned neither an access token nor an error")
)

// bearerError is a UserInfo refusal: the RFC 6750 error the client gets.
// Only this file creates it, so a ClaimsSource or store error is never
// mistaken for one.
type bearerError struct{ oe *oauth2.Error }

func (e *bearerError) Error() string { return e.oe.Error() }

func (e *bearerError) Unwrap() error { return e.oe }

// status returns the HTTP status of the refusal (RFC 6750 §3.1).
func (e *bearerError) status() int {
	switch e.oe.Code {
	case oauth2.CodeInvalidRequest:
		return http.StatusBadRequest
	case codeInsufficientScope:
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}

// refuse returns the refusal oe, caused by cause when not nil.
func refuse(oe *oauth2.Error, cause error) error {
	if cause != nil {
		oe = oe.WithCause(cause)
	}

	return &bearerError{oe: oe}
}

// UserInfoHandler returns the UserInfo endpoint (OpenID Connect Core §5.3)
// of the request's issuer. It serves GET and POST (others: 405) with the
// access token sent as a bearer token (RFC 6750 §2): in the Authorization
// header or, on a form-encoded POST, in the body — a URI query token is not
// supported, and is ignored when alone. It answers the claims the token's
// grant may release — those of its scopes (Core §5.4) and the userinfo
// claim requests the end-user agreed to (§5.5) — from the [ClaimsSource],
// filtered as for ID Tokens, with sub the token's subject: the ID Token's
// (§5.3.2). The response is JSON, never cached.
//
// The access token MUST be unexpired, issued under the request's issuer to
// an OpenID grant — a client_credentials or plain OAuth 2.0 token is not —
// of a client still registered at that issuer (removed, or bound to other
// issuers through oauth2.IssuerBoundClient, it holds no valid token), and
// outside any revoked family; its scope MUST hold openid. Refusals
// follow RFC 6750 §3: a Bearer challenge whose realm is the issuer, without
// error information when the request carries no bearer token,
// invalid_request (400), invalid_token (401) or insufficient_scope (403)
// otherwise, each reported to the ErrorHook. A storage, claims source or
// issuer failure answers 500 without a challenge (Core §5.3.3).
//
// Mount it at [Paths].UserInfo for GET and POST; CORS, when browsers call
// it, is the application's middleware.
func (p *Provider) UserInfoHandler() http.Handler {
	return http.HandlerFunc(p.serveUserInfo)
}

func (p *Provider) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "oidcprovider: method not allowed", http.StatusMethodNotAllowed)

		return
	}

	issuer, err := p.resolveIssuer(r)
	if err != nil {
		p.failInternal(w, r, err)

		return
	}

	token, err := bearerToken(r)
	if err == nil && token == "" {
		// No authentication information: no error information either
		// (RFC 6750 §3.1).
		w.Header().Set("WWW-Authenticate", bearerChallenge(issuer, nil))
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	var claims map[string]any
	if err == nil {
		claims, err = p.userInfo(r.Context(), issuer, token)
	}

	var refusal *bearerError

	switch {
	case errors.As(err, &refusal):
		p.notify(r.Context(), refusal.oe)
		w.Header().Set("WWW-Authenticate", bearerChallenge(issuer, refusal.oe))
		w.WriteHeader(refusal.status())

		return
	case err != nil:
		p.failInternal(w, r, err)

		return
	}

	body, err := json.Marshal(claims)
	if err != nil {
		p.failInternal(w, r, fmt.Errorf("oidcprovider: encode UserInfo response: %w", err))

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(body)
}

// userInfo returns the UserInfo claims of the bearer token, a refusal, or a
// server-side failure.
func (p *Provider) userInfo(ctx context.Context, issuer, token string) (map[string]any, error) {
	at, gc, err := p.userInfoGrant(ctx, issuer, token)
	if err != nil {
		return nil, err
	}

	allowed := p.names.releaseSet(gc.UserInfo, strings.Fields(at.Scope))

	src, err := p.cfg.Claims.Claims(ctx, ClaimsQuery{
		Issuer: issuer, Subject: at.Subject, ClientID: at.ClientID, Target: ClaimsForUserInfo, Names: queryNames(allowed),
	})
	if err != nil {
		return nil, sourceFailure(err, func(e error) error { return refuse(errBearerToken, e) })
	}

	claims, err := releaseClaims(src, allowed)
	if err != nil {
		return nil, err
	}

	claims[claimSub] = at.Subject

	return claims, nil
}

// userInfoGrant returns the record of an access token valid at UserInfo and
// the context of its grant, or why it is refused.
func (p *Provider) userInfoGrant(ctx context.Context, issuer, token string) (*oauth2.AccessToken, grantContext, error) {
	if !isB64Token(token) {
		return nil, grantContext{}, refuse(errBearerToken, errTokenSyntax)
	}

	at, err := p.tokens.LookupAccessToken(ctx, oauth2.HashToken(nil, token))

	switch {
	case oauth2.IsCode(err) == oauth2.CodeInvalidGrant:
		// Unknown, or its family revoked.
		return nil, grantContext{}, refuse(errBearerToken, err)
	case err != nil:
		return nil, grantContext{}, fmt.Errorf("oidcprovider: access token lookup: %w", err)
	case at == nil:
		return nil, grantContext{}, errNoAccessToken
	}

	gc, present, ctxErr := decodeContext(at.ExtensionData)

	var cause error

	switch {
	case at.IsExpired(p.now()):
		cause = security.ErrTokenExpired
	case at.Issuer != issuer:
		cause = errTokenIssuer
	case !present:
		// No context, or one this version cannot read.
		cause = errors.Join(errTokenContext, ctxErr)
	}

	if cause != nil {
		return nil, grantContext{}, refuse(errBearerToken, cause)
	}

	if err := p.checkTokenClient(ctx, at.ClientID, issuer); err != nil {
		return nil, grantContext{}, err
	}

	if !hasScope(at.Scope, ScopeOpenID) {
		return nil, grantContext{}, refuse(errBearerScope, nil)
	}

	return at, gc, nil
}

// checkTokenClient refuses a token whose client is no longer registered at
// issuer — removed, or bound to other issuers (oauth2.IssuerBoundClient):
// it holds no valid token here.
func (p *Provider) checkTokenClient(ctx context.Context, clientID, issuer string) error {
	client, err := p.clients.LoadClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("oidcprovider: load the access token's client: %w", err)
	}

	if client == nil || !oauth2.ClientAllowsIssuer(client, issuer) {
		return refuse(errBearerToken, oauth2.ErrClientNotAtIssuer)
	}

	return nil
}

// bearerToken returns the bearer token of r — "" when r carries none — or
// an invalid_request refusal (RFC 6750 §2, §3.1): the token sent by more
// than one method, a method without a token, an unreadable form body. A URI
// query token (§2.3) is not supported: alone, it is no token.
func bearerToken(r *http.Request) (string, error) {
	header, err := headerToken(r.Header)
	if err != nil {
		return "", refuse(errBearerRequest, err)
	}

	body, err := bodyToken(r)
	if err != nil {
		return "", refuse(errBearerRequest, err)
	}

	methods := 0

	for _, used := range []bool{header != "", body != "", r.URL.Query().Has(paramAccessToken)} {
		if used {
			methods++
		}
	}

	if methods > 1 {
		return "", refuse(errBearerRequest, errTokenMethods)
	}

	return header + body, nil
}

// headerToken returns the token of a Bearer Authorization header (RFC 6750
// §2.1, the scheme case-insensitive) — "" without one, or with another
// scheme.
func headerToken(h http.Header) (string, error) {
	values := h.Values("Authorization")

	switch len(values) {
	case 0:
		return "", nil
	case 1:
	default:
		return "", errTokenMethods
	}

	scheme, rest, _ := strings.Cut(values[0], " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", nil
	}

	token := strings.TrimLeft(rest, " ")
	if token == "" {
		return "", errTokenMissing
	}

	return token, nil
}

// bodyToken returns the access_token of a form-encoded POST body (RFC 6750
// §2.2) — "" without one —, reading at most maxUserInfoBody bytes.
func bodyToken(r *http.Request) (string, error) {
	if r.Method != http.MethodPost || r.Body == nil || !isFormEncoded(r) {
		return "", nil
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxUserInfoBody+1))
	if err != nil {
		return "", fmt.Errorf("%w: %w", errTokenBody, err)
	}

	if len(raw) > maxUserInfoBody {
		return "", errTokenBody
	}

	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return "", fmt.Errorf("%w: %w", errTokenBody, err)
	}

	values := form[paramAccessToken]

	switch {
	case len(values) == 0:
		return "", nil
	case len(values) > 1:
		return "", errTokenMethods
	case values[0] == "":
		return "", errTokenMissing
	}

	return values[0], nil
}

// isFormEncoded reports whether the body of r is
// application/x-www-form-urlencoded.
func isFormEncoded(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))

	return err == nil && mediaType == "application/x-www-form-urlencoded"
}

// isB64Token reports whether s matches the b64token of RFC 6750 §2.1:
// 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
func isB64Token(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}

	for i := range len(body) {
		if !isB64TokenChar(body[i]) {
			return false
		}
	}

	return true
}

// isB64TokenChar reports whether c may precede the padding of a b64token.
func isB64TokenChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	default:
		return strings.IndexByte("-._~+/", c) >= 0
	}
}

// bearerChallenge returns the Bearer challenge of realm (RFC 6750 §3): with
// the error of oe when not nil — and, for insufficient_scope, the scope the
// endpoint requires.
func bearerChallenge(realm string, oe *oauth2.Error) string {
	var b strings.Builder

	b.WriteString("Bearer realm=" + quotedString(realm))

	if oe != nil {
		b.WriteString(", error=" + quotedString(oe.Code))
		b.WriteString(", error_description=" + quotedString(oe.Description))

		if oe.Code == codeInsufficientScope {
			b.WriteString(", scope=" + quotedString(ScopeOpenID))
		}
	}

	return b.String()
}

// quotedString returns s as an HTTP quoted-string (RFC 9110 §5.6.4): '"'
// and '\' escaped.
func quotedString(s string) string {
	var b strings.Builder

	b.WriteByte('"')

	for i := range len(s) {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}

		b.WriteByte(s[i])
	}

	b.WriteByte('"')

	return b.String()
}
