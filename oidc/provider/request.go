// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hyperscale-stack/security/oauth2"
)

// Bounds on the untrusted parameters of an authorization request.
const (
	// MaxNonceLength is the longest nonce, in bytes, an OpenID request may
	// carry (longer: invalid_request). The nonce is otherwise kept as sent —
	// control characters included — save NUL and invalid UTF-8, which no
	// store keeps (OpenID Connect Core §2: no other processing).
	MaxNonceLength = 512
	// maxLoginHintLength drops a longer login_hint (it never fails a
	// request).
	maxLoginHintLength = 1024
	// maxPassthroughLength drops a longer display value.
	maxPassthroughLength = 255
	// maxListTokens keeps the first values of ui_locales, claims_locales
	// and acr_values.
	maxListTokens = 32
	// maxAgeSeconds clamps max_age (2^31-1 seconds, about 68 years).
	maxAgeSeconds = 1<<31 - 1
	// maxAgeDigits is the longest max_age parsed as is; longer is clamped.
	maxAgeDigits = 10
)

// The parameters the provider names more than once.
const (
	paramClientID     = "client_id"
	paramRedirectURI  = "redirect_uri"
	paramNonce        = "nonce"
	paramResponseMode = "response_mode"
	responseTypeCode  = "code"
)

// markerKey marks, in the request context, an authorization request served
// by Provider.AuthorizeHandler.
type markerKey struct{}

// Why an OpenID request fails on the server side; the causes the ErrorHook
// gets, the client gets a bare server_error.
var errNotMounted = errors.New("oidcprovider: OpenID request not served through Provider.AuthorizeHandler")

// authRequest is the provider's validated, immutable view of an
// authorization request — what ValidateAuthorizeRequest hands the server as
// AuthorizeRequest.ExtensionRequest. The application only ever gets copies
// of it ([Request]).
type authRequest struct {
	openID        bool
	issuer        string
	client        oauth2.Client
	redirectURI   string
	scopes        []string
	receivedAt    time.Time
	prompt        Prompt
	maxAge        *time.Duration
	acrValues     []string
	essentialACR  []string
	subjects      []string
	claims        ClaimsRequest
	loginHint     string
	display       string
	uiLocales     []string
	claimsLocales []string
	offline       bool
}

// public returns a deep copy of v for the application.
func (v *authRequest) public() *Request {
	req := &Request{
		Issuer: v.issuer, Client: v.client, RedirectURI: v.redirectURI, Scopes: slices.Clone(v.scopes),
		OpenID: v.openID, ReceivedAt: v.receivedAt, Prompt: v.prompt, ACRValues: slices.Clone(v.acrValues),
		EssentialACR: slices.Clone(v.essentialACR), Subjects: slices.Clone(v.subjects), Claims: v.claims.clone(),
		LoginHint: v.loginHint, Display: v.display, UILocales: slices.Clone(v.uiLocales),
		ClaimsLocales: slices.Clone(v.claimsLocales), OfflineAccess: v.offline,
	}

	if v.maxAge != nil {
		maxAge := *v.maxAge
		req.MaxAge = &maxAge
	}

	return req
}

// validateRequest validates the OpenID parameters of an authorization
// request the core validated (client, redirect URI, response mode and type,
// scope, PKCE) and returns the provider's view of it. A request without the
// openid scope is an OAuth 2.0 one: nothing of OpenID Connect is parsed.
func (p *Provider) validateRequest(ctx context.Context, r *http.Request, ar *oauth2.AuthorizeRequest) (*authRequest, error) {
	scopes := strings.Fields(ar.Scope)
	view := &authRequest{
		openID: slices.Contains(scopes, ScopeOpenID), issuer: ar.Issuer, client: ar.Client,
		redirectURI: ar.RedirectURI, scopes: scopes, receivedAt: p.now(),
	}

	if !view.openID {
		return view, nil
	}

	// Answers that MUST NOT be redirected come first.
	if err := checkRedirection(r.Form); err != nil {
		return nil, err
	}

	if ctx.Value(markerKey{}) != p {
		return nil, errNotMounted
	}

	if _, err := p.parseIssuer(ar.Issuer); err != nil {
		return nil, err
	}

	if err := checkProtocol(r.Form, ar); err != nil {
		return nil, err
	}

	if err := view.parseParameters(r.Form); err != nil {
		return nil, err
	}

	if err := p.designate(ctx, r.Form, view); err != nil {
		return nil, err
	}

	return view, nil
}

// coreParameters are the parameters the oauth2 core reads — the first
// occurrence of each.
var coreParameters = []string{
	paramClientID, paramRedirectURI, paramResponseMode, "response_type", "scope", "state",
	"code_challenge", "code_challenge_method", paramNonce,
}

// providerParameters are the OpenID parameters the provider reads.
var providerParameters = []string{
	"display", "prompt", "max_age", "ui_locales", "claims_locales", "id_token_hint",
	"login_hint", "acr_values", "claims", "request", "request_uri", "registration",
}

// unredirectableParameters, repeated, leave the target or the encoding of
// the answer ambiguous.
var unredirectableParameters = []string{paramClientID, paramRedirectURI, paramResponseMode}

// repeated reports whether form carries name more than once (RFC 6749 §3.1:
// "MUST NOT be included more than once"). An empty value is an omitted one
// (§3.1), so it is no repetition — except before a value the core reads: it
// reads the first occurrence, and would ignore the value that follows.
func repeated(form url.Values, name string) bool {
	values := form[name]
	nonEmpty := 0

	for _, v := range values {
		if v != "" {
			nonEmpty++
		}
	}

	if nonEmpty > 1 {
		return true
	}

	return nonEmpty == 1 && values[0] == "" && slices.Contains(coreParameters, name)
}

// value returns the value of name in form — its non-empty occurrence, if
// any (RFC 6749 §3.1: empty = omitted).
func value(form url.Values, name string) string {
	for _, v := range form[name] {
		if v != "" {
			return v
		}
	}

	return ""
}

// checkRedirection refuses, with a bare 400, an OpenID request whose answer
// could not be redirected safely: a repeated client_id, redirect_uri or
// response_mode, or no redirect_uri — REQUIRED for OpenID requests (Core
// §3.1.2.1), even when the client registered a single one (RFC 6749
// §4.1.2.1, Core §3.1.2.6).
func checkRedirection(form url.Values) error {
	for _, name := range unredirectableParameters {
		if repeated(form, name) {
			return fmt.Errorf("%w: a repeated %s", oauth2.ErrUnredirectableRequest, name)
		}
	}

	if value(form, paramRedirectURI) == "" {
		return fmt.Errorf("%w: an OpenID request without redirect_uri", oauth2.ErrUnredirectableRequest)
	}

	return nil
}

// checkProtocol refuses what an OpenID request cannot use: another
// response type than code (Core §3: OpenID Connect does not use token),
// a repeated parameter, a request object (Core §6) or a registration
// parameter (Core §7.2.1).
func checkProtocol(form url.Values, ar *oauth2.AuthorizeRequest) error {
	if ar.ResponseType != responseTypeCode {
		return oauth2.ErrUnsupportedResponseType.WithDescription("OpenID Connect requests use the code response type")
	}

	for _, list := range [][]string{coreParameters, providerParameters} {
		for _, name := range list {
			if repeated(form, name) {
				return oauth2.ErrInvalidRequest.WithDescription("a request parameter is repeated")
			}
		}
	}

	switch {
	case value(form, "request") != "":
		return oauth2.ErrRequestNotSupported
	case value(form, "request_uri") != "":
		return oauth2.ErrRequestURINotSupported
	case value(form, "registration") != "":
		return oauth2.ErrRegistrationNotSupported
	}

	if err := checkNonce(ar.Nonce); err != nil {
		return err
	}

	return nil
}

// checkNonce bounds the nonce: at most MaxNonceLength bytes of UTF-8
// without NUL.
func checkNonce(nonce string) error {
	if len(nonce) > MaxNonceLength || !utf8.ValidString(nonce) || strings.IndexByte(nonce, 0) >= 0 {
		return oauth2.ErrInvalidRequest.WithDescription("the nonce is too long or not valid UTF-8")
	}

	return nil
}

// parseParameters parses prompt, max_age, claims and the passthrough
// parameters into v.
func (v *authRequest) parseParameters(form url.Values) error {
	prompt, err := parsePrompt(value(form, "prompt"))
	if err != nil {
		return err
	}

	maxAge, err := parseMaxAge(value(form, "max_age"))
	if err != nil {
		return err
	}

	claims, err := parseClaimsParameter(value(form, "claims"))
	if err != nil {
		return err
	}

	v.prompt, v.maxAge, v.claims = prompt, maxAge, claims
	v.essentialACR = claims.essentialACR()
	v.offline = slices.Contains(v.scopes, ScopeOfflineAccess)

	v.acrValues = tokens(value(form, "acr_values"))
	v.uiLocales = tokens(value(form, "ui_locales"))
	v.claimsLocales = tokens(value(form, "claims_locales"))
	v.display = bounded(value(form, "display"), maxPassthroughLength)
	v.loginHint = bounded(value(form, "login_hint"), maxLoginHintLength)

	return nil
}

// parsePrompt parses prompt (Core §3.1.2.1): space-delimited,
// case-sensitive; unknown values are ignored; none with any other value is
// refused.
func parsePrompt(raw string) (Prompt, error) {
	var (
		prompt Prompt
		count  int
	)

	for _, v := range strings.Split(raw, " ") {
		if v == "" {
			continue
		}

		count++

		switch v {
		case "none":
			prompt.None = true
		case "login":
			prompt.Login = true
		case "consent":
			prompt.Consent = true
		case "select_account":
			prompt.SelectAccount = true
		}
	}

	if prompt.None && count > 1 {
		return Prompt{}, oauth2.ErrInvalidRequest.WithDescription("prompt none cannot be combined with other values")
	}

	return prompt, nil
}

// parseMaxAge parses max_age (Core §3.1.2.1): decimal digits; a value over
// maxAgeSeconds is clamped — it only loosens the constraint.
func parseMaxAge(raw string) (*time.Duration, error) {
	if raw == "" {
		return nil, nil
	}

	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '9' {
			return nil, oauth2.ErrInvalidRequest.WithDescription("max_age is not a number of seconds")
		}
	}

	seconds := int64(maxAgeSeconds)

	if digits := strings.TrimLeft(raw, "0"); len(digits) <= maxAgeDigits {
		parsed, _ := strconv.ParseInt("0"+digits, 10, 64) // at most 10 digits: no overflow
		seconds = min(parsed, maxAgeSeconds)
	}

	maxAge := time.Duration(seconds) * time.Second

	return &maxAge, nil
}

// tokens splits a space-delimited parameter (Core §14), keeping its first
// maxListTokens valid UTF-8 values; it never fails.
func tokens(raw string) []string {
	if !utf8.ValidString(raw) {
		return nil
	}

	var out []string

	for _, v := range strings.Split(raw, " ") {
		if v != "" && len(out) < maxListTokens {
			out = append(out, v)
		}
	}

	return out
}

// bounded returns raw when it is valid UTF-8 of at most limit bytes, and
// "" — the parameter ignored — otherwise.
func bounded(raw string, limit int) string {
	if len(raw) > limit || !utf8.ValidString(raw) {
		return ""
	}

	return raw
}

// designate verifies the id_token_hint, derives the end-users the request
// designates (Core §3.1.2.2, §5.5.1), and checks the client's ID Token
// signing algorithm has a key — before any interaction.
func (p *Provider) designate(ctx context.Context, form url.Values, v *authRequest) error {
	snap, err := p.keys(ctx, v.issuer)
	if err != nil {
		return err
	}

	if _, err := signingKey(snap, v.client); err != nil {
		return err
	}

	hint, err := p.verifyHint(ctx, value(form, "id_token_hint"), v.issuer, v.client.ID(), snap)
	if err != nil {
		return err
	}

	subjects := v.claims.subjects()
	if hint != "" {
		subjects = intersect(subjects, []string{hint})
	}

	if subjects != nil && len(subjects) == 0 {
		return oauth2.ErrInvalidRequest.WithDescription("the request designates conflicting end-users")
	}

	v.subjects = subjects

	return nil
}

// intersect returns the values of b also in a — b itself when a is nil
// (no constraint yet).
func intersect(a, b []string) []string {
	if a == nil {
		return b
	}

	out := []string{}

	for _, v := range b {
		if slices.Contains(a, v) {
			out = append(out, v)
		}
	}

	return out
}
