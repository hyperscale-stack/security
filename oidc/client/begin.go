// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// AuthOptions bounds.
const (
	maxLoginHintLength   = 1024
	maxIDTokenHintLength = 64 << 10
	maxTokenValueLength  = 256
	maxExtraParams       = 20
	maxExtraNameLength   = 64
	maxExtraValueLength  = 2048
)

// AuthOptions are the per-login parameters of an authorization request
// (OpenID Connect Core §3.1.2.1). Selecting the connection is the
// application's job; these are hints to the chosen provider.
type AuthOptions struct {
	// LoginHint is passed as login_hint (at most 1024 bytes of UTF-8,
	// without control characters).
	LoginHint string
	// IDTokenHint is passed as id_token_hint.
	IDTokenHint string
	// Prompt values are passed space-separated as prompt; "none" cannot
	// be combined with another value.
	Prompt []string
	// MaxAge, when set, is passed in whole seconds as max_age and makes
	// auth_time REQUIRED in the ID Token and no older than MaxAge before
	// the request (minus the clock skew). MaxAge 0 is the way to verify a
	// fresh authentication: prompt=login alone cannot be checked.
	MaxAge *time.Duration
	// ACRValues are passed space-separated as acr_values. When set, the ID
	// Token MUST carry an acr that is one of them, or the login fails with
	// ErrIDTokenACR: list every level you accept, and send none if you do
	// not want the check.
	ACRValues []string
	// UILocales are passed space-separated as ui_locales.
	UILocales []string
	// Display is passed as display.
	Display string
	// ExtraParams are other request parameters (domain_hint, hd,
	// kc_idp_hint…): at most 20, names of letters, digits, '.', '_' or '-'.
	// The parameters the Client sends or does not support are refused —
	// request and request_uri included, which could override state, nonce
	// or PKCE.
	ExtraParams map[string]string
	// AppState is application data stored with the transaction and
	// returned in Identity (at most 4096 bytes of UTF-8). It is not sent to
	// the provider. Validate it before using it as a redirect target.
	AppState string
}

// AuthRequest is a started login.
type AuthRequest struct {
	// URL is the authorization request: send the user agent to it.
	URL string
	// State is the state parameter, also carried by URL.
	State string
	// Binding is the browser-binding secret of the login. The user agent
	// that started the login MUST keep it — the net/http helpers put it in
	// an HttpOnly __Host- cookie — and present it at the callback. It never
	// leaves the Relying Party and the user agent: never log it.
	Binding string
	// ExpiresAt is when the login expires.
	ExpiresAt time.Time
}

// String implements fmt.Stringer without the binding secret.
func (r AuthRequest) String() string {
	return fmt.Sprintf("oidcclient.AuthRequest{URL: %q, ExpiresAt: %s, Binding: REDACTED}", r.URL, r.ExpiresAt.Format(time.RFC3339))
}

// GoString implements fmt.GoStringer without the binding secret.
func (r AuthRequest) GoString() string { return r.String() }

// LogValue implements slog.LogValuer without the binding secret.
func (r AuthRequest) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", r.URL), slog.Time("expires_at", r.ExpiresAt), slog.String("binding", "REDACTED"))
}

// Begin starts a login: it stores a Transaction and returns the
// authorization request — Authorization Code with PKCE S256 (RFC 7636),
// fresh state and nonce. The state and the binding secret come from
// crypto/rand (256 bits); the nonce, the PKCE verifier and the
// transaction's integrity key are derived from the binding secret, so the
// store holds no secret. Nothing is returned
// when the store fails. Begin writes to the store on every call: rate-limit
// login starts.
func (c *Client) Begin(ctx context.Context, opts AuthOptions) (*AuthRequest, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	state, binding := newSecret(), newSecret()
	secret, _ := decodeSecret(binding) // newSecret output always decodes

	created := time.Unix(c.now().Unix(), 0).UTC()
	tx := &Transaction{
		StateHash:    stateHashFor(state),
		BindingHash:  bindingHashFor(secret),
		ConnectionID: c.cfg.ConnectionID,
		Issuer:       c.md.Issuer,
		ClientID:     c.cfg.ClientID,
		RedirectURI:  c.cfg.RedirectURL,
		ResponseMode: c.cfg.ResponseMode,
		MaxAge:       maxAgeSeconds(opts.MaxAge),
		ACRValues:    strings.Join(opts.ACRValues, " "),
		AppState:     opts.AppState,
		CreatedAt:    created,
		ExpiresAt:    created.Add(c.cfg.TransactionTTL),
	}
	tx.Integrity = integrityFor(secret, tx)

	if err := c.cfg.Store.Save(ctx, tx); err != nil {
		return nil, fmt.Errorf("oidcclient: save login transaction: %w", err)
	}

	return &AuthRequest{
		URL:       c.authorizationURL(state, secret, opts),
		State:     state,
		Binding:   binding,
		ExpiresAt: tx.ExpiresAt,
	}, nil
}

func maxAgeSeconds(maxAge *time.Duration) int64 {
	if maxAge == nil {
		return NoMaxAge
	}

	return int64(*maxAge / time.Second)
}

// authorizationURL builds the request on the authorization endpoint,
// retaining its query (RFC 6749 §3.1).
func (c *Client) authorizationURL(state string, secret []byte, opts AuthOptions) string {
	params := url.Values{
		paramResponseType:        {responseTypeCode},
		paramClientID:            {c.cfg.ClientID},
		paramRedirectURI:         {c.cfg.RedirectURL},
		paramScope:               {strings.Join(c.cfg.Scopes, " ")},
		paramState:               {state},
		paramNonce:               {nonceFor(secret)},
		paramCodeChallenge:       {challengeFor(verifierFor(secret))},
		paramCodeChallengeMethod: {methodS256},
	}

	if c.cfg.ResponseMode == ResponseModeFormPost {
		params.Set(paramResponseMode, string(ResponseModeFormPost))
	}

	setNonEmpty(params, "login_hint", opts.LoginHint)
	setNonEmpty(params, "id_token_hint", opts.IDTokenHint)
	setNonEmpty(params, "prompt", strings.Join(opts.Prompt, " "))
	setNonEmpty(params, "acr_values", strings.Join(opts.ACRValues, " "))
	setNonEmpty(params, "ui_locales", strings.Join(opts.UILocales, " "))
	setNonEmpty(params, "display", opts.Display)

	if opts.MaxAge != nil {
		params.Set("max_age", strconv.FormatInt(maxAgeSeconds(opts.MaxAge), 10))
	}

	for name, value := range opts.ExtraParams {
		params.Set(name, value)
	}

	u := *c.authURL
	if u.RawQuery != "" {
		u.RawQuery += "&" + params.Encode()
	} else {
		u.RawQuery = params.Encode()
	}

	return u.String()
}

func setNonEmpty(params url.Values, name, value string) {
	if value != "" {
		params.Set(name, value)
	}
}

// validate checks the options before anything is stored.
func (o AuthOptions) validate() error {
	if err := validatePrompt(o.Prompt); err != nil {
		return err
	}

	if o.MaxAge != nil && (*o.MaxAge < 0 || *o.MaxAge/time.Second > maxMaxAge) {
		return fmt.Errorf("%w: MaxAge must be between 0 and 2^31-1 seconds", ErrInvalidAuthRequest)
	}

	if !validTokens(o.ACRValues) || !validTokens(o.UILocales) || len(strings.Join(o.ACRValues, " ")) > maxACRValuesLength {
		return fmt.Errorf("%w: ACRValues and UILocales must be non-empty visible ASCII tokens", ErrInvalidAuthRequest)
	}

	if o.Display != "" && !isASCII(o.Display, visibleASCII, maxTokenValueLength) {
		return fmt.Errorf("%w: Display must be a visible ASCII token", ErrInvalidAuthRequest)
	}

	if !validText(o.LoginHint, maxLoginHintLength) {
		return fmt.Errorf("%w: LoginHint must be at most 1024 bytes of UTF-8 without control characters", ErrInvalidAuthRequest)
	}

	if o.IDTokenHint != "" && !isASCII(o.IDTokenHint, visibleASCII, maxIDTokenHintLength) {
		return fmt.Errorf("%w: IDTokenHint must be a compact JWT", ErrInvalidAuthRequest)
	}

	if len(o.AppState) > maxAppStateLength || !utf8.ValidString(o.AppState) {
		return fmt.Errorf("%w: AppState must be at most 4096 bytes of UTF-8", ErrInvalidAuthRequest)
	}

	return validateExtraParams(o.ExtraParams)
}

// validatePrompt checks the prompt values (Core §3.1.2.1: none with any
// other value is an error).
func validatePrompt(prompt []string) error {
	if !validTokens(prompt) {
		return fmt.Errorf("%w: Prompt values must be non-empty visible ASCII tokens", ErrInvalidAuthRequest)
	}

	if len(prompt) > 1 && slices.Contains(prompt, "none") {
		return fmt.Errorf("%w: prompt none cannot be combined with another value", ErrInvalidAuthRequest)
	}

	return nil
}

func validateExtraParams(params map[string]string) error {
	if len(params) > maxExtraParams {
		return fmt.Errorf("%w: at most %d ExtraParams", ErrInvalidAuthRequest, maxExtraParams)
	}

	for name, value := range params {
		switch {
		case !isParamName(name):
			return fmt.Errorf("%w: invalid ExtraParams name %q", ErrInvalidAuthRequest, name)
		case slices.Contains(reservedRequestParams, name):
			return fmt.Errorf("%w: ExtraParams cannot set %q", ErrInvalidAuthRequest, name)
		case !validText(value, maxExtraValueLength):
			return fmt.Errorf("%w: invalid ExtraParams value for %q", ErrInvalidAuthRequest, name)
		}
	}

	return nil
}

// validTokens reports whether every value is a non-empty visible ASCII
// token (no space: the values are joined with spaces).
func validTokens(values []string) bool {
	for _, v := range values {
		if !isASCII(v, visibleASCII, maxTokenValueLength) {
			return false
		}
	}

	return true
}

// validText reports whether s is at most maxLen bytes of UTF-8 without
// control characters.
func validText(s string, maxLen int) bool {
	if len(s) > maxLen || !utf8.ValidString(s) {
		return false
	}

	return !strings.ContainsFunc(s, unicode.IsControl)
}

// isParamName reports whether name is 1 to 64 letters, digits, '.', '_'
// or '-'.
func isParamName(name string) bool {
	if name == "" || len(name) > maxExtraNameLength {
		return false
	}

	for i := range len(name) {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}

	return true
}
