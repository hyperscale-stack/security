// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
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
	// IDTokenHint is passed as id_token_hint: an ID Token the provider
	// issued earlier, such as Identity.Tokens.IDToken. It never prints,
	// logs nor encodes (see Secret).
	IDTokenHint Secret
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
	// No parameter is ever sent twice (RFC 6749 §3.1), and names that
	// differ only by case, or by '.' for '_', are one parameter: servers
	// that ignore case (ASP.NET) or rewrite names (PHP) read them so.
	// Refused, in any such spelling: the parameters the Client sends or
	// does not support — request and request_uri included, which could
	// override state, nonce or PKCE — the parameters of the authorization
	// endpoint's own query, which the request keeps, and two entries that
	// are one parameter.
	ExtraParams map[string]string
	// AppState is application data stored with the transaction and
	// returned in Identity (at most 4096 bytes of UTF-8). It is not sent to
	// the provider. Validate it before using it as a redirect target.
	AppState string
}

// AuthRequest is a started login. It prints and logs (String, GoString,
// Format, LogValue) without its binding secret, its state nor the query of
// its URL — with a leaked state, a request to the callback through the
// victim's own browser burns the pending login. It encodes to JSON
// (MarshalJSON), the hand-off of the request to a front end, with its URL
// and state but without its binding secret: never log it nested in another
// value under log/slog's JSON handler.
type AuthRequest struct {
	// URL is the authorization request: send the user agent to it.
	URL string
	// State is the state parameter, also carried by URL.
	State string
	// Binding is the browser-binding secret of the login. The user agent
	// that started the login MUST keep it — the net/http helpers put it in
	// an HttpOnly __Host- cookie — and present it at the callback. It never
	// leaves the Relying Party and the user agent: it is a Secret, which
	// never prints, logs nor encodes; Reveal it only to hand it to the user
	// agent.
	Binding Secret `json:"-"`
	// ExpiresAt is when the login expires.
	ExpiresAt time.Time
}

// String implements fmt.Stringer without the binding secret, the state
// nor the URL's query.
func (r AuthRequest) String() string {
	return fmt.Sprintf("oidcclient.AuthRequest{URL: %q, State: REDACTED, ExpiresAt: %s, Binding: REDACTED}",
		requestURLForLogs(r.URL), r.ExpiresAt.Format(time.RFC3339))
}

// GoString implements fmt.GoStringer like String.
func (r AuthRequest) GoString() string { return r.String() }

// LogValue implements slog.LogValuer like String.
func (r AuthRequest) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", requestURLForLogs(r.URL)), slog.String("state", redactedMark),
		slog.Time("expires_at", r.ExpiresAt), slog.String("binding", redactedMark))
}

// requestURLForLogs renders an authorization request URL without its query
// — state, nonce, hints — nor fragment or userinfo; REDACTED when it does
// not parse.
func requestURLForLogs(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactedMark
	}

	return withoutQuery(u)
}

// MarshalJSON implements json.Marshaler with the URL and the state — the
// encoding hands the request to a front end — but without the binding
// secret. log/slog's JSON handler encodes a value nested in another one (a
// struct field, a map) with encoding/json, LogValue applying to attribute
// values only: log an AuthRequest as an attribute of its own. A struct
// embedding AuthRequest is promoted this method and encodes as the
// AuthRequest alone — or, when another type embedded at the same depth
// also has a MarshalJSON, neither is promoted and encoding/json writes the
// exported fields, the binding excluded (json:"-"). Name the field instead
// of embedding it.
func (r AuthRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct { //nolint:wrapcheck // strings only: never fails
		URL       string
		State     string
		ExpiresAt string
		Binding   string
	}{r.URL, r.State, r.ExpiresAt.Format(time.RFC3339Nano), redactedMark})
}

// Begin starts a login: it stores a Transaction and returns the
// authorization request — Authorization Code with PKCE S256 (RFC 7636),
// fresh state and nonce. The state and the binding secret come from
// crypto/rand (256 bits); the nonce and the PKCE verifier are derived from
// the binding secret, so the store holds no secret, and the transaction's
// integrity MAC is keyed by the binding secret and the first transaction
// key (Config.TransactionKeys). Nothing is returned when the store fails.
// Begin writes to the store on every call: rate-limit login starts.
func (c *Client) Begin(ctx context.Context, opts AuthOptions) (*AuthRequest, error) {
	if err := opts.validate(c.md.authParams); err != nil {
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
	tx.Integrity = integrityFor([]byte(c.cfg.TransactionKeys[0].Reveal()), secret, tx)

	if err := c.cfg.Store.Save(ctx, tx); err != nil {
		return nil, fmt.Errorf("oidcclient: save login transaction: %w", err)
	}

	return &AuthRequest{
		URL:       c.authorizationURL(state, secret, opts),
		State:     state,
		Binding:   NewSecret(binding),
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
	setNonEmpty(params, "id_token_hint", opts.IDTokenHint.Reveal())
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

// validate checks the options before anything is stored; endpointParams
// are the paramKeys of the authorization endpoint's query.
func (o AuthOptions) validate(endpointParams map[string]struct{}) error {
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

	if hint := o.IDTokenHint.Reveal(); hint != "" && !isASCII(hint, visibleASCII, maxIDTokenHintLength) {
		return fmt.Errorf("%w: IDTokenHint must be a compact JWT", ErrInvalidAuthRequest)
	}

	if len(o.AppState) > maxAppStateLength || !utf8.ValidString(o.AppState) {
		return fmt.Errorf("%w: AppState must be at most 4096 bytes of UTF-8", ErrInvalidAuthRequest)
	}

	return validateExtraParams(o.ExtraParams, endpointParams)
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

// validateExtraParams checks AuthOptions.ExtraParams, in name order: the
// names and values, and no parameter twice (RFC 6749 §3.1) — none the
// Client sends or does not support, none of the authorization endpoint's
// query (endpointParams), no two entries — names compared by paramKey.
func validateExtraParams(params map[string]string, endpointParams map[string]struct{}) error {
	if len(params) > maxExtraParams {
		return fmt.Errorf("%w: at most %d ExtraParams", ErrInvalidAuthRequest, maxExtraParams)
	}

	seen := make(map[string]struct{}, len(params))

	for _, name := range slices.Sorted(maps.Keys(params)) {
		key := paramKey(name)
		_, inEndpoint := endpointParams[key]
		_, repeated := seen[key]

		switch {
		case !isParamName(name):
			return fmt.Errorf("%w: invalid ExtraParams name %s", ErrInvalidAuthRequest, quoted(name))
		case isReservedParam(key):
			return fmt.Errorf("%w: ExtraParams cannot set %s", ErrInvalidAuthRequest, quoted(name))
		case inEndpoint:
			return fmt.Errorf("%w: ExtraParams cannot set %s, which the authorization endpoint's query sets", ErrInvalidAuthRequest, quoted(name))
		case repeated:
			return fmt.Errorf("%w: ExtraParams name %s repeats another one", ErrInvalidAuthRequest, quoted(name))
		case !validText(params[name], maxExtraValueLength):
			return fmt.Errorf("%w: invalid ExtraParams value for %s", ErrInvalidAuthRequest, quoted(name))
		}

		seen[key] = struct{}{}
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
