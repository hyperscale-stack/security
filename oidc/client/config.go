// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/hyperscale-stack/security/outbound"
)

// Algorithm is a JWS signature algorithm (RFC 7518 §3.1) accepted for ID
// Tokens. Only asymmetric algorithms exist as values: an ID Token MACed
// with the client secret (HS256/384/512) or unsigned ("none") is always
// refused.
type Algorithm string

// The asymmetric algorithms an ID Token may be signed with. EdDSA means
// Ed25519.
const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	EdDSA Algorithm = "EdDSA"
)

// supportedAlgorithms is the default Config.Algorithms.
var supportedAlgorithms = []Algorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

// AuthMethod is a token endpoint client authentication method (OpenID
// Connect Core §9).
type AuthMethod string

// Supported client authentication methods.
const (
	// AuthMethodClientSecretBasic sends the client identifier and secret in
	// an HTTP Basic Authorization header, each form-urlencoded first (RFC
	// 6749 §2.3.1).
	AuthMethodClientSecretBasic AuthMethod = "client_secret_basic"
	// AuthMethodClientSecretPost sends them as client_id and client_secret
	// form parameters.
	AuthMethodClientSecretPost AuthMethod = "client_secret_post"
	// AuthMethodNone sends client_id only: a public client, whose code is
	// protected by PKCE alone — New requires the provider to advertise S256.
	AuthMethodNone AuthMethod = "none"
)

// Defaults and bounds of the Config durations.
const (
	// DefaultTransactionTTL is the lifetime of a login when
	// Config.TransactionTTL is zero.
	DefaultTransactionTTL = 10 * time.Minute
	// MaxTransactionTTL bounds Config.TransactionTTL.
	MaxTransactionTTL = time.Hour
	// DefaultClockSkew is the tolerance applied to ID Token times when
	// Config.ClockSkew is zero.
	DefaultClockSkew = time.Minute
	// MaxClockSkew bounds Config.ClockSkew (OpenID Connect Core §2: "no
	// more than a few minutes").
	MaxClockSkew = 5 * time.Minute
)

// Bounds of Config.TransactionKeys.
const (
	// MinTransactionKeySize is the minimum size of a transaction key, in
	// bytes: 256 bits.
	MinTransactionKeySize = 32
	// MaxTransactionKeys bounds the number of transaction keys: the active
	// one and the keys of a rotation in progress.
	MaxTransactionKeys = 4
)

// responseParams are the authorization response parameters the Client
// interprets (RFC 6749 §4.1.2, §4.1.2.1; RFC 9207 §2); RedirectURL may not
// carry them in its query.
var responseParams = []string{paramCode, paramState, paramError, paramErrorDescription, paramErrorURI, paramIssuer}

// Config is the trusted configuration of one connection: one provider,
// one client registration, one redirect URI. It comes from the
// application, never from a request.
type Config struct {
	// ConnectionID identifies the connection in the application (1 to 255
	// visible ASCII characters). It is bound into every transaction and
	// returned in Identity.
	ConnectionID string

	// Issuer is the provider's issuer identifier, compared byte for byte
	// with the discovery document's and the ID Token's (OpenID Connect
	// Discovery 1.0 §4.3, Core §3.1.3.7). An absolute https URL without
	// query, fragment or userinfo; a trailing slash is significant. For a
	// multi-tenant provider configure the tenant-specific issuer (for
	// Microsoft Entra ID, the tenant ID, not the "common" endpoint).
	Issuer string

	// ClientID is the client identifier registered at the provider.
	ClientID string

	// ClientSecret is the client secret, required for the client_secret_*
	// methods and forbidden for AuthMethodNone.
	ClientSecret string

	// AuthMethod is the token endpoint authentication method. It has no
	// default: choose it explicitly.
	AuthMethod AuthMethod

	// RedirectURL is the callback URL registered at the provider. It MUST
	// be distinct from every other connection's redirect URL — by scheme,
	// host, port, path or query parameter — and should be routed to this
	// Client only: the URL a response is received on is what ties it to its
	// connection (RFC 9700 §4.4.2.2), and Complete refuses a response
	// received on another URL. An absolute https URL (http only for a
	// loopback host), without fragment or userinfo, whose query does not use
	// a response parameter name.
	RedirectURL string

	// Scopes are the requested scopes; "openid" is always sent, first.
	Scopes []string

	// ResponseMode is how the provider returns the response:
	// ResponseModeQuery (default) or ResponseModeFormPost.
	ResponseMode ResponseMode

	// Store persists the pending logins. It MUST be shared by every
	// instance that may serve the callback.
	Store TransactionStore

	// TransactionKeys are the server-held keys of the transactions'
	// integrity MAC. REQUIRED: 1 to MaxTransactionKeys keys of at least
	// MinTransactionKeySize bytes from a cryptographic source, secret like
	// a session key and shared by every instance that may serve the
	// callback. TransactionKeys[0] protects the transactions Begin stores;
	// Complete accepts any of the keys. The MAC key of a transaction
	// derives from both a transaction key and the login's binding secret,
	// so whoever can write to the Store — even from the browser of a login
	// it runs itself, which holds that secret — cannot forge it.
	//
	// Rotate without failing a login: add the new key last on every
	// instance, then move it first, then remove the old key once
	// TransactionTTL has elapsed. A key removed earlier fails the logins it
	// protected with ErrTransactionIntegrity.
	TransactionKeys [][]byte

	// TransactionTTL bounds the time between Begin and the callback, in
	// whole seconds: DefaultTransactionTTL when zero, at most
	// MaxTransactionTTL.
	TransactionTTL time.Duration

	// Algorithms restricts the ID Token signature algorithms; empty means
	// every asymmetric algorithm. The effective set is its intersection
	// with the provider's id_token_signing_alg_values_supported.
	//
	// One algorithm per key (RFC 8725 §3.1): an RSA JWK without "alg" is
	// used for RS256 only — or for the single RSA algorithm of the
	// effective set. A provider signing with PS256/384/512, RS384 or RS512
	// and publishing RSA keys without "alg" therefore needs Algorithms set
	// to that one RSA algorithm, else its ID Tokens fail with
	// ErrUnknownSigningKey.
	Algorithms []Algorithm

	// TrustedAudiences lists the audiences besides ClientID an ID Token may
	// carry (OpenID Connect Core §3.1.3.7: an ID Token with an untrusted
	// additional audience MUST be rejected).
	TrustedAudiences []string

	// ClockSkew is the tolerance applied to exp, iat, nbf and auth_time:
	// DefaultClockSkew when zero, at most MaxClockSkew.
	ClockSkew time.Duration

	// Outbound is the network policy of every request to the provider
	// (discovery, JWK Set, token, UserInfo). Its zero value is strict:
	// https only and publicly routable destinations only; exempt an
	// on-premises provider's subnet in AllowedPrefixes. Token and UserInfo
	// requests never follow redirects, whatever MaxRedirects says.
	//
	// The errors of New, Complete and UserInfo wrap the network errors of
	// allowed destinations, which may name a resolved address and port
	// (refused destinations are never named). When the issuer comes from a
	// tenant, log these errors and show the tenant a generic message.
	Outbound outbound.Policy

	// InsecureCookies makes the net/http helpers set the binding cookie
	// without the __Host- prefix and the Secure attribute, for local
	// development over plain http. Refused with ResponseModeFormPost:
	// browsers refuse SameSite=None cookies that are not Secure.
	InsecureCookies bool

	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// normalized validates c and returns a copy with its defaults applied and
// its slices copied, plus the parsed RedirectURL.
func (c Config) normalized() (Config, *url.URL, error) {
	if err := c.validateClient(); err != nil {
		return Config{}, nil, err
	}

	if err := validateIssuer(c.Issuer, c.Outbound.AllowHTTP); err != nil {
		return Config{}, nil, err
	}

	redirect, err := parseRedirectURL(c.RedirectURL)
	if err != nil {
		return Config{}, nil, err
	}

	if err := c.validateFlow(); err != nil {
		return Config{}, nil, err
	}

	out := c

	if out.Scopes, err = normalizeScopes(c.Scopes); err != nil {
		return Config{}, nil, err
	}

	if out.Algorithms, err = normalizeAlgorithms(c.Algorithms); err != nil {
		return Config{}, nil, err
	}

	out.TrustedAudiences = slices.Clone(c.TrustedAudiences)
	out.TransactionKeys = cloneKeys(c.TransactionKeys)
	out.Outbound.AllowedPrefixes = slices.Clone(c.Outbound.AllowedPrefixes)
	out.applyDefaults()

	return out, redirect, nil
}

func (c *Config) applyDefaults() {
	if c.ResponseMode == "" {
		c.ResponseMode = ResponseModeQuery
	}

	if c.TransactionTTL == 0 {
		c.TransactionTTL = DefaultTransactionTTL
	}

	if c.ClockSkew == 0 {
		c.ClockSkew = DefaultClockSkew
	}

	if c.Now == nil {
		c.Now = time.Now
	}
}

func (c Config) validateClient() error {
	switch {
	case !isASCII(c.ConnectionID, visibleASCII, maxConnectionIDLen):
		return fmt.Errorf("%w: ConnectionID must be 1 to 255 visible ASCII characters", ErrInvalidConfig)
	case !isASCII(c.ClientID, printableASCII, maxClientIDLength):
		return fmt.Errorf("%w: ClientID must be 1 to 2048 printable ASCII characters", ErrInvalidConfig)
	}

	switch c.AuthMethod {
	case AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
		if c.ClientSecret == "" {
			return fmt.Errorf("%w: %s requires ClientSecret", ErrInvalidConfig, c.AuthMethod)
		}
	case AuthMethodNone:
		if c.ClientSecret != "" {
			return fmt.Errorf("%w: a public client (none) has no ClientSecret", ErrInvalidConfig)
		}
	default:
		return fmt.Errorf("%w: unsupported AuthMethod %q", ErrInvalidConfig, c.AuthMethod)
	}

	return nil
}

func (c Config) validateFlow() error {
	switch {
	case c.ResponseMode != "" && c.ResponseMode != ResponseModeQuery && c.ResponseMode != ResponseModeFormPost:
		return fmt.Errorf("%w: unsupported ResponseMode %q", ErrInvalidConfig, c.ResponseMode)
	case c.Store == nil:
		return fmt.Errorf("%w: Store is required", ErrInvalidConfig)
	case c.TransactionTTL < 0 || c.TransactionTTL > MaxTransactionTTL || c.TransactionTTL%time.Second != 0:
		return fmt.Errorf("%w: TransactionTTL must be whole seconds between 0 and %s", ErrInvalidConfig, MaxTransactionTTL)
	case c.ClockSkew < 0 || c.ClockSkew > MaxClockSkew:
		return fmt.Errorf("%w: ClockSkew must be between 0 and %s", ErrInvalidConfig, MaxClockSkew)
	case c.InsecureCookies && c.ResponseMode == ResponseModeFormPost:
		return fmt.Errorf("%w: InsecureCookies cannot carry a form_post callback", ErrInvalidConfig)
	}

	for _, aud := range c.TrustedAudiences {
		if !isASCII(aud, visibleASCII, maxURILength) {
			return fmt.Errorf("%w: TrustedAudiences entries must be 1 to 2048 visible ASCII characters", ErrInvalidConfig)
		}
	}

	return validateTransactionKeys(c.TransactionKeys)
}

// validateTransactionKeys checks Config.TransactionKeys: 1 to
// MaxTransactionKeys keys of at least MinTransactionKeySize bytes. The
// errors never carry key material.
func validateTransactionKeys(keys [][]byte) error {
	if len(keys) == 0 || len(keys) > MaxTransactionKeys {
		return fmt.Errorf("%w: TransactionKeys must hold 1 to %d keys", ErrInvalidConfig, MaxTransactionKeys)
	}

	for _, key := range keys {
		if len(key) < MinTransactionKeySize {
			return fmt.Errorf("%w: every TransactionKeys entry must be at least %d bytes", ErrInvalidConfig, MinTransactionKeySize)
		}
	}

	return nil
}

// cloneKeys returns a deep copy of keys: the Client never shares key
// bytes with its caller.
func cloneKeys(keys [][]byte) [][]byte {
	out := make([][]byte, len(keys))
	for i, key := range keys {
		out[i] = bytes.Clone(key)
	}

	return out
}

// String implements fmt.Stringer with the identifying fields only: the
// client secret and the transaction keys are redacted.
func (c Config) String() string {
	return fmt.Sprintf("oidcclient.Config{ConnectionID: %q, Issuer: %q, ClientID: %q, ClientSecret: %s, AuthMethod: %s, "+
		"RedirectURL: %q, ResponseMode: %s, TransactionKeys: %d REDACTED}",
		c.ConnectionID, c.Issuer, c.ClientID, redacted(c.ClientSecret), c.AuthMethod, c.RedirectURL, c.ResponseMode,
		len(c.TransactionKeys))
}

// GoString implements fmt.GoStringer like String.
func (c Config) GoString() string { return c.String() }

// LogValue implements slog.LogValuer like String.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("connection_id", c.ConnectionID),
		slog.String("issuer", c.Issuer),
		slog.String("client_id", c.ClientID),
		slog.String("client_secret", redacted(c.ClientSecret)),
		slog.String("auth_method", string(c.AuthMethod)),
		slog.String("redirect_url", c.RedirectURL),
		slog.String("response_mode", string(c.ResponseMode)),
		slog.Int("transaction_keys", len(c.TransactionKeys)),
	)
}

// redacted renders a secret as REDACTED, or as "" when it is empty.
func redacted(secret string) string {
	if secret == "" {
		return `""`
	}

	return "REDACTED"
}

// validateIssuer checks an issuer identifier (OpenID Connect Core §2:
// scheme, host, optional port and path, no query or fragment).
func validateIssuer(raw string, allowHTTP bool) error {
	if !isASCII(raw, visibleASCII, maxURILength) {
		return fmt.Errorf("%w: Issuer must be 1 to 2048 visible ASCII characters", ErrInvalidConfig)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: Issuer: %w", ErrInvalidConfig, err)
	}

	switch {
	case u.Scheme != schemeHTTPS && (u.Scheme != schemeHTTP || !allowHTTP):
		return fmt.Errorf("%w: Issuer must use https", ErrInvalidConfig)
	case u.Host == "" || u.Opaque != "":
		return fmt.Errorf("%w: Issuer must be an absolute URL", ErrInvalidConfig)
	case u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#"):
		return fmt.Errorf("%w: Issuer must not carry userinfo, query or fragment", ErrInvalidConfig)
	}

	return nil
}

// parseRedirectURL checks RedirectURL: absolute, https or loopback http
// (RFC 9700 §2.6, OpenID Connect Core §3.1.2.1), no fragment (RFC 6749
// §3.1.2), no userinfo, no response parameter in its query.
func parseRedirectURL(raw string) (*url.URL, error) {
	if !isASCII(raw, visibleASCII, maxURILength) {
		return nil, fmt.Errorf("%w: RedirectURL must be 1 to 2048 visible ASCII characters", ErrInvalidConfig)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: RedirectURL: %w", ErrInvalidConfig, err)
	}

	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"

	switch {
	case u.Scheme != schemeHTTPS && (u.Scheme != schemeHTTP || !loopback):
		return nil, fmt.Errorf("%w: RedirectURL must use https (http only on a loopback host)", ErrInvalidConfig)
	case u.Host == "" || u.Opaque != "":
		return nil, fmt.Errorf("%w: RedirectURL must be an absolute URL", ErrInvalidConfig)
	case u.User != nil || strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%w: RedirectURL must not carry userinfo or a fragment", ErrInvalidConfig)
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: RedirectURL query: %w", ErrInvalidConfig, err)
	}

	for _, name := range responseParams {
		if query.Has(name) {
			return nil, fmt.Errorf("%w: RedirectURL query must not use the response parameter %q", ErrInvalidConfig, name)
		}
	}

	return u, nil
}

// normalizeScopes puts openid first, drops duplicates and checks every
// scope-token (RFC 6749 §3.3).
func normalizeScopes(in []string) ([]string, error) {
	out := []string{"openid"}

	for _, s := range in {
		if !isScopeToken(s) {
			return nil, fmt.Errorf("%w: invalid scope %q", ErrInvalidConfig, s)
		}

		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}

	return out, nil
}

// isScopeToken reports whether s is an RFC 6749 §3.3 scope-token:
// 1*( %x21 / %x23-5B / %x5D-7E ).
func isScopeToken(s string) bool {
	if !isASCII(s, visibleASCII, maxURILength) {
		return false
	}

	return !strings.ContainsAny(s, `"\`)
}

func normalizeAlgorithms(in []Algorithm) ([]Algorithm, error) {
	if len(in) == 0 {
		return slices.Clone(supportedAlgorithms), nil
	}

	out := make([]Algorithm, 0, len(in))

	for _, alg := range in {
		if !slices.Contains(supportedAlgorithms, alg) {
			return nil, fmt.Errorf("%w: unsupported ID Token algorithm %q", ErrInvalidConfig, alg)
		}

		if !slices.Contains(out, alg) {
			out = append(out, alg)
		}
	}

	return out, nil
}
