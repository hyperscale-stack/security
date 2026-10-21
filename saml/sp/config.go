// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Defaults and bounds of [Config].
const (
	// DefaultTransactionTTL is the default lifetime of a login transaction.
	DefaultTransactionTTL = 10 * time.Minute
	// MaxTransactionTTL bounds [Config.TransactionTTL].
	MaxTransactionTTL = time.Hour
	// DefaultClockSkew is the default tolerance applied to every time check
	// (errata E92 suggests 3 to 5 minutes).
	DefaultClockSkew = 3 * time.Minute
	// MaxClockSkew bounds [Config.ClockSkew].
	MaxClockSkew = 5 * time.Minute
	// DefaultMaxResponseSize is the default cap on an ACS request body.
	DefaultMaxResponseSize = 256 << 10
	// MinMaxResponseSize and MaxMaxResponseSize bound [Config.MaxResponseSize].
	MinMaxResponseSize = 16 << 10
	MaxMaxResponseSize = 1 << 20
	// DefaultMetadataCacheDuration is the default cacheDuration published in
	// SP metadata (Metadata §2.3.2 requires validUntil or cacheDuration on
	// the root element).
	DefaultMetadataCacheDuration = 24 * time.Hour
	// DefaultCookieName is the default browser-binding cookie name.
	DefaultCookieName = "__Host-samlsp"
	// MinTransactionKeySize is the minimum size of a transaction key, in
	// bytes: 256 bits, the output size of the HMAC-SHA256 it keys.
	MinTransactionKeySize = 32
	// MaxTransactionKeys bounds Config.TransactionKeys: the active key and
	// the keys of a rotation in progress.
	MaxTransactionKeys = 4
)

// Config configures a [ServiceProvider]. The SP entity IDs and ACS URLs are
// per connection ([Connection]); Config holds what all connections share.
type Config struct {
	// SigningKey, when set, signs every AuthnRequest (HTTP-Redirect binding
	// signature, Bindings §3.4.4.1, rsa-sha256). RSA of at least 2048 bits
	// only; it may be backed by an HSM or a KMS. Required by connections
	// whose IdP sets WantAuthnRequestsSigned.
	SigningKey crypto.Signer

	// SigningCertificate is the certificate of SigningKey, published with
	// use="signing" in every connection's SP metadata. Required with
	// SigningKey, forbidden without it.
	SigningCertificate *x509.Certificate

	// AdditionalSigningCertificates are published next to
	// SigningCertificate (errata E68: any listed key may be used) so a new
	// SP key can be announced before it signs. Never used to sign. At most
	// four RSA certificates; requires SigningKey.
	AdditionalSigningCertificates []*x509.Certificate

	// Connections resolves the trusted connections. Required.
	Connections ConnectionResolver

	// Transactions persists login transactions. Required; shared by every
	// instance of a multi-instance deployment.
	Transactions TransactionStore

	// ReplayCache records consumed assertions (Profiles §4.1.4.5). Required;
	// shared by every instance.
	ReplayCache ReplayCache

	// TransactionKeys are the server-held keys of the transactions'
	// integrity MAC. REQUIRED: 1 to MaxTransactionKeys keys of at least
	// MinTransactionKeySize bytes from a cryptographic source, secret like a
	// session key, the same on every instance, and distinct from the keys of
	// other modules (oidcclient's transaction keys, session keys).
	// TransactionKeys[0] protects the transactions BeginLogin stores;
	// CompleteLogin accepts any of them. The MAC covers the whole stored
	// record — its key, browser binding, payload (request ID, options,
	// AppState) and expiry — and is verified, in constant time, before any
	// stored field is used: whoever can write to the transaction store
	// cannot rebind a transaction to another browser or request, nor relax
	// its ForceAuthn or RequestedAuthnContext (ErrTransactionIntegrity). The
	// keys are the only integrity protection of the records: a leaked key
	// together with write access to the store makes the store trusted again
	// — replace the key at once (the logins in progress then fail once).
	//
	// Rotate without failing a login: add the new key last on every
	// instance, then move it first, then remove the old key once
	// TransactionTTL has elapsed. A key removed earlier fails the logins it
	// protected with ErrTransactionIntegrity.
	TransactionKeys [][]byte

	// TransactionTTL is the lifetime of a login transaction (0 means
	// DefaultTransactionTTL): a whole number of seconds, since the stores
	// keep expiries to the second ([ValidateExpiry]), from one second to
	// MaxTransactionTTL.
	TransactionTTL time.Duration

	// ClockSkew is tolerated on every time check against IdP-issued
	// instants (0 means DefaultClockSkew); at most MaxClockSkew. Zero skew
	// cannot be configured: one nanosecond is the strictest setting.
	ClockSkew time.Duration

	// MaxResponseSize caps the ACS request body in bytes or, when the
	// application parsed the form before CompleteLogin, the SAMLResponse
	// value (0 means DefaultMaxResponseSize); between MinMaxResponseSize
	// and MaxMaxResponseSize.
	MaxResponseSize int64

	// MetadataCacheDuration is the cacheDuration of the published SP
	// metadata (0 means DefaultMetadataCacheDuration); between one minute
	// and 30 days.
	MetadataCacheDuration time.Duration

	// CookieName is the browser-binding cookie name (empty means
	// DefaultCookieName). It MUST start with "__Host-": the prefix forbids a
	// Domain attribute and requires Secure and Path=/, so no sibling
	// subdomain or network attacker can plant the cookie (login CSRF).
	CookieName string

	// Now returns the current time (nil means time.Now). It is read once per
	// operation.
	Now func() time.Time
}

// withDefaults returns a copy of c with the zero fields defaulted.
func (c Config) withDefaults() Config {
	if c.TransactionTTL == 0 {
		c.TransactionTTL = DefaultTransactionTTL
	}

	if c.ClockSkew == 0 {
		c.ClockSkew = DefaultClockSkew
	}

	if c.MaxResponseSize == 0 {
		c.MaxResponseSize = DefaultMaxResponseSize
	}

	if c.MetadataCacheDuration == 0 {
		c.MetadataCacheDuration = DefaultMetadataCacheDuration
	}

	if c.CookieName == "" {
		c.CookieName = DefaultCookieName
	}

	if c.Now == nil {
		c.Now = time.Now
	}

	return c
}

// validate checks a defaulted configuration.
func (c Config) validate() error {
	switch {
	case c.Connections == nil:
		return fmt.Errorf("%w: Connections is required", ErrInvalidConfig)
	case c.Transactions == nil:
		return fmt.Errorf("%w: Transactions is required", ErrInvalidConfig)
	case c.ReplayCache == nil:
		return fmt.Errorf("%w: ReplayCache is required", ErrInvalidConfig)
	case len(c.TransactionKeys) == 0 || len(c.TransactionKeys) > MaxTransactionKeys:
		return fmt.Errorf("%w: TransactionKeys must hold 1 to %d keys", ErrInvalidConfig, MaxTransactionKeys)
	case c.TransactionTTL < time.Second || c.TransactionTTL > MaxTransactionTTL || c.TransactionTTL%time.Second != 0:
		return fmt.Errorf("%w: TransactionTTL must be a whole number of seconds between 1s and %s",
			ErrInvalidConfig, MaxTransactionTTL)
	case c.ClockSkew < 0 || c.ClockSkew > MaxClockSkew:
		return fmt.Errorf("%w: ClockSkew must be between 0 and %s", ErrInvalidConfig, MaxClockSkew)
	case c.MaxResponseSize < MinMaxResponseSize || c.MaxResponseSize > MaxMaxResponseSize:
		return fmt.Errorf("%w: MaxResponseSize must be between %d and %d bytes",
			ErrInvalidConfig, MinMaxResponseSize, MaxMaxResponseSize)
	case c.MetadataCacheDuration < time.Minute || c.MetadataCacheDuration > 30*24*time.Hour:
		return fmt.Errorf("%w: MetadataCacheDuration must be between 1m and 720h", ErrInvalidConfig)
	}

	for _, key := range c.TransactionKeys {
		if len(key) < MinTransactionKeySize {
			// The error never carries key material.
			return fmt.Errorf("%w: every TransactionKeys entry must be at least %d bytes", ErrInvalidConfig, MinTransactionKeySize)
		}
	}

	if err := validateCookieName(c.CookieName); err != nil {
		return err
	}

	return c.validateSigning()
}

// validateCookieName requires the __Host- prefix and RFC 6265 token
// characters.
func validateCookieName(name string) error {
	const prefix = "__Host-"

	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) || len(name) > 64 {
		return fmt.Errorf("%w: CookieName must start with %q", ErrInvalidConfig, prefix)
	}

	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return fmt.Errorf("%w: CookieName must be an RFC 6265 token", ErrInvalidConfig)
		}
	}

	return nil
}

// isTokenChar reports RFC 7230 tchar.
func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	default:
		return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
	}
}

// validateSigning checks the SP signing material.
func (c Config) validateSigning() error {
	if c.SigningKey == nil {
		if c.SigningCertificate != nil || len(c.AdditionalSigningCertificates) > 0 {
			return fmt.Errorf("%w: signing certificates require SigningKey", ErrInvalidConfig)
		}

		return nil
	}

	pub, ok := c.SigningKey.Public().(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: SigningKey must be an RSA key", ErrInvalidConfig)
	}

	if err := checkRSAKey(pub); err != nil {
		return fmt.Errorf("%w: SigningKey: %w", ErrInvalidConfig, err)
	}

	if c.SigningCertificate == nil {
		return fmt.Errorf("%w: SigningCertificate is required with SigningKey", ErrInvalidConfig)
	}

	certPub, ok := c.SigningCertificate.PublicKey.(*rsa.PublicKey)
	if !ok || !certPub.Equal(pub) {
		return fmt.Errorf("%w: SigningCertificate does not match SigningKey", ErrInvalidConfig)
	}

	if len(c.AdditionalSigningCertificates) > maxAdditionalSPCerts {
		return fmt.Errorf("%w: at most %d additional signing certificates", ErrInvalidConfig, maxAdditionalSPCerts)
	}

	for _, extra := range c.AdditionalSigningCertificates {
		if extra == nil {
			return fmt.Errorf("%w: nil additional signing certificate", ErrInvalidConfig)
		}

		k, ok := extra.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: additional signing certificates must be RSA", ErrInvalidConfig)
		}

		if err := checkRSAKey(k); err != nil {
			return fmt.Errorf("%w: additional signing certificate: %w", ErrInvalidConfig, err)
		}
	}

	return nil
}
