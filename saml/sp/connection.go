// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Key size policy (OWASP SAML cheat sheet: RSA ≥ 2048 bits).
const (
	minRSABits = 2048
	maxRSABits = 8192
)

// IdentityProvider is the explicitly trusted configuration of one SAML
// identity provider: where AuthnRequests go and which keys may sign the
// responses. It is usually produced by [ParseIdentityProviderMetadata].
// Trust comes only from this configuration: nothing in a response (Issuer,
// KeyInfo) can extend it.
type IdentityProvider struct {
	// EntityID is the IdP entity ID: the exact Issuer of the Response and
	// of the Assertion. Required; an absolute URI of at most 1024 bytes.
	EntityID string

	// SSOURL is the SingleSignOnService location for the HTTP-Redirect
	// binding. Required; https, or http on a loopback host for development.
	// It MUST NOT already carry SAMLRequest, RelayState, SigAlg, Signature
	// or SAMLEncoding parameters.
	SSOURL string

	// SigningCertificates are the trusted signing keys (1 to 8). Several
	// keys support rollover (errata E68): any of them may sign. A signature
	// whose KeyInfo carries a certificate selects it among these by exact
	// equality; without KeyInfo, the three most recent (by NotBefore) valid
	// certificates are tried, since each attempt costs a full verification.
	// Keys must be
	// RSA of at least 2048 bits, or ECDSA P-256, P-384 or P-521. ECDSA is
	// verified as goxmldsig implements it (ASN.1 DER signature values): IdPs
	// that follow XML Signature 1.1 (raw r‖s values) fail closed. The
	// certificate validity window is enforced at verification time.
	SigningCertificates []*x509.Certificate

	// WantAuthnRequestsSigned mirrors the IdP metadata attribute (Metadata
	// §2.4.3): when true, [ServiceProvider.BeginLogin] fails closed unless
	// the SP has a signing key.
	WantAuthnRequestsSigned bool

	// ValidUntil, when set, is the metadata expiry: at or after it the IdP is
	// refused with ErrMetadataExpired (Metadata §4.3.2, errata E94).
	ValidUntil time.Time

	// CacheDuration is the metadata refresh hint (errata E94); informational.
	CacheDuration time.Duration
}

// Validate checks the configuration; it returns an error matching
// [ErrInvalidConnection].
func (p *IdentityProvider) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil identity provider", ErrInvalidConnection)
	}

	if err := validateEntityID(p.EntityID); err != nil {
		return fmt.Errorf("%w: identity provider entity ID: %w", ErrInvalidConnection, err)
	}

	if err := validateSSOURL(p.SSOURL); err != nil {
		return fmt.Errorf("%w: identity provider SSO URL: %w", ErrInvalidConnection, err)
	}

	if p.CacheDuration < 0 {
		return fmt.Errorf("%w: negative cache duration", ErrInvalidConnection)
	}

	return validateSigningCertificates(p.SigningCertificates)
}

// expired reports whether the IdP metadata is past its ValidUntil.
func (p *IdentityProvider) expired(now time.Time) bool {
	return !p.ValidUntil.IsZero() && !now.Before(p.ValidUntil)
}

// validateSigningCertificates enforces the count, the key policy and the
// absence of duplicates.
func validateSigningCertificates(certs []*x509.Certificate) error {
	if len(certs) == 0 || len(certs) > maxSigningCerts {
		return fmt.Errorf("%w: need 1 to %d signing certificates", ErrInvalidConnection, maxSigningCerts)
	}

	for i, c := range certs {
		if c == nil {
			return fmt.Errorf("%w: nil signing certificate", ErrInvalidConnection)
		}

		if err := checkIdPKey(c.PublicKey); err != nil {
			return fmt.Errorf("%w: signing certificate %d: %w", ErrInvalidConnection, i, err)
		}

		for _, prev := range certs[:i] {
			if prev.Equal(c) {
				return fmt.Errorf("%w: duplicate signing certificate", ErrInvalidConnection)
			}
		}
	}

	return nil
}

// checkIdPKey enforces the IdP key policy: RSA 2048–8192 bits or ECDSA on
// P-256/P-384/P-521.
func checkIdPKey(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return checkRSAKey(k)
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		default:
			return errUnsupportedKey
		}
	default:
		return errUnsupportedKey
	}
}

// checkRSAKey enforces the RSA modulus size policy.
func checkRSAKey(k *rsa.PublicKey) error {
	if bits := k.N.BitLen(); bits < minRSABits || bits > maxRSABits {
		return errWeakKey
	}

	return nil
}

var (
	errUnsupportedKey = errors.New("unsupported key type (want RSA or ECDSA P-256/P-384/P-521)")
	errWeakKey        = fmt.Errorf("RSA key size outside %d–%d bits", minRSABits, maxRSABits)
	errNotAbsoluteURI = errors.New("not an absolute URI")
	errBadURL         = errors.New("not an absolute https URL (http only on a loopback host)")
	errACSQuery       = errors.New("ACS URL must not carry a query string")
	errACSPath        = errors.New("ACS URL must have a path")
	errACSHost        = errors.New("ACS URL host must be ASCII (the IDNA A-label browsers send in Host)")
)

// validateEntityID checks an entity ID: an absolute URI of at most 1024
// bytes without white space or control characters (Metadata §2.3.2).
func validateEntityID(id string) error {
	if id == "" || len(id) > maxEntityIDLen || strings.IndexFunc(id, isSpaceOrControl) >= 0 {
		return errNotAbsoluteURI
	}

	u, err := url.Parse(id)
	if err != nil || u.Scheme == "" {
		return errNotAbsoluteURI
	}

	return nil
}

// isSpaceOrControl reports white space and control characters.
func isSpaceOrControl(r rune) bool {
	return r <= ' ' || r == 0x7f
}

// validateEndpointURL checks a browser-facing endpoint: absolute https URL,
// or http on a loopback host; no user info, no fragment.
func validateEndpointURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 2048 || strings.IndexFunc(raw, isSpaceOrControl) >= 0 {
		return nil, errBadURL
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" ||
		strings.HasSuffix(raw, "#") {
		return nil, errBadURL
	}

	switch u.Scheme {
	case schemeHTTPS:
		return u, nil
	case schemeHTTP:
		if isLoopbackHost(u.Hostname()) {
			return u, nil
		}
	}

	return nil, errBadURL
}

// isLoopbackHost reports localhost and loopback IP literals.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// reservedQueryParams are the HTTP-Redirect binding parameters an SSO URL
// must not already carry (Bindings §3.4.4).
var reservedQueryParams = []string{"SAMLRequest", formFieldResponse, formFieldRelayState, "SigAlg", tagSignature, "SAMLEncoding"}

// validateSSOURL checks an IdP SSO endpoint.
func validateSSOURL(raw string) error {
	u, err := validateEndpointURL(raw)
	if err != nil {
		return err
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errBadURL
	}

	for _, p := range reservedQueryParams {
		if _, ok := q[p]; ok {
			return fmt.Errorf("SSO URL already carries %s", p)
		}
	}

	return nil
}

// validateACSURL checks an assertion consumer service URL: an endpoint URL
// without query string, compared verbatim with Destination and Recipient.
func validateACSURL(raw string) error {
	u, err := validateEndpointURL(raw)
	if err != nil {
		return err
	}

	if u.RawQuery != "" || strings.Contains(raw, "?") {
		return errACSQuery
	}

	if u.EscapedPath() == "" {
		return errACSPath
	}

	// CompleteLogin compares the request's Host with this host: browsers
	// send an internationalized host name in its ASCII (punycode) form.
	if !isASCII(u.Host) {
		return errACSHost
	}

	return nil
}

// isASCII reports whether s holds ASCII characters only.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}

	return true
}

// Connection is one application-defined trust relationship between the SP
// and an IdP, for example one tenant's enterprise IdP. Each connection has
// its own SP entity ID and ACS URL (e.g. https://sp.example/saml/{id} and
// https://sp.example/saml/{id}/acs): an IdP that registered one connection's
// SP refuses requests from another, and a response for one connection
// cannot be delivered to another's ACS. SP entity IDs and ACS URLs MUST be
// distinct across connections; the library cannot check it across a
// [ConnectionResolver].
type Connection struct {
	// ID identifies the connection in the application: 1 to 256 visible
	// ASCII characters. It scopes transactions and MUST be part of the keys
	// the application derives from an [Identity].
	ID string

	// SPEntityID is the SP entity ID of this connection: the AuthnRequest
	// Issuer and the Audience the assertions must name. Required; an
	// absolute URI of at most 1024 bytes.
	SPEntityID string

	// ACSURL is the AssertionConsumerService URL (HTTP-POST binding) of this
	// connection: the exact Destination and Recipient the responses must
	// carry. Required; https (http on loopback for development), a path, no
	// query string, an ASCII host (the punycode form of an
	// internationalized name). The application MUST mount
	// [ServiceProvider.CompleteLogin] at exactly this URL: CompleteLogin
	// refuses a request received at another path or host (r.Host), or with
	// a query string. Behind a reverse proxy that rewrites Host, restore
	// r.Host from the trusted proxy's forwarding header first.
	ACSURL string

	// IdentityProvider is the trusted IdP configuration.
	IdentityProvider IdentityProvider

	// NameIDFormat, when set, is requested in the AuthnRequest NameIDPolicy
	// (Core §3.4.1.1) and published in the SP metadata; unless it is
	// NameIDFormatUnspecified, the asserted NameID MUST carry it.
	NameIDFormat string

	// InsecureAllowSHA1 accepts rsa-sha1 and ecdsa-sha1 signatures and SHA-1
	// digests from this IdP. SHA-1 is broken for collision resistance: use
	// it only for a legacy IdP that cannot be moved to SHA-256. It does not
	// relax anything else (inclusive canonicalization and RSA keys under
	// 2048 bits stay refused).
	InsecureAllowSHA1 bool
}

// Validate checks the connection; it returns an error matching
// [ErrInvalidConnection].
func (c *Connection) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil connection", ErrInvalidConnection)
	}

	if err := validateConnectionID(c.ID); err != nil {
		return err
	}

	if err := validateEntityID(c.SPEntityID); err != nil {
		return fmt.Errorf("%w: SP entity ID: %w", ErrInvalidConnection, err)
	}

	if err := validateACSURL(c.ACSURL); err != nil {
		return fmt.Errorf("%w: ACS URL: %w", ErrInvalidConnection, err)
	}

	if c.NameIDFormat != "" {
		if err := validateEntityID(c.NameIDFormat); err != nil {
			return fmt.Errorf("%w: NameID format: %w", ErrInvalidConnection, err)
		}
	}

	return c.IdentityProvider.Validate()
}

// validateConnectionID checks a connection ID: 1 to 256 visible ASCII
// characters.
func validateConnectionID(id string) error {
	if id == "" || len(id) > maxConnectionIDLen {
		return fmt.Errorf("%w: connection ID must be 1 to %d characters", ErrInvalidConnection, maxConnectionIDLen)
	}

	for i := 0; i < len(id); i++ {
		if c := id[i]; c <= ' ' || c >= 0x7f {
			return fmt.Errorf("%w: connection ID must be visible ASCII", ErrInvalidConnection)
		}
	}

	return nil
}

// ConnectionResolver returns the current trusted configuration of a
// connection. Implementations return an error matching
// [ErrUnknownConnection] for an unknown ID; any other error is treated as an
// infrastructure failure. The returned value is not modified.
type ConnectionResolver interface {
	ResolveConnection(ctx context.Context, id string) (*Connection, error)
}

// ConnectionResolverFunc adapts a function to [ConnectionResolver].
type ConnectionResolverFunc func(ctx context.Context, id string) (*Connection, error)

// ResolveConnection calls f.
func (f ConnectionResolverFunc) ResolveConnection(ctx context.Context, id string) (*Connection, error) {
	return f(ctx, id)
}
