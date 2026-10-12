// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// LoginOptions tunes one SP-initiated login.
type LoginOptions struct {
	// AppState is opaque application state (at most 2 KiB of UTF-8 without
	// NUL), kept server-side in the transaction and returned by
	// [ServiceProvider.CompleteLogin]: typically where to send the user
	// afterwards. The library never follows it; an application redirecting
	// to it MUST only accept local paths (no open redirect, errata E90),
	// with an allowlist: one leading slash and no "//", RFC 3986 path and
	// query characters only (no control, white space, backslash or
	// non-ASCII byte: browsers drop TAB, CR and LF inside URLs), still a
	// local path once percent-decoded. See safeReturn in examples/saml-sp.
	AppState string

	// ForceAuthn asks the IdP to authenticate the user afresh (Core §3.4.1);
	// a response whose AuthnInstant predates the request is then refused.
	ForceAuthn bool

	// IsPassive forbids the IdP to interact with the user (Core §3.4.1); it
	// answers NoPassive when it cannot authenticate silently.
	IsPassive bool

	// RequestedAuthnContext lists acceptable authentication context classes
	// (at most 8 absolute URIs), requested with Comparison="exact" (Core
	// §3.3.2.2.1). The response's AuthnContextClassRef MUST be one of them.
	RequestedAuthnContext []string
}

// validate checks the options.
func (o LoginOptions) validate() error {
	if len(o.AppState) > maxAppStateLen || !utf8.ValidString(o.AppState) || strings.IndexByte(o.AppState, 0) >= 0 {
		return fmt.Errorf("%w: AppState must be at most %d bytes of UTF-8 without NUL",
			ErrInvalidLoginOptions, maxAppStateLen)
	}

	if len(o.RequestedAuthnContext) > maxRequestedContexts {
		return fmt.Errorf("%w: at most %d requested authentication contexts", ErrInvalidLoginOptions, maxRequestedContexts)
	}

	for _, c := range o.RequestedAuthnContext {
		if len(c) > maxRequestedContextLn || validateEntityID(c) != nil {
			return fmt.Errorf("%w: requested authentication contexts must be absolute URIs", ErrInvalidLoginOptions)
		}
	}

	return nil
}

// BeginLogin starts an SP-initiated Web Browser SSO login (Profiles §4.1)
// with the IdP of the connection. It
//
//  1. builds an AuthnRequest (Core §3.4.1, Profiles §4.1.4.1): a 256-bit
//     random ID (Core §1.3.4), IssueInstant, Destination = the IdP SSO URL,
//     AssertionConsumerServiceURL = the connection's ACS URL with the
//     HTTP-POST ProtocolBinding, Issuer = the connection's SP entity ID,
//     NameIDPolicy AllowCreate="true" with the connection's format, and the
//     ForceAuthn/IsPassive/RequestedAuthnContext options;
//  2. encodes it for the HTTP-Redirect binding (Bindings §3.4.4.1: DEFLATE,
//     base64, SAMLRequest) with a RelayState that is a random 43-character
//     handle — never application data — and, when the SP has a signing key,
//     the SigAlg and Signature parameters (rsa-sha256);
//  3. stores the transaction (insert-if-absent, keyed by the connection and
//     the handle, bound to the browser, expiring after the TTL);
//  4. sets the browser-binding cookie on w: __Host- prefixed, Secure,
//     HttpOnly, SameSite=None (the IdP's response is a cross-site POST that
//     a Lax or Strict cookie would not reach), Path=/, Max-Age = TTL; an
//     existing well-formed binding cookie is reused, so concurrent logins of
//     one browser keep working.
//
// It returns the IdP URL; the caller MUST redirect the browser to it with a
// 302 or 303 response. On error nothing is stored and no cookie is set.
// BeginLogin needs no authentication and writes to the transaction store:
// applications SHOULD rate-limit it. They MUST also gate login initiation:
// a page of another site can otherwise start a login in the user's browser
// (forced login initiation, a form of login CSRF); accept same-origin
// navigations only (Fetch Metadata: Sec-Fetch-Site same-origin or none) or
// start logins from a CSRF-protected POST — see "Browser binding, CSRF and
// replay" in docs/security-considerations.md, and examples/saml-sp.
func (sp *ServiceProvider) BeginLogin(ctx context.Context, w http.ResponseWriter, r *http.Request,
	connectionID string, opts LoginOptions,
) (_ string, err error) {
	ctx, span := startSpan(ctx, "samlsp.ServiceProvider.BeginLogin")
	defer func() { endSpan(span, err) }()

	if w == nil || r == nil {
		return "", fmt.Errorf("%w: BeginLogin needs a ResponseWriter and a Request", ErrInvalidConfig)
	}

	if err := opts.validate(); err != nil {
		return "", err
	}

	conn, err := sp.resolve(ctx, connectionID)
	if err != nil {
		return "", err
	}

	annotateConnection(span, conn)

	now := sp.cfg.Now().UTC().Truncate(time.Second)

	if conn.IdentityProvider.expired(now) {
		return "", ErrMetadataExpired
	}

	if conn.IdentityProvider.WantAuthnRequestsSigned && sp.cfg.SigningKey == nil {
		return "", fmt.Errorf("%w: the identity provider wants signed AuthnRequests but the SP has no signing key",
			ErrInvalidConfig)
	}

	tx := &transaction{
		Version:      payloadVersion,
		RequestID:    newRequestID(),
		ConnectionID: conn.ID,
		IdP:          conn.IdentityProvider.EntityID,
		SP:           conn.SPEntityID,
		ACS:          conn.ACSURL,
		IssuedAt:     now.Unix(),
		NameIDFormat: conn.NameIDFormat,
		ForceAuthn:   opts.ForceAuthn,
		IsPassive:    opts.IsPassive,
		AuthnContext: opts.RequestedAuthnContext,
		AppState:     opts.AppState,
	}

	payload := tx.encode()
	if len(payload) > MaxTransactionPayloadSize {
		return "", fmt.Errorf("%w: the options exceed the transaction payload limit of %d bytes once encoded",
			ErrInvalidLoginOptions, MaxTransactionPayloadSize)
	}

	handle := newHandle()

	redirect, err := sp.authnRequestURL(conn, tx, handle, now)
	if err != nil {
		return "", err
	}

	binding := sp.bindingValue(r)

	rec := &TransactionRecord{
		ID:          transactionID(conn.ID, handle),
		BindingHash: bindingHash(binding),
		Payload:     payload,
		ExpiresAt:   now.Add(sp.cfg.TransactionTTL),
	}

	if err := sp.cfg.Transactions.SaveTransaction(ctx, rec); err != nil {
		return "", fmt.Errorf("samlsp: save transaction: %w", err)
	}

	http.SetCookie(w, sp.bindingCookie(binding))

	return redirect, nil
}

// authnRequestURL builds the AuthnRequest of tx with gosaml2 and returns the
// HTTP-Redirect URL.
func (sp *ServiceProvider) authnRequestURL(conn *Connection, tx *transaction, handle string, now time.Time) (string, error) {
	gsp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      conn.IdentityProvider.SSOURL,
		IdentityProviderSSOBinding:  saml2.BindingHttpRedirect,
		IdentityProviderIssuer:      conn.IdentityProvider.EntityID,
		AssertionConsumerServiceURL: conn.ACSURL,
		ServiceProviderIssuer:       conn.SPEntityID,
		NameIdFormat:                conn.NameIDFormat,
		ForceAuthn:                  tx.ForceAuthn,
		IsPassive:                   tx.IsPassive,
		Clock:                       dsig.NewFakeClockAt(now),
		SignAuthnRequests:           sp.cfg.SigningKey != nil,
		SignAuthnRequestsAlgorithm:  dsig.RSASHA256SignatureMethod,
	}

	if len(tx.AuthnContext) > 0 {
		gsp.RequestedAuthnContext = &saml2.RequestedAuthnContext{Comparison: comparisonExact, Contexts: tx.AuthnContext}
	}

	if sp.cfg.SigningKey != nil {
		err := gsp.SetSPSigningKeyStore(&saml2.KeyStore{Signer: sp.cfg.SigningKey, Cert: sp.cfg.SigningCertificate.Raw})
		if err != nil {
			return "", fmt.Errorf("samlsp: signing key: %w", err)
		}
	}

	doc, err := gsp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		return "", fmt.Errorf("samlsp: build AuthnRequest: %w", err)
	}

	// gosaml2 uses a UUIDv4 (122 random bits), below the 128 bits Core
	// §1.3.4 requires: use our 256-bit identifier instead.
	doc.Root().CreateAttr("ID", tx.RequestID)

	redirect, err := gsp.BuildAuthURLRedirect(handle, doc)
	if err != nil {
		return "", fmt.Errorf("samlsp: encode AuthnRequest: %w", err)
	}

	return redirect, nil
}

// bindingValue returns the browser's existing binding value when it is
// well-formed, a new random one otherwise. Reusing it is safe because the
// __Host- prefix keeps other origins from planting it.
func (sp *ServiceProvider) bindingValue(r *http.Request) string {
	if c, err := r.Cookie(sp.cfg.CookieName); err == nil && isHandle(c.Value) {
		return c.Value
	}

	return newHandle()
}

// bindingCookie renders the browser-binding cookie.
func (sp *ServiceProvider) bindingCookie(value string) *http.Cookie {
	// SameSite=None is deliberate: the ACS request is a cross-site POST
	// initiated by the IdP's page; Lax or Strict cookies are not sent with
	// it. Secure, HttpOnly and the __Host- prefix still apply.
	return &http.Cookie{ //nolint:gosec // G124: SameSite=None is required by the cross-site HTTP-POST binding; Secure and HttpOnly are set
		Name:     sp.cfg.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sp.cfg.TransactionTTL / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	}
}
