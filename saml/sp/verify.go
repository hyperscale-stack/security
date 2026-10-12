// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"slices"
	"time"

	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// gosamlMaxTokens is the token bound handed to gosaml2 (it estimates
// 3·count('<')+1). The lexical gate already admits far less, so only
// '<' characters inside CDATA sections can reach it.
const gosamlMaxTokens = 3*(2*MaxResponseElements+4096) + 1

// verifyResponse runs gosaml2 (and goxmldsig) over the pre-checked bytes
// with the connection's trusted certificates and returns the decoded,
// verified response: every value comes from the digested canonical bytes.
//
// When a signature has no KeyInfo and the connection trusts several
// certificates, goxmldsig cannot select one ("Missing x509 Element"), so
// the certificates are tried alone (Core §5.4.5 lets KeyInfo be absent;
// plan review F7): the three most recent valid at now−skew, since each
// attempt re-runs the whole verification (code review F4). A KeyInfo
// certificate, when present, only selects among the trusted ones by exact
// equality.
func (sp *ServiceProvider) verifyResponse(raw *rawResponse, conn *Connection, now time.Time) (*types.Response, error) {
	certs := conn.IdentityProvider.SigningCertificates
	at := now.Add(-sp.cfg.ClockSkew)

	if !raw.keyInfoMissing || len(certs) == 1 {
		return sp.validateWith(raw, conn, at, certs)
	}

	var lastErr error

	for _, c := range rolloverCandidates(certs, at) {
		resp, err := sp.validateWith(raw, conn, at, []*x509.Certificate{c})
		if err == nil {
			return resp, nil
		}

		lastErr = err
	}

	if lastErr == nil {
		return nil, reject(ErrInvalidSignature, "no trusted certificate is currently valid", nil)
	}

	return nil, lastErr
}

// maxRolloverAttempts bounds the certificates tried when a signature has
// no KeyInfo: an IdP rolling its key announces the current and the next
// one, sometimes the previous one too.
const maxRolloverAttempts = 3

// rolloverCandidates returns the certificates tried one by one when a
// signature has no KeyInfo: the maxRolloverAttempts most recent (by
// NotBefore) of those valid at at, newest first.
func rolloverCandidates(certs []*x509.Certificate, at time.Time) []*x509.Certificate {
	var out []*x509.Certificate

	for _, c := range certs {
		if at.Before(c.NotBefore) || at.After(c.NotAfter) {
			continue
		}

		out = append(out, c)
	}

	slices.SortStableFunc(out, func(a, b *x509.Certificate) int { return b.NotBefore.Compare(a.NotBefore) })

	return out[:min(len(out), maxRolloverAttempts)]
}

// validateWith runs gosaml2 with the given trusted certificates. gosaml2's
// clock is now−skew: its inclusive SubjectConfirmationData expiry check is
// then never stricter than ours, and the certificate validity window is
// evaluated at that instant.
func (sp *ServiceProvider) validateWith(raw *rawResponse, conn *Connection, at time.Time, certs []*x509.Certificate) (*types.Response, error) {
	gsp := &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      conn.IdentityProvider.EntityID,
		AssertionConsumerServiceURL: conn.ACSURL,
		ServiceProviderIssuer:       conn.SPEntityID,
		AudienceURI:                 conn.SPEntityID,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: certs},
		Clock:                       dsig.NewFakeClockAt(at),
		// POST messages are never DEFLATE-encoded (Bindings §3.5.4): a
		// one-byte limit makes gosaml2's inflate fallback fail at once.
		MaximumDecompressedBodySize: 1,
		MaximumXMLTokens:            gosamlMaxTokens,
		SkipSignatureValidation:     false,
	}

	resp, err := gsp.ValidateEncodedResponse(base64.StdEncoding.EncodeToString(raw.data))
	if err != nil {
		return nil, mapVerifyError(err)
	}

	return resp, nil
}

// mapVerifyError maps a gosaml2/goxmldsig error to a rejection. The cause
// stays reachable through errors.As but its text, which may echo message
// content, is never part of the returned error's message. gosaml2 wraps
// some causes with %v, so only top-level types can be matched; anything
// unrecognized is a signature failure (fail closed).
func mapVerifyError(err error) error {
	var (
		invalid saml2.ErrInvalidValue
		missing saml2.ErrMissingElement
		parsing saml2.ErrParsing
		trip    rtvalidator.XMLRoundtripError
		valid   rtvalidator.XMLValidationError
		syntax  *xml.SyntaxError
	)

	switch {
	case errors.Is(err, etreeutils.ErrTraversalLimit):
		return reject(ErrResponseTooLarge, "verifier traversal budget exceeded", err)
	case errors.Is(err, dsig.ErrMissingSignature):
		return reject(ErrInvalidSignature, "not signed", err)
	case errors.As(err, &invalid):
		return reject(invalidValueReason(invalid), "", err)
	case errors.As(err, &missing):
		if missing.Tag == saml2.IssuerTag {
			return reject(ErrIssuerMismatch, "missing Issuer", err)
		}

		return reject(ErrInvalidAssertion, "missing element", err)
	case errors.As(err, &parsing), errors.As(err, &trip), errors.As(err, &valid), errors.As(err, &syntax):
		return reject(ErrMalformedResponse, "", err)
	default:
		return reject(ErrInvalidSignature, "signature verification failed", err)
	}
}

// invalidValueReason maps the key of a gosaml2 ErrInvalidValue.
func invalidValueReason(e saml2.ErrInvalidValue) error {
	switch e.Key {
	case saml2.DestinationAttr:
		return ErrDestinationMismatch
	case saml2.RecipientAttr:
		return ErrRecipientMismatch
	case saml2.IssuerTag:
		return ErrIssuerMismatch
	case saml2.StatusCodeTag:
		return ErrResponseStatus
	case saml2.NotOnOrAfterAttr:
		return ErrAssertionExpired
	case "SAML version":
		return ErrMalformedResponse
	default:
		return ErrInvalidAssertion
	}
}
