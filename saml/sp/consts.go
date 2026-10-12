// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

// Name identifier formats (Core §8.3). Only persistent identifiers are
// stable keys — and only together with the connection and the qualifiers;
// see [NameID].
const (
	// NameIDFormatUnspecified lets the IdP choose (Core §8.3.1, errata E84).
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	// NameIDFormatEmailAddress is an email address (Core §8.3.2); not a
	// stable key.
	NameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	// NameIDFormatPersistent is a pairwise, never reassigned identifier
	// (Core §8.3.7, errata E78).
	NameIDFormatPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	// NameIDFormatTransient is a one-time identifier (Core §8.3.8); never a
	// key.
	NameIDFormatTransient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// XML namespaces.
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	nsXMLEnc    = "http://www.w3.org/2001/04/xmlenc#"
	nsExcC14N   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	nsXML       = "http://www.w3.org/XML/1998/namespace"
	nsXMLNS     = "http://www.w3.org/2000/xmlns/"
)

// tagSignature is the local name of the XML-DSig Signature element.
const tagSignature = "Signature"

// tagX509Certificate is the local name of the XML-DSig X509Certificate
// element.
const tagX509Certificate = "X509Certificate"

// Protocol constants.
const (
	samlVersion           = "2.0"
	bindingHTTPPost       = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindingHTTPRedirect   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	statusSuccess         = "urn:oasis:names:tc:SAML:2.0:status:Success"
	confirmationBearer    = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // G101: a SAML confirmation-method URI, not a credential
	nameIDFormatEntity    = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	comparisonExact       = "exact"
	metadataMediaType     = "application/samlmetadata+xml"
	formMediaType         = "application/x-www-form-urlencoded"
	formFieldResponse     = "SAMLResponse"
	formFieldRelayState   = "RelayState"
	maxRelayStateLen      = 80 // Bindings §3.4.3, §3.5.3
	maxEntityIDLen        = 1024
	maxConnectionIDLen    = 256
	maxSigningCerts       = 8
	maxAdditionalSPCerts  = 4
	maxAppStateLen        = 2 << 10
	maxRequestedContexts  = 8
	maxRequestedContextLn = 1024
)

// XML-DSig algorithm identifiers (RFC 6931, XML-DSig 1.0/1.1).
const (
	algRSASHA1          = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	algRSASHA256        = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algRSASHA384        = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	algRSASHA512        = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	algECDSASHA1        = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	algECDSASHA256      = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	algECDSASHA384      = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	algECDSASHA512      = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	algDigestSHA1       = "http://www.w3.org/2000/09/xmldsig#sha1"
	algDigestSHA256     = "http://www.w3.org/2001/04/xmlenc#sha256"
	algDigestSHA384     = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	algDigestSHA512     = "http://www.w3.org/2001/04/xmlenc#sha512"
	algExcC14N          = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algExcC14NComments  = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	algEnvelopedSigning = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)
