// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// DefaultMetadataMaxSize is the default cap on an IdP metadata document.
const DefaultMetadataMaxSize = 1 << 20

// MetadataOptions tunes [ParseIdentityProviderMetadata].
type MetadataOptions struct {
	// EntityID, when set, pins the expected IdP entity ID: the document
	// must describe exactly this entity. It is required to select one entity
	// out of an EntitiesDescriptor that lists several.
	EntityID string

	// Now returns the current time used to evaluate validUntil (nil means
	// time.Now).
	Now func() time.Time

	// MaxSize caps the document size in bytes (0 means
	// DefaultMetadataMaxSize).
	MaxSize int64
}

// ParseIdentityProviderMetadata imports explicitly trusted IdP metadata
// (SAML 2.0 Metadata): bytes from an administrator upload or a file; see
// [FetchIdentityProviderMetadata] and [MetadataSource] for a metadata URL.
// Importing is the act of trust: an embedded
// ds:Signature is not verified, and aggregates (EntitiesDescriptor of many
// entities) are only accepted with a pinned EntityID.
//
// The document must have an EntityDescriptor root, or an
// EntitiesDescriptor whose single (or pinned) EntityDescriptor is used;
// nested EntitiesDescriptors are refused. The entity must have exactly one
// IDPSSODescriptor supporting the SAML 2.0 protocol (several are ambiguous,
// Metadata §2.3.2). The result carries:
//
//   - the entity ID;
//   - the first SingleSignOnService of the HTTP-Redirect binding (none is an
//     error), validated like [IdentityProvider.SSOURL];
//   - every X509Certificate of the KeyDescriptors whose use is "signing" or
//     absent (encryption-only keys are ignored), deduplicated, subject to
//     the key policy (RSA ≥ 2048 bits, ECDSA P-256/384/521), 1 to 8 of them;
//   - WantAuthnRequestsSigned;
//   - validUntil and cacheDuration: the smallest of the root, entity and
//     role values (errata E76). Expired metadata yields ErrMetadataExpired
//     (Metadata §4.3.2, errata E94).
//
// Other failures match [ErrInvalidMetadata].
func ParseIdentityProviderMetadata(data []byte, opts MetadataOptions) (*IdentityProvider, error) {
	idp, _, err := parseIdentityProviderMetadata(data, opts)

	return idp, err
}

// parseIdentityProviderMetadata is ParseIdentityProviderMetadata, also
// reporting whether the document set a cacheDuration: an explicit PT0S
// differs from an absent one for a MetadataSource.
func parseIdentityProviderMetadata(data []byte, opts MetadataOptions) (*IdentityProvider, bool, error) {
	if opts.MaxSize == 0 {
		opts.MaxSize = DefaultMetadataMaxSize
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}

	if opts.MaxSize < 0 || int64(len(data)) > opts.MaxSize {
		return nil, false, fmt.Errorf("%w: document larger than %d bytes", ErrInvalidMetadata, opts.MaxSize)
	}

	data = stripBOM(data)

	lim := metadataLimits
	lim.maxBytes = opts.MaxSize

	if err := checkXML(data, lim); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrInvalidMetadata, err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, false, fmt.Errorf("%w: not well-formed XML", ErrInvalidMetadata)
	}

	m := &metadataReader{}

	entity, err := m.selectEntity(doc.Root(), opts.EntityID)
	if err != nil {
		return nil, false, err
	}

	idp, err := m.readEntity(entity)
	if err != nil {
		return nil, false, err
	}

	if err := idp.Validate(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrInvalidMetadata, err)
	}

	if idp.expired(opts.Now()) {
		return nil, false, ErrMetadataExpired
	}

	return idp, m.cacheSet, nil
}

// metadataReader accumulates the effective validUntil/cacheDuration while
// walking from the root to the role descriptor.
type metadataReader struct {
	validUntil    time.Time
	cacheDuration time.Duration
	cacheSet      bool // a cacheDuration was found (PT0S included)
}

// inNS reports whether el is the element {ns}local.
func inNS(el *etree.Element, ns, local string) bool {
	return el != nil && el.Tag == local && el.NamespaceURI() == ns
}

// selectEntity returns the EntityDescriptor to import.
func (m *metadataReader) selectEntity(root *etree.Element, pin string) (*etree.Element, error) {
	if err := m.applyValidity(root); err != nil {
		return nil, err
	}

	if inNS(root, nsMetadata, "EntityDescriptor") {
		return root, checkPin(root, pin)
	}

	if !inNS(root, nsMetadata, "EntitiesDescriptor") {
		return nil, fmt.Errorf("%w: root is not an EntityDescriptor or EntitiesDescriptor", ErrInvalidMetadata)
	}

	var candidates []*etree.Element

	for _, child := range root.ChildElements() {
		switch {
		case inNS(child, nsMetadata, "EntitiesDescriptor"):
			return nil, fmt.Errorf("%w: nested EntitiesDescriptor (aggregates are not supported)", ErrInvalidMetadata)
		case inNS(child, nsMetadata, "EntityDescriptor"):
			if pin == "" || attrValue(child, "entityID") == pin {
				candidates = append(candidates, child)
			}
		}
	}

	if len(candidates) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one matching EntityDescriptor, found %d",
			ErrInvalidMetadata, len(candidates))
	}

	if err := m.applyValidity(candidates[0]); err != nil {
		return nil, err
	}

	return candidates[0], nil
}

// checkPin compares the entity ID with the pinned one.
func checkPin(entity *etree.Element, pin string) error {
	if pin != "" && attrValue(entity, "entityID") != pin {
		return fmt.Errorf("%w: entity ID does not match the pinned one", ErrInvalidMetadata)
	}

	return nil
}

// applyValidity folds the validUntil and cacheDuration of el into m (the
// smallest value wins, errata E76).
func (m *metadataReader) applyValidity(el *etree.Element) error {
	if v, ok := attr(el, "validUntil"); ok {
		t, err := parseMetadataTime(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("%w: validUntil: %w", ErrInvalidMetadata, err)
		}

		if m.validUntil.IsZero() || t.Before(m.validUntil) {
			m.validUntil = t
		}
	}

	if v, ok := attr(el, "cacheDuration"); ok {
		d, err := parseXSDuration(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("%w: cacheDuration: %w", ErrInvalidMetadata, err)
		}

		if !m.cacheSet || d < m.cacheDuration {
			m.cacheDuration, m.cacheSet = d, true
		}
	}

	return nil
}

// readEntity extracts the IdP configuration of an EntityDescriptor.
func (m *metadataReader) readEntity(entity *etree.Element) (*IdentityProvider, error) {
	role, err := idpDescriptor(entity)
	if err != nil {
		return nil, err
	}

	if err := m.applyValidity(role); err != nil {
		return nil, err
	}

	ssoURL := ""

	for _, el := range role.ChildElements() {
		if inNS(el, nsMetadata, "SingleSignOnService") && attrValue(el, "Binding") == bindingHTTPRedirect {
			ssoURL = strings.TrimSpace(attrValue(el, "Location"))

			break
		}
	}

	if ssoURL == "" {
		return nil, fmt.Errorf("%w: no SingleSignOnService for the HTTP-Redirect binding", ErrInvalidMetadata)
	}

	certs, err := signingCertificates(role)
	if err != nil {
		return nil, err
	}

	want := false

	if v, ok := attr(role, "WantAuthnRequestsSigned"); ok {
		if want, err = parseXSBoolean(v); err != nil {
			return nil, fmt.Errorf("%w: WantAuthnRequestsSigned: %w", ErrInvalidMetadata, err)
		}
	}

	return &IdentityProvider{
		EntityID:                attrValue(entity, "entityID"),
		SSOURL:                  ssoURL,
		SigningCertificates:     certs,
		WantAuthnRequestsSigned: want,
		ValidUntil:              m.validUntil,
		CacheDuration:           m.cacheDuration,
	}, nil
}

// idpDescriptor returns the single IDPSSODescriptor supporting SAML 2.0.
func idpDescriptor(entity *etree.Element) (*etree.Element, error) {
	var found *etree.Element

	for _, el := range entity.ChildElements() {
		if !inNS(el, nsMetadata, "IDPSSODescriptor") {
			continue
		}

		if !containsToken(attrValue(el, "protocolSupportEnumeration"), nsProtocol) {
			continue
		}

		if found != nil {
			return nil, fmt.Errorf("%w: several IDPSSODescriptors support SAML 2.0", ErrInvalidMetadata)
		}

		found = el
	}

	if found == nil {
		return nil, fmt.Errorf("%w: no IDPSSODescriptor supporting SAML 2.0", ErrInvalidMetadata)
	}

	return found, nil
}

// containsToken reports whether the white-space separated list holds tok.
func containsToken(list, tok string) bool {
	for _, f := range strings.Fields(list) {
		if f == tok {
			return true
		}
	}

	return false
}

// signingCertificates collects the signing certificates of a role.
func signingCertificates(role *etree.Element) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for _, kd := range role.ChildElements() {
		if !inNS(kd, nsMetadata, "KeyDescriptor") {
			continue
		}

		if use := attrValue(kd, "use"); use != "" && use != "signing" {
			continue
		}

		for _, el := range kd.FindElements(".//X509Certificate") {
			if el.NamespaceURI() != nsDSig {
				continue
			}

			cert, err := parseCertificateText(el.Text())
			if err != nil {
				return nil, err
			}

			if !containsCert(certs, cert) {
				certs = append(certs, cert)
			}
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no signing certificate", ErrInvalidMetadata)
	}

	return certs, nil
}

// parseCertificateText decodes a base64 DER certificate, white space
// tolerated.
func parseCertificateText(text string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		return nil, fmt.Errorf("%w: certificate is not base64", ErrInvalidMetadata)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: unparsable certificate", ErrInvalidMetadata)
	}

	return cert, nil
}

func containsCert(certs []*x509.Certificate, c *x509.Certificate) bool {
	for _, x := range certs {
		if x.Equal(c) {
			return true
		}
	}

	return false
}

var errBadBoolean = errors.New("not an xs:boolean")

// parseXSBoolean parses an xs:boolean ("true", "false", "1", "0").
func parseXSBoolean(s string) (bool, error) {
	switch strings.TrimSpace(s) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, errBadBoolean
	}
}
