// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/beevik/etree"
)

// Metadata returns the SP metadata of a connection (Metadata §2.3.2,
// §2.4.4): an EntityDescriptor whose entityID is the connection's SP entity
// ID, with a cacheDuration (the root of a metadata instance must carry
// validUntil or cacheDuration; no validUntil is set, so an administrator's
// copy never expires) and one SPSSODescriptor that
//
//   - supports the SAML 2.0 protocol;
//   - sets AuthnRequestsSigned to whether the SP signs its requests;
//   - omits WantAssertionsSigned: a signed Response covering the assertion
//     is accepted as well as a signed Assertion (Profiles §4.1.3.5 and
//     §4.1.4.5 as amended by errata E93 and E26);
//   - publishes the SP certificates with an explicit use="signing" (a
//     KeyDescriptor without use would also announce an encryption key) and
//     no encryption key at all: encrypted assertions are refused;
//   - lists the connection's NameIDFormat, if any;
//   - declares one AssertionConsumerService, HTTP-POST binding, at the
//     connection's ACS URL, index 0 and default.
//
// No SingleLogoutService is published: Single Logout is not supported.
func (sp *ServiceProvider) Metadata(ctx context.Context, connectionID string) ([]byte, error) {
	conn, err := sp.resolve(ctx, connectionID)
	if err != nil {
		return nil, err
	}

	return sp.metadataDocument(conn)
}

// metadataDocument renders the SP metadata of conn.
func (sp *ServiceProvider) metadataDocument(conn *Connection) ([]byte, error) {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", nsDSig)
	ed.CreateAttr("entityID", conn.SPEntityID)
	ed.CreateAttr("cacheDuration", formatXSDuration(sp.cfg.MetadataCacheDuration))

	sso := ed.CreateElement("md:SPSSODescriptor")
	sso.CreateAttr("protocolSupportEnumeration", nsProtocol)
	sso.CreateAttr("AuthnRequestsSigned", strconv.FormatBool(sp.cfg.SigningKey != nil))

	for _, der := range sp.metadataCerts {
		kd := sso.CreateElement("md:KeyDescriptor")
		kd.CreateAttr("use", "signing")
		kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
			SetText(base64.StdEncoding.EncodeToString(der))
	}

	if conn.NameIDFormat != "" {
		sso.CreateElement("md:NameIDFormat").SetText(conn.NameIDFormat)
	}

	acs := sso.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("Binding", bindingHTTPPost)
	acs.CreateAttr("Location", conn.ACSURL)
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")

	doc.Indent(2)

	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("samlsp: render metadata: %w", err)
	}

	return out, nil
}

// ServeMetadata writes the SP metadata of a connection to w: GET and HEAD
// only (405 with an Allow header otherwise), Content-Type
// application/samlmetadata+xml (Metadata §4.1.1), public caching for the
// configured cache duration, 404 for an unknown connection and 500 for any
// other failure (bodies carry no detail). The application routes, for
// instance, /saml/{connection}/metadata to it.
func (sp *ServiceProvider) ServeMetadata(w http.ResponseWriter, r *http.Request, connectionID string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}

	body, err := sp.Metadata(r.Context(), connectionID)

	switch {
	case errors.Is(err, ErrUnknownConnection):
		http.NotFound(w, r)

		return
	case err != nil:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", metadataMediaType)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.FormatInt(int64(sp.cfg.MetadataCacheDuration.Seconds()), 10))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}
