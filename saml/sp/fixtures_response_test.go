// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	_ "crypto/sha1" // SHA-1 fixtures
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/stretchr/testify/require"
)

// Namespaces and constants of the generated responses.
const (
	nsP          = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsA          = "urn:oasis:names:tc:SAML:2.0:assertion"
	statusOK     = "urn:oasis:names:tc:SAML:2.0:status:Success"
	bearer       = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	entityFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	pptClass     = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	nameIDValue  = "alice-pairwise-0001"
	assertionID  = "_a7f3c2b1e0d9a8f7e6d5c4b3a2f1e0d9c8b7a6f5"
	responseID   = "_r1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0"
)

// respParams are the values a generated response asserts.
type respParams struct {
	requestID string
	issued    time.Time // IssueInstant of the Response and the Assertion
}

// buildAssertion returns a standalone assertion with every field the Web
// Browser SSO profile requires (Profiles §4.1.4.2).
func buildAssertion(p respParams) *etree.Element {
	ts := func(d time.Duration) string { return p.issued.Add(d).UTC().Format("2006-01-02T15:04:05Z") }

	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsA)
	a.CreateAttr("ID", assertionID)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", ts(0))
	a.CreateElement("saml:Issuer").SetText(idpEntity)

	subject := a.CreateElement("saml:Subject")
	nid := subject.CreateElement("saml:NameID")
	nid.CreateAttr("Format", samlsp.NameIDFormatPersistent)
	nid.CreateAttr("NameQualifier", idpEntity)
	nid.CreateAttr("SPNameQualifier", spEntityID)
	nid.SetText(nameIDValue)

	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", bearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("InResponseTo", p.requestID)
	scd.CreateAttr("NotOnOrAfter", ts(5*time.Minute))
	scd.CreateAttr("Recipient", acsURL)

	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", ts(-time.Minute))
	cond.CreateAttr("NotOnOrAfter", ts(5*time.Minute))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(spEntityID)

	authn := a.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", ts(0))
	authn.CreateAttr("SessionIndex", "_session-42")
	authn.CreateAttr("SessionNotOnOrAfter", ts(8*time.Hour))
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(pptClass)

	attrs := a.CreateElement("saml:AttributeStatement")
	addAttribute(attrs, "mail", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", "", "alice@example.com")
	addAttribute(attrs, "groups", "", "", "admins", "devs")

	targeted := attrs.CreateElement("saml:Attribute")
	targeted.CreateAttr("Name", "urn:oid:1.3.6.1.4.1.5923.1.1.1.10")
	targeted.CreateAttr("FriendlyName", "eduPersonTargetedID")
	tnid := targeted.CreateElement("saml:AttributeValue").CreateElement("saml:NameID")
	tnid.CreateAttr("Format", samlsp.NameIDFormatPersistent)
	tnid.SetText("targeted-7")

	return a
}

// addAttribute adds an Attribute whose values re-declare xs/xsi, as
// OpenSAML-based IdPs do.
func addAttribute(stmt *etree.Element, name, format, friendly string, values ...string) {
	attr := stmt.CreateElement("saml:Attribute")
	attr.CreateAttr("Name", name)

	if format != "" {
		attr.CreateAttr("NameFormat", format)
	}

	if friendly != "" {
		attr.CreateAttr("FriendlyName", friendly)
	}

	for _, v := range values {
		av := attr.CreateElement("saml:AttributeValue")
		av.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
		av.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
		av.CreateAttr("xsi:type", "xs:string")
		av.SetText(v)
	}
}

// buildResponse returns a Response envelope (without assertion).
func buildResponse(p respParams) *etree.Element {
	r := etree.NewElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", nsP)
	r.CreateAttr("xmlns:saml", nsA)
	r.CreateAttr("ID", responseID)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", p.issued.UTC().Format("2006-01-02T15:04:05Z"))
	r.CreateAttr("Destination", acsURL)
	r.CreateAttr("InResponseTo", p.requestID)

	iss := r.CreateElement("saml:Issuer")
	iss.CreateAttr("Format", entityFormat)
	iss.SetText(idpEntity)

	r.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", statusOK)

	return r
}

// sigOpts configures a fixture signature.
type sigOpts struct {
	signer    keyPair // zero: idpA
	method    string  // zero: rsa-sha256 (ecdsa-sha256 for an EC key)
	canon     dsig.Canonicalizer
	noKeyInfo bool
	// inclusivePrefixes, when set, signs with an exc-c14n InclusiveNamespaces
	// PrefixList on the reference transform, as OpenSAML-based IdPs do.
	inclusivePrefixes string
}

// sign signs el (enveloped) and moves the signature right after Issuer, as
// the SAML schema places it; the enveloped transform makes its position
// irrelevant to the digest.
func sign(t testing.TB, el *etree.Element, o sigOpts) *etree.Element {
	t.Helper()

	if o.signer.signer == nil {
		o.signer = keys(t).idpA
	}

	ctx, err := dsig.NewSigningContext(o.signer.signer, [][]byte{o.signer.cert.Raw})
	require.NoError(t, err)

	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(o.inclusivePrefixes)
	if o.canon != nil {
		ctx.Canonicalizer = o.canon
	}

	method := o.method
	if method == "" {
		method = dsig.RSASHA256SignatureMethod
		if _, ok := o.signer.signer.(*ecdsa.PrivateKey); ok {
			method = dsig.ECDSASHA256SignatureMethod
		}
	}

	require.NoError(t, ctx.SetSignatureMethod(method))

	signedEl, err := ctx.SignEnveloped(el)
	require.NoError(t, err)

	// goxmldsig appends the signature without setting its parent: reparse
	// to get a consistent tree before moving it.
	signed := reparse(t, signedEl)
	sig := signed.ChildElements()[len(signed.ChildElements())-1]
	signed.RemoveChild(sig)
	signed.InsertChildAt(1, sig) // after Issuer

	if o.noKeyInfo {
		if ki := sig.FindElement("./KeyInfo"); ki != nil {
			sig.RemoveChild(ki)
		}
	}

	if o.inclusivePrefixes != "" {
		// goxmldsig digests with the prefix list but does not emit it:
		// declare it on the reference transform and sign SignedInfo again.
		transform := path(sig, "SignedInfo", "Reference", "Transforms").ChildElements()[1]
		inc := transform.CreateElement("ec:InclusiveNamespaces")
		inc.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
		inc.CreateAttr("PrefixList", o.inclusivePrefixes)
		resign(t, sig, o.signer, crypto.SHA256)
	}

	return signed
}

// resign recomputes the SignatureValue of sig after its SignedInfo changed
// (RSA PKCS#1 v1.5 with hash), canonicalizing SignedInfo as goxmldsig does.
func resign(t testing.TB, sig *etree.Element, key keyPair, hash crypto.Hash) {
	t.Helper()

	si := path(sig, "SignedInfo")

	nsCtx, err := etreeutils.NSBuildParentContext(si)
	require.NoError(t, err)

	detached, err := etreeutils.NSDetatch(nsCtx, si)
	require.NoError(t, err)

	canonical, err := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("").Canonicalize(detached)
	require.NoError(t, err)

	h := hash.New()
	_, _ = h.Write(canonical)

	value, err := key.signer.Sign(rand.Reader, h.Sum(nil), hash)
	require.NoError(t, err)

	path(sig, "SignatureValue").SetText(base64.StdEncoding.EncodeToString(value))
}

// reparse serializes el and parses it back.
func reparse(t testing.TB, el *etree.Element) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el)

	out, err := doc.WriteToString()
	require.NoError(t, err)

	parsed := etree.NewDocument()
	require.NoError(t, parsed.ReadFromString(out))

	return parsed.Root()
}

// respOpts configures a generated response.
type respOpts struct {
	signResponse   bool
	unsignedAssert bool // do not sign the assertion
	assertionSig   sigOpts
	responseSig    sigOpts
	// before mutates the response and the assertion before signing.
	before func(resp, assertion *etree.Element)
	// beforeAssertion mutates the standalone assertion before it is signed.
	beforeAssertion func(assertion *etree.Element)
	// after mutates the signed document (tampering).
	after func(resp *etree.Element)
	// raw mutates the final XML text.
	raw func(string) string
	// issued overrides the IssueInstant (default t0).
	issued time.Time
}

// respond builds the base64 SAMLResponse answering requestID.
func respond(t testing.TB, requestID string, o respOpts) string {
	t.Helper()

	return base64.StdEncoding.EncodeToString([]byte(respondXML(t, requestID, o)))
}

// respondXML builds the XML of the response answering requestID.
func respondXML(t testing.TB, requestID string, o respOpts) string {
	t.Helper()

	p := respParams{requestID: requestID, issued: t0}
	if !o.issued.IsZero() {
		p.issued = o.issued
	}

	assertion := buildAssertion(p)
	if o.beforeAssertion != nil {
		o.beforeAssertion(assertion)
	}

	if !o.unsignedAssert {
		assertion = sign(t, assertion, o.assertionSig)
	}

	resp := buildResponse(p)
	resp.AddChild(assertion)

	if o.before != nil {
		o.before(resp, assertion)
	}

	if o.signResponse {
		resp = sign(t, resp, o.responseSig)
	}

	if o.after != nil {
		o.after(resp)
	}

	doc := etree.NewDocument()
	doc.SetRoot(resp)

	out, err := doc.WriteToString()
	require.NoError(t, err)

	if o.raw != nil {
		out = o.raw(out)
	}

	return out
}

// encodeString base64-encodes an XML string.
func encodeString(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// exclusiveWithComments is the exc-c14n#WithComments canonicalizer.
func exclusiveWithComments() dsig.Canonicalizer {
	return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("")
}

// acsRequest builds an HTTP-POST binding request to the ACS of connection
// acme.
func acsRequest(samlResponse, relayState, cookie string) *http.Request {
	form := url.Values{"SAMLResponse": {samlResponse}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}

	req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: cookie})
	}

	return req
}

// complete posts samlResponse for the login lr from the same browser.
func complete(e *env, lr loginResult, samlResponse string) (*samlsp.LoginResult, error) {
	return e.sp.CompleteLogin(context.Background(), acsRequest(samlResponse, lr.relayState, lr.cookie.Value), connID)
}

// flow starts a login and posts the response generated with o.
func flow(t testing.TB, e *env, o respOpts) (*samlsp.LoginResult, error) {
	t.Helper()

	lr := begin(t, e, samlsp.LoginOptions{AppState: "/after"})

	return complete(e, lr, respond(t, lr.requestID, o))
}

// child returns the first child element of el with the local name tag.
func child(el *etree.Element, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}

	return nil
}

// path walks child elements by local names.
func path(el *etree.Element, tags ...string) *etree.Element {
	for _, tag := range tags {
		if el = child(el, tag); el == nil {
			return nil
		}
	}

	return el
}
