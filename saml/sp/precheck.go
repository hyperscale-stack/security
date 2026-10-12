// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"errors"
	"strconv"

	"github.com/beevik/etree"
)

// rawResponse is what the structural pre-check learned from the raw tree.
// Only C14N-invariant structure is read from it (element counts, attribute
// presence and values); identity data is read exclusively from the verified
// canonical form decoded by gosaml2.
type rawResponse struct {
	// data are the exact bytes checked here and verified by gosaml2.
	data []byte
	// status is the top-level status of the Response.
	status responseStatus
	// inResponseTo is the (possibly unsigned) Response InResponseTo.
	inResponseTo string
	// keyInfoMissing reports a signature without KeyInfo: the certificate
	// rollover retry applies.
	keyInfoMissing bool
	// proxyCountPresent reports a ProxyRestriction with a Count attribute.
	proxyCountPresent bool
}

// responseStatus is the decoded <samlp:Status> (sanitized diagnostics).
type responseStatus struct {
	code, subCode, message string
}

func (s responseStatus) success() bool { return s.code == statusSuccess }

// gateRejection maps a lexical-gate refusal to a rejection.
func gateRejection(err error) error {
	var ge *gateError
	if errors.As(err, &ge) && ge.tooLarge {
		return reject(ErrResponseTooLarge, ge.msg, nil)
	}

	return reject(ErrMalformedResponse, err.Error(), nil)
}

// precheck runs the lexical gate and the structural rules on the decoded
// SAMLResponse. It never performs signature work: every input it refuses
// is refused before goxmldsig runs. With a non-Success status it only
// checks the envelope (an error response carries no assertion and is never
// trusted).
func precheck(data []byte, allowSHA1 bool) (*rawResponse, error) {
	if err := checkXML(data, responseLimits); err != nil {
		return nil, gateRejection(err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, reject(ErrMalformedResponse, "not well-formed XML", nil)
	}

	root := doc.Root()

	if err := checkEnvelope(root); err != nil {
		return nil, err
	}

	status, err := readStatus(root)
	if err != nil {
		return nil, err
	}

	raw := &rawResponse{data: data, status: status, inResponseTo: root.SelectAttrValue("InResponseTo", "")}
	assertions := descendants(root, nsAssertion, "Assertion")

	if !status.success() {
		if len(assertions) != 0 {
			return nil, reject(ErrMalformedResponse, "an error response carries an assertion", nil)
		}

		return raw, nil
	}

	if len(assertions) != 1 || assertions[0].Parent() != root {
		return nil, reject(ErrMalformedResponse, "a response must carry exactly one assertion, child of the Response", nil)
	}

	assertion := assertions[0]

	if err := checkAssertionHeader(assertion); err != nil {
		return nil, err
	}

	if err := checkIssuers(root, "Response"); err != nil {
		return nil, err
	}

	if raw.keyInfoMissing, err = checkSignatures(root, assertion, allowSHA1); err != nil {
		return nil, err
	}

	if err := checkAssertion(assertion, raw); err != nil {
		return nil, err
	}

	return raw, nil
}

// checkEnvelope checks the root, the identifiers, the absence of encrypted
// content and the time formats.
func checkEnvelope(root *etree.Element) error {
	if !inNS(root, nsProtocol, "Response") {
		return reject(ErrMalformedResponse, "root is not a SAML 2.0 Response", nil)
	}

	if root.SelectAttrValue("Version", "") != samlVersion {
		return reject(ErrMalformedResponse, "unsupported SAML version", nil)
	}

	if root.SelectAttrValue("ID", "") == "" || root.SelectAttr("IssueInstant") == nil {
		return reject(ErrMalformedResponse, "Response without ID or IssueInstant", nil)
	}

	if err := checkIDs(root); err != nil {
		return err
	}

	if err := checkNoEncryption(root); err != nil {
		return err
	}

	return checkTimeFormats(root)
}

// descendants returns el's descendants (el excluded) named {ns}local.
func descendants(el *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element

	for _, c := range el.ChildElements() {
		if inNS(c, ns, local) {
			out = append(out, c)
		}

		out = append(out, descendants(c, ns, local)...)
	}

	return out
}

// children returns el's child elements named {ns}local.
func children(el *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element

	for _, c := range el.ChildElements() {
		if inNS(c, ns, local) {
			out = append(out, c)
		}
	}

	return out
}

// walk calls fn on el and every descendant, stopping at the first error.
func walk(el *etree.Element, fn func(*etree.Element) error) error {
	if err := fn(el); err != nil {
		return err
	}

	for _, c := range el.ChildElements() {
		if err := walk(c, fn); err != nil {
			return err
		}
	}

	return nil
}

// checkIDs refuses duplicate identifier values (Core §1.3.4: exactly one
// declaration per identifier), whatever the identifier attribute.
func checkIDs(root *etree.Element) error {
	seen := map[string]struct{}{}

	return walk(root, func(el *etree.Element) error {
		for _, a := range el.Attr {
			if !isIDAttribute(a) {
				continue
			}

			if _, dup := seen[a.Value]; dup {
				return reject(ErrMalformedResponse, "duplicate identifier", nil)
			}

			seen[a.Value] = struct{}{}
		}

		return nil
	})
}

// isIDAttribute reports the attributes used as identifiers: unprefixed
// ID/Id/id and xml:id (the gate refuses any other prefixed form).
func isIDAttribute(a etree.Attr) bool {
	return (a.Space == "" && isIDName(a.Key)) || (a.Space == prefixXML && a.Key == "id")
}

// encryptedElements are the SAML elements carrying encrypted content.
var encryptedElements = map[string]bool{"EncryptedAssertion": true, "EncryptedID": true, "EncryptedAttribute": true}

// nsXMLEnc11 is the XML Encryption 1.1 namespace.
const nsXMLEnc11 = "http://www.w3.org/2009/xmlenc11#"

// checkNoEncryption refuses encrypted content anywhere: encryption is not
// supported and SP metadata publishes no encryption key.
func checkNoEncryption(root *etree.Element) error {
	return walk(root, func(el *etree.Element) error {
		ns := el.NamespaceURI()
		if ns == nsXMLEnc || ns == nsXMLEnc11 || (ns == nsAssertion && encryptedElements[el.Tag]) {
			return reject(ErrEncryptedAssertionUnsupported, "", nil)
		}

		return nil
	})
}

// timeAttributes are the SAML attributes holding time instants.
var timeAttributes = map[string]bool{
	"IssueInstant": true, "NotBefore": true, "NotOnOrAfter": true, "AuthnInstant": true, "SessionNotOnOrAfter": true,
}

// checkTimeFormats requires every SAML time value to be in the UTC form of
// Core §1.3.3.
func checkTimeFormats(root *etree.Element) error {
	return walk(root, func(el *etree.Element) error {
		if ns := el.NamespaceURI(); ns != nsAssertion && ns != nsProtocol {
			return nil
		}

		for _, a := range el.Attr {
			if a.Space == "" && timeAttributes[a.Key] && !isSAMLTime(a.Value) {
				return reject(ErrMalformedResponse, "time value not in UTC xs:dateTime form", nil)
			}
		}

		return nil
	})
}

// readStatus decodes the single top-level Status.
func readStatus(root *etree.Element) (responseStatus, error) {
	statuses := children(root, nsProtocol, "Status")
	if len(statuses) != 1 {
		return responseStatus{}, reject(ErrMalformedResponse, "a Response needs exactly one Status", nil)
	}

	codes := children(statuses[0], nsProtocol, "StatusCode")
	if len(codes) != 1 || codes[0].SelectAttrValue("Value", "") == "" {
		return responseStatus{}, reject(ErrMalformedResponse, "a Status needs exactly one StatusCode with a Value", nil)
	}

	subs := children(codes[0], nsProtocol, "StatusCode")
	messages := children(statuses[0], nsProtocol, "StatusMessage")

	if len(subs) > 1 || len(messages) > 1 {
		return responseStatus{}, reject(ErrMalformedResponse, "repeated StatusCode or StatusMessage", nil)
	}

	st := responseStatus{code: sanitizeURI(codes[0].SelectAttrValue("Value", ""))}

	if len(subs) == 1 {
		st.subCode = sanitizeURI(subs[0].SelectAttrValue("Value", ""))
	}

	if len(messages) == 1 {
		st.message = sanitizeDiagnostic(messages[0].Text())
	}

	return st, nil
}

// checkIssuers requires exactly one Issuer child of el whose Format is
// absent or entity (Profiles §4.1.4.2, Core §2.2.5). A Response without
// Issuer is refused even unsigned (errata E17 only requires it when signed;
// gosaml2 always does).
func checkIssuers(el *etree.Element, what string) error {
	issuers := children(el, nsAssertion, "Issuer")
	if len(issuers) != 1 {
		return reject(ErrIssuerMismatch, what+" needs exactly one Issuer", nil)
	}

	if f := issuers[0].SelectAttrValue("Format", nameIDFormatEntity); f != nameIDFormatEntity {
		return reject(ErrIssuerMismatch, what+" Issuer Format is not entity", nil)
	}

	return nil
}

// checkAssertionHeader checks the assertion version, ID and IssueInstant.
func checkAssertionHeader(a *etree.Element) error {
	if a.SelectAttrValue("Version", "") != samlVersion {
		return reject(ErrMalformedResponse, "unsupported assertion version", nil)
	}

	if a.SelectAttrValue("ID", "") == "" || a.SelectAttr("IssueInstant") == nil {
		return reject(ErrMalformedResponse, "Assertion without ID or IssueInstant", nil)
	}

	return nil
}

// checkAssertion enforces the strict assertion shape: a shape that
// gosaml2's single-valued decoding would merge ambiguously is refused.
func checkAssertion(a *etree.Element, raw *rawResponse) error {
	if err := checkIssuers(a, "Assertion"); err != nil {
		return err
	}

	subjects := children(a, nsAssertion, "Subject")
	if len(subjects) != 1 {
		return reject(ErrInvalidAssertion, "an assertion needs exactly one Subject", nil)
	}

	if err := checkSubject(subjects[0]); err != nil {
		return err
	}

	conditions := children(a, nsAssertion, "Conditions")
	if len(conditions) > 1 {
		return reject(ErrInvalidAssertion, "repeated Conditions", nil)
	}

	if len(conditions) == 1 {
		if err := checkConditions(conditions[0], raw); err != nil {
			return err
		}
	}

	statements := children(a, nsAssertion, "AuthnStatement")
	if len(statements) != 1 {
		return reject(ErrInvalidAssertion, "an assertion needs exactly one AuthnStatement", nil)
	}

	if err := checkAuthnStatement(statements[0]); err != nil {
		return err
	}

	for _, v := range descendants(a, nsAssertion, "AttributeValue") {
		if len(children(v, nsAssertion, "NameID")) > 1 {
			return reject(ErrInvalidAssertion, "repeated NameID in an AttributeValue", nil)
		}
	}

	return nil
}

// checkSubject requires one NameID and one bearer SubjectConfirmation with
// one SubjectConfirmationData without NotBefore (Profiles §4.1.4.2).
func checkSubject(s *etree.Element) error {
	if len(children(s, nsAssertion, "BaseID")) > 0 {
		return reject(ErrInvalidAssertion, "BaseID subjects are not supported", nil)
	}

	if len(children(s, nsAssertion, "NameID")) != 1 {
		return reject(ErrInvalidAssertion, "a Subject needs exactly one NameID", nil)
	}

	confirmations := children(s, nsAssertion, "SubjectConfirmation")
	if len(confirmations) != 1 {
		return reject(ErrInvalidAssertion, "a Subject needs exactly one SubjectConfirmation", nil)
	}

	sc := confirmations[0]
	if sc.SelectAttrValue("Method", "") != confirmationBearer {
		return reject(ErrInvalidAssertion, "the subject confirmation is not bearer", nil)
	}

	data := children(sc, nsAssertion, "SubjectConfirmationData")
	if len(data) != 1 {
		return reject(ErrInvalidAssertion, "a bearer confirmation needs exactly one SubjectConfirmationData", nil)
	}

	if data[0].SelectAttr("NotBefore") != nil {
		return reject(ErrInvalidAssertion, "a bearer SubjectConfirmationData must not carry NotBefore", nil)
	}

	return nil
}

// checkConditions refuses conditions that are not understood (Core
// §2.5.1.1: Indeterminate MUST be rejected) and repeated singletons.
func checkConditions(c *etree.Element, raw *rawResponse) error {
	var oneTimeUse, proxy int

	for _, ch := range c.ChildElements() {
		if ch.NamespaceURI() != nsAssertion {
			return reject(ErrInvalidAssertion, "condition not understood", nil)
		}

		switch ch.Tag {
		case "AudienceRestriction":
			if err := onlyAudiences(ch, true); err != nil {
				return err
			}
		case "OneTimeUse":
			oneTimeUse++
		case "ProxyRestriction":
			proxy++

			if err := checkProxyRestriction(ch, raw); err != nil {
				return err
			}
		default:
			return reject(ErrInvalidAssertion, "condition not understood", nil)
		}
	}

	if oneTimeUse > 1 || proxy > 1 {
		return reject(ErrInvalidAssertion, "repeated OneTimeUse or ProxyRestriction", nil)
	}

	return nil
}

// onlyAudiences requires el's children to be Audience elements (at least
// one when required).
func onlyAudiences(el *etree.Element, required bool) error {
	audiences := children(el, nsAssertion, "Audience")
	if len(audiences) != len(el.ChildElements()) || (required && len(audiences) == 0) {
		return reject(ErrInvalidAssertion, "malformed audience list", nil)
	}

	return nil
}

// checkProxyRestriction validates a ProxyRestriction and records whether it
// sets Count (attribute presence is C14N-invariant).
func checkProxyRestriction(pr *etree.Element, raw *rawResponse) error {
	if err := onlyAudiences(pr, false); err != nil {
		return err
	}

	if a := pr.SelectAttr("Count"); a != nil {
		if n, err := strconv.Atoi(a.Value); err != nil || n < 0 {
			return reject(ErrInvalidAssertion, "ProxyRestriction Count is not a non-negative integer", nil)
		}

		raw.proxyCountPresent = true
	}

	return nil
}

// checkAuthnStatement requires AuthnInstant and one AuthnContext with at
// most one class reference.
func checkAuthnStatement(st *etree.Element) error {
	if st.SelectAttr("AuthnInstant") == nil {
		return reject(ErrInvalidAssertion, "AuthnStatement without AuthnInstant", nil)
	}

	contexts := children(st, nsAssertion, "AuthnContext")
	if len(contexts) != 1 {
		return reject(ErrInvalidAssertion, "an AuthnStatement needs exactly one AuthnContext", nil)
	}

	if len(children(contexts[0], nsAssertion, "AuthnContextClassRef")) > 1 {
		return reject(ErrInvalidAssertion, "repeated AuthnContextClassRef", nil)
	}

	return nil
}
