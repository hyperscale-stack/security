// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"strings"
	"time"
	"unicode"

	"github.com/russellhaering/gosaml2/types"
)

// replayRetentionMargin covers clock differences between instances and
// between an instance and the replay-cache backend.
const replayRetentionMargin = time.Minute

// verified bundles what the post-checks need besides the decoded response.
type verified struct {
	resp *types.Response
	raw  *rawResponse
	tx   *transaction
	conn *Connection
	// txExpiry is the transaction expiry: no assertion of this transaction
	// is ever accepted after it.
	txExpiry time.Time
	now      time.Time
	skew     time.Duration
	// scdNotOnOrAfter is the bearer confirmation expiry, set by
	// checkSubject.
	scdNotOnOrAfter time.Time
}

// check applies the Web Browser SSO processing rules (Profiles §4.1.4.2,
// §4.1.4.3 as amended by errata E17/E26/E52) and this package's policy to
// the verified response and returns the identity and the replay-cache
// retention.
func (v *verified) check() (*Identity, time.Time, error) {
	if len(v.resp.Assertions) != 1 {
		return nil, time.Time{}, reject(ErrMalformedResponse, "expected exactly one verified assertion", nil)
	}

	a := &v.resp.Assertions[0]

	if !v.resp.SignatureValidated && !a.SignatureValidated {
		return nil, time.Time{}, reject(ErrInvalidSignature, "the assertion is not covered by a verified signature", nil)
	}

	checks := []func(*types.Assertion) error{
		v.checkEnvelope, v.checkIssuers, v.checkInstants, v.checkSubject, v.checkConditions,
		v.checkAuthnStatement, v.checkNameID,
	}

	for _, c := range checks {
		if err := c(a); err != nil {
			return nil, time.Time{}, err
		}
	}

	return v.identity(a), v.replayExpiry(v.scdNotOnOrAfter), nil
}

// checkEnvelope checks the Response-level values. They may be unsigned when
// only the assertion is signed: they only ever add rejections.
func (v *verified) checkEnvelope(*types.Assertion) error {
	if v.resp.Version != samlVersion {
		return reject(ErrMalformedResponse, "unsupported SAML version", nil)
	}

	// Bindings §3.5.5.2: a signed message MUST carry Destination.
	if v.resp.SignatureValidated && v.resp.Destination == "" {
		return reject(ErrDestinationMismatch, "signed Response without Destination", nil)
	}

	if v.resp.Destination != "" && v.resp.Destination != v.conn.ACSURL {
		return reject(ErrDestinationMismatch, "Destination is not the connection's ACS URL", nil)
	}

	if v.resp.InResponseTo != "" && v.resp.InResponseTo != v.tx.RequestID {
		return reject(ErrInResponseToMismatch, "Response InResponseTo is not the request ID", nil)
	}

	return nil
}

// checkIssuers requires the connection's IdP entity ID on the Response and
// the Assertion (exact match).
func (v *verified) checkIssuers(a *types.Assertion) error {
	idp := v.conn.IdentityProvider.EntityID

	if v.resp.Issuer == nil || v.resp.Issuer.Value != idp || a.Issuer == nil || a.Issuer.Value != idp {
		return reject(ErrIssuerMismatch, "Issuer is not the connection's IdP entity ID", nil)
	}

	return nil
}

// checkInstants bounds the IssueInstants: not in the future beyond the skew
// and not before the AuthnRequest they answer.
func (v *verified) checkInstants(a *types.Assertion) error {
	earliest := v.tx.issuedAt().Add(-v.skew)
	latest := v.now.Add(v.skew)

	for _, instant := range []time.Time{v.resp.IssueInstant, a.IssueInstant} {
		switch {
		case instant.IsZero():
			return reject(ErrMalformedResponse, "missing IssueInstant", nil)
		case instant.After(latest):
			return reject(ErrAssertionNotYetValid, "IssueInstant in the future", nil)
		case instant.Before(earliest):
			return reject(ErrInvalidAssertion, "issued before the AuthnRequest it answers", nil)
		}
	}

	return nil
}

// checkSubject applies the bearer confirmation rules (Profiles §4.1.4.2,
// §4.1.4.3, errata E52): Recipient is the connection's ACS URL,
// InResponseTo is the request ID, NotOnOrAfter has not passed (exclusive,
// plus the skew).
func (v *verified) checkSubject(a *types.Assertion) error {
	if a.Subject == nil || a.Subject.SubjectConfirmation == nil || a.Subject.SubjectConfirmation.SubjectConfirmationData == nil ||
		a.Subject.SubjectConfirmation.Method != confirmationBearer {
		return reject(ErrInvalidAssertion, "missing bearer subject confirmation", nil)
	}

	scd := a.Subject.SubjectConfirmation.SubjectConfirmationData

	if scd.Recipient != v.conn.ACSURL {
		return reject(ErrRecipientMismatch, "Recipient is not the connection's ACS URL", nil)
	}

	switch {
	case scd.InResponseTo == "":
		return reject(ErrUnsolicitedResponse, "no InResponseTo in the bearer confirmation", nil)
	case scd.InResponseTo != v.tx.RequestID:
		return reject(ErrInResponseToMismatch, "InResponseTo is not the request ID", nil)
	}

	notOnOrAfter, err := parseSAMLTime(scd.NotOnOrAfter)
	if err != nil {
		return reject(ErrInvalidAssertion, "bearer confirmation without NotOnOrAfter", nil)
	}

	if !v.now.Before(notOnOrAfter.Add(v.skew)) {
		return reject(ErrAssertionExpired, "subject confirmation expired", nil)
	}

	v.scdNotOnOrAfter = notOnOrAfter

	return nil
}

// checkConditions applies Core §2.5.1: validity window (each bound
// optional, NotBefore before NotOnOrAfter) with the skew, and the audience
// restrictions — at least one, each naming the connection's SP entity ID
// (Profiles §4.1.4.2; Core §2.5.1.4, errata E46).
func (v *verified) checkConditions(a *types.Assertion) error {
	c := a.Conditions
	if c == nil || len(c.AudienceRestrictions) == 0 {
		return reject(ErrAudienceMismatch, "no AudienceRestriction", nil)
	}

	notBefore, notOnOrAfter, err := conditionBounds(c)
	if err != nil {
		return err
	}

	if !notBefore.IsZero() && v.now.Add(v.skew).Before(notBefore) {
		return reject(ErrAssertionNotYetValid, "assertion not yet valid", nil)
	}

	if !notOnOrAfter.IsZero() && !v.now.Before(notOnOrAfter.Add(v.skew)) {
		return reject(ErrAssertionExpired, "assertion expired", nil)
	}

	for _, restriction := range c.AudienceRestrictions {
		if !hasAudience(restriction, v.conn.SPEntityID) {
			return reject(ErrAudienceMismatch, "an AudienceRestriction does not name the SP entity ID", nil)
		}
	}

	return nil
}

// conditionBounds parses the optional Conditions bounds.
func conditionBounds(c *types.Conditions) (time.Time, time.Time, error) {
	var notBefore, notOnOrAfter time.Time

	if c.NotBefore != "" {
		t, err := parseSAMLTime(c.NotBefore)
		if err != nil {
			return time.Time{}, time.Time{}, reject(ErrMalformedResponse, "bad Conditions NotBefore", nil)
		}

		notBefore = t
	}

	if c.NotOnOrAfter != "" {
		t, err := parseSAMLTime(c.NotOnOrAfter)
		if err != nil {
			return time.Time{}, time.Time{}, reject(ErrMalformedResponse, "bad Conditions NotOnOrAfter", nil)
		}

		notOnOrAfter = t
	}

	if !notBefore.IsZero() && !notOnOrAfter.IsZero() && !notBefore.Before(notOnOrAfter) {
		return time.Time{}, time.Time{}, reject(ErrInvalidAssertion, "NotBefore is not before NotOnOrAfter", nil)
	}

	return notBefore, notOnOrAfter, nil
}

func hasAudience(r types.AudienceRestriction, sp string) bool {
	for _, a := range r.Audiences {
		if a.Value == sp {
			return true
		}
	}

	return false
}

// checkAuthnStatement checks the authentication instant and session bound,
// ForceAuthn freshness (Core §3.4.1) and the requested context classes
// (Core §3.3.2.2.1, exact comparison).
func (v *verified) checkAuthnStatement(a *types.Assertion) error {
	st := a.AuthnStatement
	if st == nil || st.AuthnInstant == nil {
		return reject(ErrInvalidAssertion, "missing AuthnStatement or AuthnInstant", nil)
	}

	if st.AuthnInstant.After(v.now.Add(v.skew)) {
		return reject(ErrAssertionNotYetValid, "AuthnInstant in the future", nil)
	}

	if st.SessionNotOnOrAfter != nil && !v.now.Before(st.SessionNotOnOrAfter.Add(v.skew)) {
		return reject(ErrAssertionExpired, "session already ended", nil)
	}

	if v.tx.ForceAuthn && st.AuthnInstant.Before(v.tx.issuedAt().Add(-v.skew)) {
		return reject(ErrStaleAuthentication, "", nil)
	}

	if len(v.tx.AuthnContext) > 0 && !contains(v.tx.AuthnContext, classRef(st)) {
		return reject(ErrAuthnContextMismatch, "", nil)
	}

	return nil
}

// classRef returns the AuthnContextClassRef of a statement ("" if none).
func classRef(st *types.AuthnStatement) string {
	if st.AuthnContext == nil || st.AuthnContext.AuthnContextClassRef == nil {
		return ""
	}

	return st.AuthnContext.AuthnContextClassRef.Value
}

// checkNameID requires a NameID that is not blank, in the requested format
// when one was requested (Core §3.4.1.1). Blank — empty, or only white
// space and invisible characters — is this package's policy (Core §2.2.2
// types NameID as a mere string): users whose IdP-side source attribute is
// blank would otherwise share one account. The value itself is never
// trimmed.
func (v *verified) checkNameID(a *types.Assertion) error {
	nid := a.Subject.NameID
	if nid == nil || isBlank(nid.Value) {
		return reject(ErrInvalidAssertion, "missing or empty NameID", nil)
	}

	if want := v.tx.NameIDFormat; want != "" && want != NameIDFormatUnspecified && nid.Format != want {
		return reject(ErrNameIDFormatMismatch, "", nil)
	}

	return nil
}

// isBlank reports whether s holds only Unicode white space (Zs, Zl, Zp,
// tab, line breaks, NEL) and control or format characters (Cc, Cf:
// zero-width spaces and joiners, word joiner, byte order mark, soft hyphen,
// bidi controls). Other characters that may render as nothing (Hangul
// fillers, variation selectors, a blank Braille pattern) are not blank.
func isBlank(s string) bool {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.In(r, unicode.Cc, unicode.Cf)
	}) == ""
}

// identity builds the verified identity.
func (v *verified) identity(a *types.Assertion) *Identity {
	nid := a.Subject.NameID
	st := a.AuthnStatement

	id := &Identity{
		ConnectionID: v.conn.ID,
		Issuer:       a.Issuer.Value,
		Audience:     v.conn.SPEntityID,
		NameID: NameID{
			Value: nid.Value, Format: nid.Format, NameQualifier: nid.NameQualifier, SPNameQualifier: nid.SPNameQualifier,
		},
		SessionIndex:         st.SessionIndex,
		AuthnInstant:         st.AuthnInstant.UTC(),
		AuthnContextClassRef: classRef(st),
		AssertionID:          a.ID,
		ProxyRestriction:     v.proxyRestriction(a.Conditions),
	}

	if st.SessionNotOnOrAfter != nil {
		id.SessionNotOnOrAfter = st.SessionNotOnOrAfter.UTC()
	}

	if a.AttributeStatement != nil {
		for _, attr := range a.AttributeStatement.Attributes {
			id.Attributes = append(id.Attributes, convertAttribute(attr))
		}
	}

	return id
}

// convertAttribute converts a decoded attribute; NameID-valued values are rendered
// as their NameID value.
func convertAttribute(attr types.Attribute) Attribute {
	out := Attribute{Name: attr.Name, NameFormat: attr.NameFormat, FriendlyName: attr.FriendlyName}

	for _, value := range attr.Values {
		if value.NameID != nil {
			out.Values = append(out.Values, value.NameID.Value)

			continue
		}

		out.Values = append(out.Values, value.Value)
	}

	return out
}

// proxyRestriction surfaces the ProxyRestriction condition; Count comes
// from the verified element, its presence from the pre-check (gosaml2
// decodes an absent Count as 0).
func (v *verified) proxyRestriction(c *types.Conditions) *ProxyRestriction {
	if c == nil || c.ProxyRestriction == nil {
		return nil
	}

	pr := &ProxyRestriction{}

	if v.raw.proxyCountPresent {
		count := c.ProxyRestriction.Count
		pr.Count = &count
	}

	for _, a := range c.ProxyRestriction.Audience {
		pr.Audiences = append(pr.Audiences, a.Value)
	}

	return pr
}

// replayExpiry is the replay-cache retention: the last instant the
// assertion could be accepted — its bearer confirmation NotOnOrAfter plus
// the skew, rounded up to the second (Profiles §4.1.4.5), but never beyond
// the transaction expiry, after which no response of this transaction is
// accepted (plan review F10) — plus a margin for clock differences.
func (v *verified) replayExpiry(scdNotOnOrAfter time.Time) time.Time {
	exp := scdNotOnOrAfter.Add(v.skew).UTC()
	if exp.Nanosecond() != 0 {
		exp = exp.Truncate(time.Second).Add(time.Second)
	}

	if v.txExpiry.Before(exp) {
		exp = v.txExpiry
	}

	return exp.Add(replayRetentionMargin)
}
