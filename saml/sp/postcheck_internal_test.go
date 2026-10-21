// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

// The post-checks repeat several rules gosaml2 or the structural pre-check
// already enforce (defence in depth: a dependency upgrade must not silently
// drop them). Those guards are unreachable through CompleteLogin, so they
// are tested here on hand-built decoded responses.

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pcNow = time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)

const (
	pcIdP = "https://idp.example.com"
	pcSP  = "https://sp.example.com/saml/x"
	pcACS = "https://sp.example.com/saml/x/acs"
	pcReq = "_req"
)

// validDecoded returns a decoded response every post-check accepts.
func validDecoded() *verified {
	instant := pcNow
	session := pcNow.Add(time.Hour)
	ts := func(d time.Duration) string { return formatSAMLTime(pcNow.Add(d)) }

	return &verified{
		resp: &types.Response{
			Version: "2.0", Destination: pcACS, InResponseTo: pcReq, IssueInstant: pcNow,
			Issuer:             &types.Issuer{Value: pcIdP},
			SignatureValidated: true,
			Assertions: []types.Assertion{{
				ID: "_a", Version: "2.0", IssueInstant: pcNow, Issuer: &types.Issuer{Value: pcIdP},
				Subject: &types.Subject{
					NameID: &types.NameID{Value: "alice", Format: NameIDFormatPersistent},
					SubjectConfirmation: &types.SubjectConfirmation{
						Method: confirmationBearer,
						SubjectConfirmationData: &types.SubjectConfirmationData{
							NotOnOrAfter: ts(5 * time.Minute), Recipient: pcACS, InResponseTo: pcReq,
						},
					},
				},
				Conditions: &types.Conditions{
					NotBefore: ts(-time.Minute), NotOnOrAfter: ts(5 * time.Minute),
					AudienceRestrictions: []types.AudienceRestriction{{Audiences: []types.Audience{{Value: pcSP}}}},
				},
				AuthnStatement: &types.AuthnStatement{AuthnInstant: &instant, SessionNotOnOrAfter: &session},
			}},
		},
		raw:      &rawResponse{},
		tx:       &transaction{RequestID: pcReq, IssuedAt: pcNow.Unix()},
		conn:     &Connection{ID: "x", SPEntityID: pcSP, ACSURL: pcACS, IdentityProvider: IdentityProvider{EntityID: pcIdP}},
		txExpiry: pcNow.Add(10 * time.Minute),
		now:      pcNow,
		skew:     DefaultClockSkew,
	}
}

func TestVerified_Accepts(t *testing.T) {
	t.Parallel()

	id, exp, err := validDecoded().check()
	require.NoError(t, err)
	assert.Equal(t, "alice", id.NameID.Value)
	assert.True(t, exp.Equal(pcNow.Add(5*time.Minute+DefaultClockSkew+replayRetentionMargin)))
}

func TestVerified_DefenceInDepth(t *testing.T) {
	t.Parallel()

	a := func(v *verified) *types.Assertion { return &v.resp.Assertions[0] }

	cases := []struct {
		name   string
		mutate func(*verified)
		want   error
	}{
		{"two assertions", func(v *verified) { v.resp.Assertions = append(v.resp.Assertions, v.resp.Assertions[0]) }, ErrMalformedResponse},
		{"nothing verified", func(v *verified) { v.resp.SignatureValidated = false }, ErrInvalidSignature},
		{"response version", func(v *verified) { v.resp.Version = "1.1" }, ErrMalformedResponse},
		{"signed without Destination", func(v *verified) { v.resp.Destination = "" }, ErrDestinationMismatch},
		{"other Destination", func(v *verified) { v.resp.Destination = "https://other/acs" }, ErrDestinationMismatch},
		{"other Response InResponseTo", func(v *verified) { v.resp.InResponseTo = "_x" }, ErrInResponseToMismatch},
		{"no Response issuer", func(v *verified) { v.resp.Issuer = nil }, ErrIssuerMismatch},
		{"other Response issuer", func(v *verified) { v.resp.Issuer.Value = "https://evil" }, ErrIssuerMismatch},
		{"no assertion issuer", func(v *verified) { a(v).Issuer = nil }, ErrIssuerMismatch},
		// gosaml2 refuses a foreign assertion Issuer first; this package
		// checks it again (audit F-24).
		{"other assertion issuer", func(v *verified) { a(v).Issuer.Value = "https://evil" }, ErrIssuerMismatch},
		{"zero IssueInstant", func(v *verified) { v.resp.IssueInstant = time.Time{} }, ErrMalformedResponse},
		{"no subject", func(v *verified) { a(v).Subject = nil }, ErrInvalidAssertion},
		{"no confirmation", func(v *verified) { a(v).Subject.SubjectConfirmation = nil }, ErrInvalidAssertion},
		{"no confirmation data", func(v *verified) { a(v).Subject.SubjectConfirmation.SubjectConfirmationData = nil }, ErrInvalidAssertion},
		{"not bearer", func(v *verified) { a(v).Subject.SubjectConfirmation.Method = "urn:x" }, ErrInvalidAssertion},
		{"other Recipient", func(v *verified) {
			a(v).Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = "https://other/acs"
		}, ErrRecipientMismatch},
		{"unparsable confirmation expiry", func(v *verified) {
			a(v).Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = "soon"
		}, ErrInvalidAssertion},
		{"unparsable NotBefore", func(v *verified) { a(v).Conditions.NotBefore = "x" }, ErrMalformedResponse},
		{"unparsable NotOnOrAfter", func(v *verified) { a(v).Conditions.NotOnOrAfter = "x" }, ErrMalformedResponse},
		{"no Conditions", func(v *verified) { a(v).Conditions = nil }, ErrAudienceMismatch},
		{"no AuthnStatement", func(v *verified) { a(v).AuthnStatement = nil }, ErrInvalidAssertion},
		{"no AuthnInstant", func(v *verified) { a(v).AuthnStatement.AuthnInstant = nil }, ErrInvalidAssertion},
		{"no NameID", func(v *verified) { a(v).Subject.NameID = nil }, ErrInvalidAssertion},
		{"blank NameID", func(v *verified) { a(v).Subject.NameID.Value = " \u200b\t" }, ErrInvalidAssertion},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v := validDecoded()
			tc.mutate(v)

			_, _, err := v.check()
			require.ErrorIs(t, err, tc.want)
			require.ErrorIs(t, err, ErrRejected)
		})
	}
}

func TestVerified_ReplayExpiryRoundsUp(t *testing.T) {
	t.Parallel()

	v := validDecoded()
	v.skew = 1500 * time.Millisecond

	exp := v.replayExpiry(pcNow)
	assert.True(t, exp.Equal(pcNow.Add(2*time.Second+replayRetentionMargin)), "ceil to the second: %s", exp)
}

func TestVerified_UnsignedAssertionInSignedResponse(t *testing.T) {
	t.Parallel()

	// Only the Response is signed: the assertion is covered by it.
	v := validDecoded()
	v.resp.Assertions[0].SignatureValidated = false
	_, _, err := v.check()
	require.NoError(t, err)

	// Only the assertion is signed.
	v = validDecoded()
	v.resp.SignatureValidated = false
	v.resp.Destination = ""
	v.resp.Assertions[0].SignatureValidated = true
	_, _, err = v.check()
	require.NoError(t, err)
}

func TestMapVerifyError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   error
		want error
	}{
		{"traversal limit", etreeutils.ErrTraversalLimit, ErrResponseTooLarge},
		{"missing signature", dsig.ErrMissingSignature, ErrInvalidSignature},
		{"destination", saml2.ErrInvalidValue{Key: saml2.DestinationAttr}, ErrDestinationMismatch},
		{"recipient", saml2.ErrInvalidValue{Key: saml2.RecipientAttr}, ErrRecipientMismatch},
		{"issuer", saml2.ErrInvalidValue{Key: saml2.IssuerTag}, ErrIssuerMismatch},
		{"status", saml2.ErrInvalidValue{Key: saml2.StatusCodeTag}, ErrResponseStatus},
		{"expired", saml2.ErrInvalidValue{Key: saml2.NotOnOrAfterAttr, Reason: saml2.ReasonExpired}, ErrAssertionExpired},
		{"version", saml2.ErrInvalidValue{Key: "SAML version"}, ErrMalformedResponse},
		{"other value", saml2.ErrInvalidValue{Key: saml2.SubjectConfirmationTag}, ErrInvalidAssertion},
		{"missing issuer", saml2.ErrMissingElement{Tag: saml2.IssuerTag}, ErrIssuerMismatch},
		{"missing element", saml2.ErrMissingElement{Tag: saml2.SubjectTag}, ErrInvalidAssertion},
		{"parsing", saml2.ErrParsing{Tag: "x"}, ErrMalformedResponse},
		{"unknown", errors.New("Signature could not be verified"), ErrInvalidSignature},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := mapVerifyError(tc.in)
			require.ErrorIs(t, err, tc.want)
			require.ErrorIs(t, err, ErrRejected)
			require.ErrorIs(t, err, tc.in, "the cause stays reachable")
			assert.NotContains(t, err.Error(), tc.in.Error(), "the cause text is never printed")
		})
	}
}

func TestRejection(t *testing.T) {
	t.Parallel()

	bare := reject(ErrAudienceMismatch, "", nil)
	assert.Equal(t, ErrAudienceMismatch.Error(), bare.Error())
	require.ErrorIs(t, bare, ErrRejected)

	detailed := reject(ErrAudienceMismatch, "static detail", errors.New("echo <attacker>"))
	assert.Equal(t, ErrAudienceMismatch.Error()+" (static detail)", detailed.Error())
	assert.NotContains(t, detailed.Error(), "attacker")
}

func TestSanitize(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "a b", sanitizeDiagnostic("a\x00\t b\u0085\u009b"))
	assert.Equal(t, "urn:x", sanitizeURI("urn:\n x\x7f"))
	assert.Len(t, sanitizeDiagnostic(repeatRune('é', 300)), 256)
	assert.Len(t, sanitizeURI(repeatRune('a', 300)), 256)
}

func repeatRune(r rune, n int) string {
	out := make([]rune, n)
	for i := range out {
		out[i] = r
	}

	return string(out)
}

func TestRolloverCandidates(t *testing.T) {
	t.Parallel()

	cert := func(notBefore, notAfter time.Duration) *x509.Certificate {
		return &x509.Certificate{NotBefore: pcNow.Add(notBefore), NotAfter: pcNow.Add(notAfter)}
	}

	expired := cert(-48*time.Hour, -time.Hour)
	future := cert(time.Hour, 48*time.Hour)
	c1, c2, c3, c4 := cert(-10*time.Hour, 24*time.Hour), cert(-5*time.Hour, 24*time.Hour),
		cert(-3*time.Hour, 24*time.Hour), cert(-time.Hour, 24*time.Hour)

	// Each candidate re-runs the whole verification: the three most recent
	// valid certificates, newest first (code review F4).
	got := rolloverCandidates([]*x509.Certificate{c1, expired, c2, future, c3, c4}, pcNow)
	assert.Equal(t, []*x509.Certificate{c4, c3, c2}, got)
	assert.Equal(t, []*x509.Certificate{c2, c1}, rolloverCandidates([]*x509.Certificate{c1, c2}, pcNow))
	assert.Empty(t, rolloverCandidates([]*x509.Certificate{expired, future}, pcNow))
}

// TestPreferCertificate: the certificate that last verified moves to the
// front, the others keep their order, and nothing is ever added (audit
// SAML-01: an ordering hint, never a trust decision).
func TestPreferCertificate(t *testing.T) {
	t.Parallel()

	c1, c2, c3 := &x509.Certificate{Raw: []byte("one")}, &x509.Certificate{Raw: []byte("two")}, &x509.Certificate{Raw: []byte("three")}
	all := []*x509.Certificate{c1, c2, c3}

	assert.Equal(t, []*x509.Certificate{c3, c1, c2}, preferCertificate(all, sha256.Sum256([]byte("three"))))
	assert.Equal(t, []*x509.Certificate{c2, c1, c3}, preferCertificate(all, sha256.Sum256([]byte("two"))))
	assert.Equal(t, all, preferCertificate(all, sha256.Sum256([]byte("one"))))
	assert.Equal(t, all, preferCertificate(all, sha256.Sum256([]byte("absent"))), "a certificate no longer a candidate is not added")
	assert.Equal(t, []*x509.Certificate{c1, c2, c3}, all, "the candidates are not modified")
	assert.Empty(t, preferCertificate(nil, sha256.Sum256([]byte("one"))))
}

func TestVerifyResponse_NoValidCertificate(t *testing.T) {
	t.Parallel()

	expired := &x509.Certificate{NotBefore: pcNow.Add(-48 * time.Hour), NotAfter: pcNow.Add(-24 * time.Hour)}
	sp := &ServiceProvider{cfg: Config{ClockSkew: DefaultClockSkew}}
	conn := &Connection{IdentityProvider: IdentityProvider{SigningCertificates: []*x509.Certificate{expired, expired}}}

	_, err := sp.verifyResponse(&rawResponse{keyInfoMissing: true}, conn, pcNow)
	require.ErrorIs(t, err, ErrInvalidSignature)
}
