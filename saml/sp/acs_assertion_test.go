// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ts renders t0+d as a SAML time value.
func ts(d time.Duration) string { return t0.Add(d).UTC().Format("2006-01-02T15:04:05Z") }

// onAssertion mutates the assertion before it is signed.
func onAssertion(f func(a *etree.Element)) respOpts { return respOpts{beforeAssertion: f} }

// onResponse mutates the (unsigned) Response envelope.
func onResponse(f func(r *etree.Element)) respOpts {
	return respOpts{before: func(r, _ *etree.Element) { f(r) }}
}

func scd(a *etree.Element) *etree.Element {
	return path(a, "Subject", "SubjectConfirmation", "SubjectConfirmationData")
}

func TestCompleteLogin_Versions(t *testing.T) {
	t.Parallel()

	reject(t, onResponse(func(r *etree.Element) { r.CreateAttr("Version", "1.1") }), samlsp.ErrMalformedResponse)
	reject(t, onAssertion(func(a *etree.Element) { a.CreateAttr("Version", "2.1") }), samlsp.ErrMalformedResponse)
}

func TestCompleteLogin_Destination(t *testing.T) {
	t.Parallel()

	reject(t, respOpts{signResponse: true, before: func(r, _ *etree.Element) { r.RemoveAttr("Destination") }},
		samlsp.ErrDestinationMismatch)
	reject(t, respOpts{signResponse: true, before: func(r, _ *etree.Element) { r.CreateAttr("Destination", "https://other.example.com/acs") }},
		samlsp.ErrDestinationMismatch)
	reject(t, onResponse(func(r *etree.Element) { r.CreateAttr("Destination", "https://sp.example.com/saml/globex/acs") }),
		samlsp.ErrDestinationMismatch)

	// An unsigned Response may omit Destination (Bindings §3.5.5.2 only
	// requires it on signed messages).
	_, err := flow(t, newEnv(t), onResponse(func(r *etree.Element) { r.RemoveAttr("Destination") }))
	require.NoError(t, err)
}

func TestCompleteLogin_Issuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		o    respOpts
	}{
		{"response issuer of another IdP", onResponse(func(r *etree.Element) { child(r, "Issuer").SetText("https://idp.example.com/globex") })},
		{"assertion issuer of another IdP", onAssertion(func(a *etree.Element) { child(a, "Issuer").SetText("https://idp.example.com/globex") })},
		{"response without issuer (strict profile)", onResponse(func(r *etree.Element) { r.RemoveChild(child(r, "Issuer")) })},
		{"two response issuers", onResponse(func(r *etree.Element) { r.InsertChildAt(0, child(r, "Issuer").Copy()) })},
		{"response issuer format not entity", onResponse(func(r *etree.Element) {
			child(r, "Issuer").CreateAttr("Format", samlsp.NameIDFormatPersistent)
		})},
		{"assertion issuer format not entity", onAssertion(func(a *etree.Element) {
			child(a, "Issuer").CreateAttr("Format", samlsp.NameIDFormatEmailAddress)
		})},
		{"assertion without issuer", onAssertion(func(a *etree.Element) { a.RemoveChild(child(a, "Issuer")) })},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reject(t, tc.o, samlsp.ErrIssuerMismatch)
		})
	}
}

func TestCompleteLogin_InResponseTo(t *testing.T) {
	t.Parallel()

	t.Run("response of another transaction of the same browser", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		first := begin(t, e, samlsp.LoginOptions{})
		second := begin(t, e, samlsp.LoginOptions{}, first.cookie)

		// Recombination of RelayState and response (Bindings §3.5.5.2).
		_, err := complete(e, first, respond(t, second.requestID, respOpts{}))
		requireRejected(t, e, first, err, samlsp.ErrInResponseToMismatch)
	})

	reject(t, onResponse(func(r *etree.Element) { r.CreateAttr("InResponseTo", "_other") }), samlsp.ErrInResponseToMismatch)
	reject(t, onAssertion(func(a *etree.Element) { scd(a).CreateAttr("InResponseTo", "_other") }), samlsp.ErrInResponseToMismatch)
	reject(t, onAssertion(func(a *etree.Element) { scd(a).RemoveAttr("InResponseTo") }), samlsp.ErrUnsolicitedResponse)

	// Core §3.2.2: a response to a request whose ID is known MUST carry
	// InResponseTo; a Success without it is unsolicited, refused before any
	// signature work (audit SAML-I11).
	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	_, err := complete(e, lr, respond(t, lr.requestID, onResponse(func(r *etree.Element) { r.RemoveAttr("InResponseTo") })))
	requireRejected(t, e, lr, err, samlsp.ErrUnsolicitedResponse)
	assert.Equal(t, samlsp.ErrUnsolicitedResponse.Error()+" (no InResponseTo on the Response)", err.Error())

	// An error status may lack it (a malformed request has no ID to answer).
	r := buildResponse(respParams{requestID: lr.requestID, issued: t0})
	r.RemoveAttr("InResponseTo")
	path(r, "Status", "StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Requester")

	_, err = complete(e, lr, encodeElement(t, r))
	requireRejected(t, e, lr, err, samlsp.ErrResponseStatus)
}

func TestCompleteLogin_SubjectConfirmation(t *testing.T) {
	t.Parallel()

	reject(t, onAssertion(func(a *etree.Element) { scd(a).CreateAttr("Recipient", "https://sp.example.com/saml/globex/acs") }),
		samlsp.ErrRecipientMismatch)
	reject(t, onAssertion(func(a *etree.Element) { scd(a).RemoveAttr("Recipient") }), samlsp.ErrRecipientMismatch)
	reject(t, onAssertion(func(a *etree.Element) {
		path(a, "Subject", "SubjectConfirmation").CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key")
	}), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) { scd(a).RemoveAttr("NotOnOrAfter") }), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) { scd(a).CreateAttr("NotBefore", ts(-time.Minute)) }), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		sc := path(a, "Subject", "SubjectConfirmation")
		sc.RemoveChild(child(sc, "SubjectConfirmationData"))
	}), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		s := path(a, "Subject")
		s.AddChild(child(s, "SubjectConfirmation").Copy())
	}), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		s := path(a, "Subject")
		s.RemoveChild(child(s, "SubjectConfirmation"))
	}), samlsp.ErrInvalidAssertion)
}

// timeBoundary checks that a response is accepted at accept and rejected
// with want at rejectAt (both relative to t0).
func timeBoundary(t *testing.T, o respOpts, accept, rejectAt time.Duration, want error) {
	t.Helper()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	resp := respond(t, lr.requestID, o)

	e.clock.set(t0.Add(rejectAt))
	_, err := complete(e, lr, resp)
	requireRejected(t, e, lr, err, want)

	e.clock.set(t0.Add(accept))
	_, err = complete(e, lr, resp)
	require.NoError(t, err, "accepted at the boundary")
}

func TestCompleteLogin_TimeBoundaries(t *testing.T) {
	t.Parallel()

	skew := samlsp.DefaultClockSkew

	// Keep the other bounds out of the way of the one under test.
	wide := func(a *etree.Element) {
		scd(a).CreateAttr("NotOnOrAfter", ts(9*time.Minute))
		child(a, "Conditions").CreateAttr("NotOnOrAfter", ts(9*time.Minute))
	}

	t.Run("SubjectConfirmationData NotOnOrAfter + skew is exclusive", func(t *testing.T) {
		t.Parallel()

		timeBoundary(t, onAssertion(func(a *etree.Element) {
			wide(a)
			scd(a).CreateAttr("NotOnOrAfter", ts(5*time.Minute))
		}), 5*time.Minute+skew-time.Second, 5*time.Minute+skew, samlsp.ErrAssertionExpired)
	})

	t.Run("Conditions NotOnOrAfter + skew is exclusive", func(t *testing.T) {
		t.Parallel()

		timeBoundary(t, onAssertion(func(a *etree.Element) {
			wide(a)
			child(a, "Conditions").CreateAttr("NotOnOrAfter", ts(5*time.Minute))
		}), 5*time.Minute+skew-time.Second, 5*time.Minute+skew, samlsp.ErrAssertionExpired)
	})

	t.Run("Conditions NotBefore - skew is inclusive", func(t *testing.T) {
		t.Parallel()

		timeBoundary(t, onAssertion(func(a *etree.Element) {
			wide(a)
			child(a, "Conditions").CreateAttr("NotBefore", ts(5*time.Minute))
		}), 5*time.Minute-skew, 5*time.Minute-skew-time.Second, samlsp.ErrAssertionNotYetValid)
	})

	t.Run("SessionNotOnOrAfter + skew is exclusive", func(t *testing.T) {
		t.Parallel()

		timeBoundary(t, onAssertion(func(a *etree.Element) {
			wide(a)
			child(a, "AuthnStatement").CreateAttr("SessionNotOnOrAfter", ts(time.Minute))
		}), time.Minute+skew-time.Second, time.Minute+skew, samlsp.ErrAssertionExpired)
	})

	t.Run("custom skew", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, func(c *samlsp.Config, _ *samlsp.Connection) { c.ClockSkew = 30 * time.Second })
		lr := begin(t, e, samlsp.LoginOptions{})
		e.clock.set(t0.Add(5*time.Minute + 30*time.Second))

		_, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
		requireRejected(t, e, lr, err, samlsp.ErrAssertionExpired)
	})
}

func TestCompleteLogin_Conditions(t *testing.T) {
	t.Parallel()

	reject(t, onAssertion(func(a *etree.Element) {
		child(a, "Conditions").CreateAttr("NotBefore", ts(5*time.Minute))
	}), samlsp.ErrInvalidAssertion) // NotBefore >= NotOnOrAfter (Core §2.5.1.2)

	reject(t, onAssertion(func(a *etree.Element) {
		cond := child(a, "Conditions").CreateElement("saml:Condition")
		cond.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
		cond.CreateAttr("xsi:type", "x:Custom")
	}), samlsp.ErrInvalidAssertion) // Indeterminate (Core §2.5.1.1)

	reject(t, onAssertion(func(a *etree.Element) {
		el := child(a, "Conditions").CreateElement("x:Custom")
		el.CreateAttr("xmlns:x", "urn:example:x")
	}), samlsp.ErrInvalidAssertion)

	reject(t, onAssertion(func(a *etree.Element) {
		c := child(a, "Conditions")
		c.CreateElement("saml:OneTimeUse")
		c.CreateElement("saml:OneTimeUse")
	}), samlsp.ErrInvalidAssertion)

	reject(t, onAssertion(func(a *etree.Element) {
		c := child(a, "Conditions")
		c.CreateElement("saml:ProxyRestriction")
		c.CreateElement("saml:ProxyRestriction")
	}), samlsp.ErrInvalidAssertion)

	reject(t, onAssertion(func(a *etree.Element) {
		c := a.CreateElement("saml:Conditions")
		c.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(spEntityID)
	}), samlsp.ErrInvalidAssertion) // two Conditions

	// Optional bounds may be absent (Core §2.5.1.2).
	_, err := flow(t, newEnv(t), onAssertion(func(a *etree.Element) {
		c := child(a, "Conditions")
		c.RemoveAttr("NotBefore")
		c.RemoveAttr("NotOnOrAfter")
	}))
	require.NoError(t, err)
}

func TestCompleteLogin_Audience(t *testing.T) {
	t.Parallel()

	refused := []struct {
		name string
		f    func(a *etree.Element)
	}{
		{"no Conditions", func(a *etree.Element) { a.RemoveChild(child(a, "Conditions")) }},
		{"no AudienceRestriction", func(a *etree.Element) {
			c := child(a, "Conditions")
			c.RemoveChild(child(c, "AudienceRestriction"))
		}},
		{"another SP", func(a *etree.Element) {
			path(a, "Conditions", "AudienceRestriction", "Audience").SetText("https://sp.example.com/saml/globex")
		}},
		{"second restriction without the SP (AND, errata E46)", func(a *etree.Element) {
			child(a, "Conditions").CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText("https://other.example")
		}},
		{"empty restriction", func(a *etree.Element) { child(a, "Conditions").CreateElement("saml:AudienceRestriction") }},
	}

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := samlsp.ErrAudienceMismatch
			if tc.name == "empty restriction" {
				want = samlsp.ErrInvalidAssertion
			}

			reject(t, onAssertion(tc.f), want)
		})
	}

	_, err := flow(t, newEnv(t), onAssertion(func(a *etree.Element) {
		ar := path(a, "Conditions", "AudienceRestriction")
		ar.InsertChildAt(0, etree.NewElement("saml:Audience"))
		ar.ChildElements()[0].SetText("https://another.example") // OR within a restriction
	}))
	require.NoError(t, err)
}

func TestCompleteLogin_UseConditions(t *testing.T) {
	t.Parallel()

	res, err := flow(t, newEnv(t), onAssertion(func(a *etree.Element) {
		c := child(a, "Conditions")
		c.CreateElement("saml:OneTimeUse")
		pr := c.CreateElement("saml:ProxyRestriction")
		pr.CreateAttr("Count", "0")
		pr.CreateElement("saml:Audience").SetText("https://downstream.example")
	}))
	require.NoError(t, err, "OneTimeUse and ProxyRestriction are conditions on use (Core §2.5.1.5/6)")
	require.NotNil(t, res.Identity.ProxyRestriction)
	require.NotNil(t, res.Identity.ProxyRestriction.Count)
	assert.Equal(t, 0, *res.Identity.ProxyRestriction.Count)
	assert.Equal(t, []string{"https://downstream.example"}, res.Identity.ProxyRestriction.Audiences)

	res, err = flow(t, newEnv(t), onAssertion(func(a *etree.Element) {
		child(a, "Conditions").CreateElement("saml:ProxyRestriction")
	}))
	require.NoError(t, err)
	require.NotNil(t, res.Identity.ProxyRestriction)
	assert.Nil(t, res.Identity.ProxyRestriction.Count, "an absent Count is not zero (review F4)")
	assert.Empty(t, res.Identity.ProxyRestriction.Audiences)

	reject(t, onAssertion(func(a *etree.Element) {
		child(a, "Conditions").CreateElement("saml:ProxyRestriction").CreateAttr("Count", "-1")
	}), samlsp.ErrInvalidAssertion)
}

func TestCompleteLogin_IssueInstant(t *testing.T) {
	t.Parallel()

	skew := samlsp.DefaultClockSkew

	reject(t, onAssertion(func(a *etree.Element) { a.CreateAttr("IssueInstant", ts(skew+time.Second)) }), samlsp.ErrAssertionNotYetValid)
	reject(t, onResponse(func(r *etree.Element) { r.CreateAttr("IssueInstant", ts(skew+time.Second)) }), samlsp.ErrAssertionNotYetValid)
	reject(t, onAssertion(func(a *etree.Element) { a.CreateAttr("IssueInstant", ts(-skew-time.Second)) }), samlsp.ErrInvalidAssertion)
	reject(t, onResponse(func(r *etree.Element) { r.CreateAttr("IssueInstant", ts(-skew-time.Second)) }), samlsp.ErrInvalidAssertion)
	reject(t, onResponse(func(r *etree.Element) { r.RemoveAttr("IssueInstant") }), samlsp.ErrMalformedResponse)

	_, err := flow(t, newEnv(t), onAssertion(func(a *etree.Element) { a.CreateAttr("IssueInstant", ts(-skew)) }))
	require.NoError(t, err, "issued up to the skew before the request")
}

func TestCompleteLogin_AuthnStatement(t *testing.T) {
	t.Parallel()

	stmt := func(a *etree.Element) *etree.Element { return child(a, "AuthnStatement") }

	reject(t, onAssertion(func(a *etree.Element) { a.RemoveChild(stmt(a)) }), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) { a.AddChild(stmt(a).Copy()) }), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) { stmt(a).RemoveAttr("AuthnInstant") }), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) { stmt(a).RemoveChild(child(stmt(a), "AuthnContext")) }), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		ac := child(stmt(a), "AuthnContext")
		ac.AddChild(child(ac, "AuthnContextClassRef").Copy())
	}), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		stmt(a).CreateAttr("AuthnInstant", ts(samlsp.DefaultClockSkew+time.Second))
	}), samlsp.ErrAssertionNotYetValid)

	// No class reference: the context is empty, not an error.
	res, err := flow(t, newEnv(t), onAssertion(func(a *etree.Element) {
		ac := child(stmt(a), "AuthnContext")
		ac.RemoveChild(child(ac, "AuthnContextClassRef"))
		ac.CreateElement("saml:AuthnContextDeclRef").SetText("urn:example:decl")
	}))
	require.NoError(t, err)
	assert.Empty(t, res.Identity.AuthnContextClassRef)
	assert.True(t, res.Identity.SessionNotOnOrAfter.Equal(t0.Add(8*time.Hour)))

	res, err = flow(t, newEnv(t), onAssertion(func(a *etree.Element) {
		stmt(a).RemoveAttr("SessionNotOnOrAfter")
		stmt(a).RemoveAttr("SessionIndex")
	}))
	require.NoError(t, err)
	assert.True(t, res.Identity.SessionNotOnOrAfter.IsZero())
	assert.Empty(t, res.Identity.SessionIndex)
}

func TestCompleteLogin_NameID(t *testing.T) {
	t.Parallel()

	nid := func(a *etree.Element) *etree.Element { return path(a, "Subject", "NameID") }

	reject(t, onAssertion(func(a *etree.Element) { nid(a).SetText("") }), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) { path(a, "Subject").RemoveChild(nid(a)) }), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		s := path(a, "Subject")
		s.InsertChildAt(0, nid(a).Copy())
	}), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		s := path(a, "Subject")
		s.RemoveChild(nid(a))
		s.InsertChildAt(0, etree.NewElement("saml:BaseID"))
	}), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		a.InsertChildAt(2, child(a, "Subject").Copy())
	}), samlsp.ErrInvalidAssertion)
	reject(t, onAssertion(func(a *etree.Element) {
		av := path(a, "AttributeStatement").ChildElements()[2].ChildElements()[0]
		av.AddChild(child(av, "NameID").Copy())
	}), samlsp.ErrInvalidAssertion) // two NameIDs in one AttributeValue (review F6)

	// Whitespace is preserved, never trimmed.
	res, err := flow(t, newEnv(t), onAssertion(func(a *etree.Element) { nid(a).SetText(" alice ") }))
	require.NoError(t, err)
	assert.Equal(t, " alice ", res.Identity.NameID.Value)
}

func TestCompleteLogin_NameIDFormatPolicy(t *testing.T) {
	t.Parallel()

	persistent := func(_ *samlsp.Config, c *samlsp.Connection) { c.NameIDFormat = samlsp.NameIDFormatPersistent }
	unspecified := func(_ *samlsp.Config, c *samlsp.Connection) { c.NameIDFormat = samlsp.NameIDFormatUnspecified }
	email := onAssertion(func(a *etree.Element) {
		path(a, "Subject", "NameID").CreateAttr("Format", samlsp.NameIDFormatEmailAddress)
	})

	reject(t, email, samlsp.ErrNameIDFormatMismatch, persistent)

	_, err := flow(t, newEnv(t, persistent), respOpts{})
	require.NoError(t, err)

	_, err = flow(t, newEnv(t, unspecified), email)
	require.NoError(t, err, "unspecified lets the IdP choose")

	_, err = flow(t, newEnv(t), email)
	require.NoError(t, err, "no requested format")
}

func TestCompleteLogin_ForceAuthn(t *testing.T) {
	t.Parallel()

	stale := func(d time.Duration) respOpts {
		return onAssertion(func(a *etree.Element) { child(a, "AuthnStatement").CreateAttr("AuthnInstant", ts(d)) })
	}

	run := func(o respOpts) error {
		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{ForceAuthn: true})
		_, err := complete(e, lr, respond(t, lr.requestID, o))

		return err
	}

	require.ErrorIs(t, run(stale(-samlsp.DefaultClockSkew-time.Second)), samlsp.ErrStaleAuthentication)
	require.NoError(t, run(stale(-samlsp.DefaultClockSkew)), "within the skew")

	// Without ForceAuthn an old authentication is fine.
	_, err := flow(t, newEnv(t), stale(-24*time.Hour))
	require.NoError(t, err)
}

func TestCompleteLogin_RequestedAuthnContext(t *testing.T) {
	t.Parallel()

	run := func(requested []string, o respOpts) error {
		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{RequestedAuthnContext: requested})
		_, err := complete(e, lr, respond(t, lr.requestID, o))

		return err
	}

	const x509Class = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"

	require.ErrorIs(t, run([]string{x509Class}, respOpts{}), samlsp.ErrAuthnContextMismatch)
	require.NoError(t, run([]string{x509Class, pptClass}, respOpts{}))
	require.ErrorIs(t, run([]string{pptClass}, onAssertion(func(a *etree.Element) {
		ac := path(a, "AuthnStatement", "AuthnContext")
		ac.RemoveChild(child(ac, "AuthnContextClassRef"))
		ac.CreateElement("saml:AuthnContextDeclRef").SetText("urn:example:decl")
	})), samlsp.ErrAuthnContextMismatch)
}

func TestCompleteLogin_Encoding(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	xml := respondXML(t, lr.requestID, respOpts{})

	var deflated bytes.Buffer
	fw, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = fw.Write([]byte(xml))
	require.NoError(t, err)
	require.NoError(t, fw.Close())

	for name, value := range map[string]string{
		"not base64":            "!!!" + encodeString(xml),
		"DEFLATE on the POST":   base64.StdEncoding.EncodeToString(deflated.Bytes()),
		"not XML":               encodeString("hello"),
		"spaces inside base64":  strings.Replace(encodeString(xml), "A", " A", 3),
		"XML declaration later": encodeString(" <?xml version=\"1.0\"?>" + xml),
	} {
		_, err := complete(e, lr, value)
		require.ErrorIs(t, err, samlsp.ErrMalformedResponse, name)
	}

	// Line-wrapped base64 (Bindings §3.5.4) and a UTF-8 BOM are accepted.
	b64 := encodeString("\xEF\xBB\xBF" + xml)

	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 76 {
		wrapped.WriteString(b64[i:min(i+76, len(b64))])
		wrapped.WriteString("\r\n")
	}

	_, err = complete(e, lr, wrapped.String())
	require.NoError(t, err)
}

func TestCompleteLogin_XMLHygiene(t *testing.T) {
	t.Parallel()

	reject(t, respOpts{raw: func(s string) string { return `<!DOCTYPE samlp:Response>` + s }}, samlsp.ErrMalformedResponse)
	reject(t, respOpts{raw: func(s string) string {
		return `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` + s
	}}, samlsp.ErrMalformedResponse)
	reject(t, respOpts{raw: func(s string) string { return s + `<?php ?>` }}, samlsp.ErrMalformedResponse)
	reject(t, respOpts{raw: func(s string) string {
		return strings.Replace(s, `InResponseTo=`, `InResponseTo="_evil" InResponseTo=`, 1)
	}}, samlsp.ErrMalformedResponse) // duplicate attribute (review F6)
	reject(t, respOpts{raw: func(s string) string {
		return strings.Replace(s, `<samlp:Response `, `<samlp:Response xmlns:foo="urn:foo" foo:ID="_x" `, 1)
	}}, samlsp.ErrMalformedResponse) // prefixed ID (review F6)
	reject(t, respOpts{raw: func(s string) string {
		return strings.Replace(s, `<samlp:Status>`, `<x:Status>`, 1)
	}}, samlsp.ErrMalformedResponse) // undeclared prefix
	reject(t, onAssertion(func(a *etree.Element) {
		a.CreateAttr("IssueInstant", "2026-10-12T12:00:00+02:00")
	}), samlsp.ErrMalformedResponse) // not UTC "Z" (Core §1.3.3)
	reject(t, onAssertion(func(a *etree.Element) {
		attr := path(a, "AttributeStatement", "Attribute")
		for i := 0; i < samlsp.MaxResponseElements; i++ {
			attr.CreateElement("saml:AttributeValue").SetText("g")
		}
	}), samlsp.ErrResponseTooLarge)
}

func TestCompleteLogin_Root(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})

	assertionOnly := etree.NewDocument()
	assertionOnly.SetRoot(sign(t, buildAssertion(respParams{requestID: lr.requestID, issued: t0}), sigOpts{}))
	s, err := assertionOnly.WriteToString()
	require.NoError(t, err)

	for name, doc := range map[string]string{
		"bare assertion":  s,
		"logout response": strings.ReplaceAll(respondXML(t, lr.requestID, respOpts{}), "samlp:Response", "samlp:LogoutResponse"),
		"wrong namespace": strings.Replace(respondXML(t, lr.requestID, respOpts{}), `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`, `xmlns:samlp="urn:example:protocol"`, 1),
	} {
		_, err := complete(e, lr, encodeString(doc))
		requireRejected(t, e, lr, err, samlsp.ErrMalformedResponse)
		_ = name
	}
}

func TestCompleteLogin_EncryptedContentRefused(t *testing.T) {
	t.Parallel()

	encrypted := func(local string) func(a *etree.Element) {
		return func(a *etree.Element) {
			el := a.CreateElement("saml:" + local)
			el.CreateElement("xenc:EncryptedData").CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
		}
	}

	reject(t, respOpts{after: func(r *etree.Element) {
		ea := r.CreateElement("saml:EncryptedAssertion")
		ed := ea.CreateElement("xenc:EncryptedData")
		ed.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	}}, samlsp.ErrEncryptedAssertionUnsupported)
	reject(t, onAssertion(func(a *etree.Element) { encrypted("EncryptedID")(path(a, "Subject")) }), samlsp.ErrEncryptedAssertionUnsupported)
	reject(t, onAssertion(func(a *etree.Element) { encrypted("EncryptedAttribute")(path(a, "AttributeStatement")) }), samlsp.ErrEncryptedAssertionUnsupported)
	reject(t, respOpts{after: func(r *etree.Element) {
		ek := r.CreateElement("x:EncryptedKey")
		ek.CreateAttr("xmlns:x", "http://www.w3.org/2001/04/xmlenc#")
	}}, samlsp.ErrEncryptedAssertionUnsupported)
}

func TestCompleteLogin_ProfileRefusedBeforeSignatureWork(t *testing.T) {
	t.Parallel()

	// Signed with an untrusted key: had the pre-check let them through, the
	// signature verification would answer ErrInvalidSignature instead.
	untrusted := func(o respOpts) respOpts {
		o.assertionSig = sigOpts{signer: keys(t).attacker}

		return o
	}

	cases := []struct {
		name string
		o    respOpts
		want error
	}{
		{"Response version", onResponse(func(r *etree.Element) { r.CreateAttr("Version", "1.1") }), samlsp.ErrMalformedResponse},
		{"holder-of-key confirmation", onAssertion(func(a *etree.Element) {
			path(a, "Subject", "SubjectConfirmation").CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key")
		}), samlsp.ErrInvalidAssertion},
		{"AuthnInstant missing", onAssertion(func(a *etree.Element) { child(a, "AuthnStatement").RemoveAttr("AuthnInstant") }), samlsp.ErrInvalidAssertion},
		{"BaseID next to the NameID", onAssertion(func(a *etree.Element) { path(a, "Subject").CreateElement("saml:BaseID") }), samlsp.ErrInvalidAssertion},
		{"unknown condition", onAssertion(func(a *etree.Element) { child(a, "Conditions").CreateElement("saml:Condition") }), samlsp.ErrInvalidAssertion},
		{"time zone offset", onAssertion(func(a *etree.Element) { a.CreateAttr("IssueInstant", "2026-10-12T12:00:00+02:00") }), samlsp.ErrMalformedResponse},
		{"AuthnInstant with an offset", onAssertion(func(a *etree.Element) {
			child(a, "AuthnStatement").CreateAttr("AuthnInstant", "2026-10-12T12:00:00+02:00")
		}), samlsp.ErrMalformedResponse},
		{"SessionNotOnOrAfter without a zone", onAssertion(func(a *etree.Element) {
			child(a, "AuthnStatement").CreateAttr("SessionNotOnOrAfter", "2026-10-12T18:00:00")
		}), samlsp.ErrMalformedResponse},
		{"encrypted identifier", onAssertion(func(a *etree.Element) {
			el := path(a, "Subject").CreateElement("saml:EncryptedID")
			el.CreateElement("xenc:EncryptedData").CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
		}), samlsp.ErrEncryptedAssertionUnsupported},
		{"issuer format", onAssertion(func(a *etree.Element) {
			child(a, "Issuer").CreateAttr("Format", samlsp.NameIDFormatEmailAddress)
		}), samlsp.ErrIssuerMismatch},
		{"duplicate ID", onResponse(func(r *etree.Element) { child(r, "Status").CreateAttr("ID", assertionID) }), samlsp.ErrMalformedResponse},
		{"two NameIDs in an AttributeValue", onAssertion(func(a *etree.Element) {
			av := path(a, "AttributeStatement").ChildElements()[2].ChildElements()[0]
			av.AddChild(child(av, "NameID").Copy())
		}), samlsp.ErrInvalidAssertion},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reject(t, untrusted(tc.o), tc.want)
		})
	}
}

func TestCompleteLogin_ProfileShape(t *testing.T) {
	t.Parallel()

	// Status must be present and single.
	reject(t, onResponse(func(r *etree.Element) { r.RemoveChild(child(r, "Status")) }), samlsp.ErrMalformedResponse)
	reject(t, onResponse(func(r *etree.Element) {
		st := child(r, "Status")
		st.AddChild(child(st, "StatusCode").Copy())
	}), samlsp.ErrMalformedResponse)
	reject(t, onResponse(func(r *etree.Element) {
		path(r, "Status", "StatusCode").RemoveAttr("Value")
	}), samlsp.ErrMalformedResponse)
	// No assertion at all with a Success status.
	reject(t, onResponse(func(r *etree.Element) { r.RemoveChild(child(r, "Assertion")) }), samlsp.ErrMalformedResponse)
	reject(t, onResponse(func(r *etree.Element) {
		st := child(r, "Status")
		st.CreateElement("samlp:StatusMessage").SetText("a")
		st.CreateElement("samlp:StatusMessage").SetText("b")
	}), samlsp.ErrMalformedResponse)
	reject(t, onAssertion(func(a *etree.Element) {
		child(a, "Conditions").CreateElement("saml:ProxyRestriction").CreateElement("saml:Other")
	}), samlsp.ErrInvalidAssertion)
	// Assertion without ID.
	reject(t, onAssertion(func(a *etree.Element) { a.RemoveAttr("ID") }), samlsp.ErrMalformedResponse)
	// Response without ID.
	reject(t, onResponse(func(r *etree.Element) { r.RemoveAttr("ID") }), samlsp.ErrMalformedResponse)
}
