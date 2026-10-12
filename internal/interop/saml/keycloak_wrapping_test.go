// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/require"
)

const (
	evilNameID   = "mallory@attacker.example"
	oneAssertion = "a response must carry exactly one assertion, child of the Response"
	duplicateID  = "duplicate identifier"
	verifyFailed = "signature verification failed"
	notSigned    = "neither the Response nor the Assertion is signed"
)

// kcChild returns the first child element of e with the local name tag,
// whatever its prefix (Keycloak writes samlp:, saml: and dsig:).
func kcChild(t *testing.T, e *etree.Element, tag string) *etree.Element {
	t.Helper()

	for _, c := range e.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}

	require.Failf(t, "missing element", "%s has no %s child", e.Tag, tag)

	return nil
}

// kcUnsigned returns a copy of e without its Signature child.
func kcUnsigned(t *testing.T, e *etree.Element) *etree.Element {
	t.Helper()

	c := e.Copy()
	c.RemoveChild(kcChild(t, c, "Signature"))

	return c
}

// kcNameID returns the NameID of an assertion.
func kcNameID(t *testing.T, assertion *etree.Element) *etree.Element {
	t.Helper()

	return kcChild(t, kcChild(t, assertion, "Subject"), "NameID")
}

// kcForge marks e as the attacker's: a new ID unless id is empty, and the
// attacker's NameID when e is an assertion.
func kcForge(t *testing.T, e *etree.Element, id string) *etree.Element {
	t.Helper()

	if id != "" {
		e.CreateAttr("ID", id)
	}

	kcNameID(t, e).SetText(evilNameID)

	return e
}

// wrappingAttack transforms a parsed Keycloak Response in place.
type wrappingAttack struct {
	name      string
	bases     []string // pinned cases it applies to
	transform func(t *testing.T, r *etree.Element)
	sentinel  error  // nil: accepted
	detail    string // static detail of the refusal
}

// wrappingAttacks is SAML Raider's XSW1-XSW8 catalogue (as in the corpus),
// signature exclusion and comment injection.
func wrappingAttacks() []wrappingAttack {
	responseSigned := []string{"response-signed", "both-signed"}
	assertionSigned := []string{"assertion-signed", "both-signed"}
	assertionOf := func(t *testing.T, r *etree.Element) *etree.Element { return kcChild(t, r, "Assertion") }

	return []wrappingAttack{
		{
			name: "xsw1", bases: responseSigned, sentinel: samlsp.ErrMalformedResponse, detail: duplicateID,
			transform: func(t *testing.T, r *etree.Element) {
				kcChild(t, r, "Signature").AddChild(kcUnsigned(t, r))
				r.CreateAttr("ID", "_evil_response_ID")
				kcForge(t, assertionOf(t, r), "")
			},
		},
		{
			name: "xsw2", bases: responseSigned, sentinel: samlsp.ErrMalformedResponse, detail: duplicateID,
			transform: func(t *testing.T, r *etree.Element) {
				r.InsertChildAt(kcChild(t, r, "Signature").Index(), kcUnsigned(t, r))
				r.CreateAttr("ID", "_evil_response_ID")
				kcForge(t, assertionOf(t, r), "")
			},
		},
		{
			name: "xsw3", bases: assertionSigned, sentinel: samlsp.ErrMalformedResponse, detail: oneAssertion,
			transform: func(t *testing.T, r *etree.Element) {
				a := assertionOf(t, r)
				r.InsertChildAt(a.Index(), kcForge(t, a.Copy(), "_evil_assertion_ID"))
			},
		},
		{
			name: "xsw4", bases: assertionSigned, sentinel: samlsp.ErrMalformedResponse, detail: oneAssertion,
			transform: func(t *testing.T, r *etree.Element) {
				a := assertionOf(t, r)
				e := kcForge(t, a.Copy(), "_evil_assertion_ID")
				r.RemoveChild(a)
				e.AddChild(a)
				r.AddChild(e)
			},
		},
		{
			name: "xsw5", bases: assertionSigned, sentinel: samlsp.ErrMalformedResponse, detail: oneAssertion,
			transform: func(t *testing.T, r *etree.Element) {
				a := assertionOf(t, r)
				r.AddChild(kcUnsigned(t, a))
				kcForge(t, a, "_evil_assertion_ID")
			},
		},
		{
			name: "xsw6", bases: assertionSigned, sentinel: samlsp.ErrMalformedResponse, detail: oneAssertion,
			transform: func(t *testing.T, r *etree.Element) {
				a := assertionOf(t, r)
				kcChild(t, a, "Signature").AddChild(kcUnsigned(t, a))
				kcForge(t, a, "_evil_assertion_ID")
			},
		},
		{
			name: "xsw7", bases: assertionSigned, sentinel: samlsp.ErrMalformedResponse, detail: duplicateID,
			transform: func(t *testing.T, r *etree.Element) {
				a := assertionOf(t, r)
				ext := etree.NewElement("samlp:Extensions")
				r.InsertChildAt(a.Index(), ext)
				ext.AddChild(kcForge(t, a.Copy(), ""))
			},
		},
		{
			name: "xsw8", bases: assertionSigned, sentinel: samlsp.ErrMalformedResponse, detail: duplicateID,
			transform: func(t *testing.T, r *etree.Element) {
				a := assertionOf(t, r)
				orig := kcUnsigned(t, a)
				kcForge(t, a, "")
				kcChild(t, a, "Signature").CreateElement("dsig:Object").AddChild(orig)
			},
		},
		{
			// Profiles §4.1.3.5: the assertion signature alone suffices.
			name: "response-signature-removed", bases: []string{"both-signed"},
			transform: func(t *testing.T, r *etree.Element) { r.RemoveChild(kcChild(t, r, "Signature")) },
		},
		{
			// The Response signature covers the assertion with its signature.
			name: "assertion-signature-removed", bases: []string{"both-signed"},
			sentinel: samlsp.ErrInvalidSignature, detail: verifyFailed,
			transform: func(t *testing.T, r *etree.Element) {
				a := assertionOf(t, r)
				a.RemoveChild(kcChild(t, a, "Signature"))
			},
		},
		{
			name: "every-signature-removed", bases: []string{"response-signed", "assertion-signed", "both-signed"},
			sentinel: samlsp.ErrInvalidSignature, detail: notSigned,
			transform: func(t *testing.T, r *etree.Element) {
				for _, e := range []*etree.Element{r, assertionOf(t, r)} {
					if sig := e.SelectElement("Signature"); sig != nil {
						e.RemoveChild(sig)
					}
				}
			},
		},
		{
			name: "nameid-changed-after-signing", bases: []string{"response-signed", "assertion-signed", "both-signed"},
			sentinel: samlsp.ErrInvalidSignature, detail: verifyFailed,
			transform: func(t *testing.T, r *etree.Element) { kcForge(t, assertionOf(t, r), "") },
		},
		{
			// CVE-2017-11427 class: exclusive C14N drops the comment, the
			// signature still verifies, and the full value must be used.
			name: "comment-in-nameid", bases: []string{"response-signed", "assertion-signed", "both-signed"},
			transform: func(t *testing.T, r *etree.Element) {
				n := kcNameID(t, assertionOf(t, r))
				v := n.Text()
				n.SetText(v[:len(v)/2])
				n.CreateComment("")
				n.CreateText(v[len(v)/2:])
			},
		},
	}
}

// TestKeycloakWrapping applies the wrapping catalogue, signature exclusion,
// tampering and comment injection to real Apache Santuario output: the
// pinned Keycloak responses signed on the Response, on the Assertion and
// on both. No attack yields an identity other than the signed one.
func TestKeycloakWrapping(t *testing.T) {
	t.Parallel()

	cases := make(map[string]keycloakCase)
	for _, c := range loadKeycloakCases(t) {
		cases[c.Name] = c
	}

	for _, a := range wrappingAttacks() {
		for _, base := range a.bases {
			t.Run(a.name+"/"+base, func(t *testing.T) {
				t.Parallel()

				c, ok := cases[base]
				require.True(t, ok, "no pinned %s case", base)

				raw, err := base64.StdEncoding.DecodeString(c.Response)
				require.NoError(t, err)

				doc := etree.NewDocument()
				require.NoError(t, doc.ReadFromBytes(raw))

				signed := kcNameID(t, kcChild(t, doc.Root(), "Assertion")).Text()

				a.transform(t, doc.Root())

				out, err := doc.WriteToBytes()
				require.NoError(t, err)

				res, err := replayKeycloak(t, c, false, base64.StdEncoding.EncodeToString(out))

				if a.sentinel == nil {
					require.NoError(t, err)
					require.Equal(t, signed, res.Identity.NameID.Value, "the full signed value")

					return
				}

				require.ErrorIs(t, err, a.sentinel)
				require.True(t, strings.HasSuffix(err.Error(), "("+a.detail+")"), err.Error())
				require.NotContains(t, err.Error(), "mallory")
				require.Nil(t, res)
			})
		}
	}
}
