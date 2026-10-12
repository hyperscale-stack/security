// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"testing"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyInfoContent replaces the content of the KeyInfo of the signature of
// the element at sigPath (after signing: KeyInfo is outside every digest
// it could matter to — see TestCompleteLogin_CertificatelessKeyInfo).
func keyInfoContent(sigOf func(r *etree.Element) *etree.Element, content func(ki *etree.Element)) func(r *etree.Element) {
	return func(r *etree.Element) {
		ki := path(sigOf(r), "KeyInfo")
		for _, c := range ki.ChildElements() {
			ki.RemoveChild(c)
		}

		content(ki)
	}
}

func responseSignature(r *etree.Element) *etree.Element { return child(r, "Signature") }

func keyName(ki *etree.Element) { ki.CreateElement("ds:KeyName").SetText("idp-signing-2026") }

// TestCompleteLogin_CertificatelessKeyInfo: Core §5.4.5 — "SAML does not
// require the use of <ds:KeyInfo>, nor does it impose any restrictions on
// its use". goxmldsig refuses a KeyInfo without X509Certificate even when
// the connection trusts a single certificate, so such a KeyInfo is cut
// from the verified bytes and the signature treated as KeyInfo-less, where
// that is neutral: always for the Response signature (its KeyInfo is in no
// digest), for the Assertion signature only when the Response is unsigned
// (a signed Response digests the Assertion's Signature element). Audit
// SAML-I5.
func TestCompleteLogin_CertificatelessKeyInfo(t *testing.T) {
	t.Parallel()

	k := keys(t)

	accepted := []struct {
		name string
		o    respOpts
		opts []envOption
	}{
		{"KeyName only, one trusted key", respOpts{after: keyInfoContent(assertionSignature, keyName)}, nil},
		{"KeyValue only, one trusted key", respOpts{after: keyInfoContent(assertionSignature, func(ki *etree.Element) {
			rsa := ki.CreateElement("ds:KeyValue").CreateElement("ds:RSAKeyValue")
			rsa.CreateElement("ds:Modulus").SetText("AQAB")
			rsa.CreateElement("ds:Exponent").SetText("AQAB")
		})}, nil},
		{"KeyName only, two trusted keys (rollover)", respOpts{
			assertionSig: sigOpts{signer: k.idpB},
			after:        keyInfoContent(assertionSignature, keyName),
		}, []envOption{trustKeys(k.idpA, k.idpB)}},
		{"KeyName only on a signed Response", respOpts{
			unsignedAssert: true, signResponse: true,
			after: keyInfoContent(responseSignature, keyName),
		}, nil},
		{"KeyName only on the Response signature, both signed", respOpts{
			signResponse: true,
			after:        keyInfoContent(responseSignature, keyName),
		}, nil},
		{"empty KeyInfo", respOpts{after: keyInfoContent(assertionSignature, func(*etree.Element) {})}, nil},
	}

	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := flow(t, newEnv(t, tc.opts...), tc.o)
			require.NoError(t, err)
			assert.Equal(t, nameIDValue, res.Identity.NameID.Value)
		})
	}

	t.Run("an error status of a signed Response is still a status", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})

		_, err := complete(e, lr, respond(t, lr.requestID, respOpts{signResponse: true, unsignedAssert: true,
			before: func(r, a *etree.Element) {
				r.RemoveChild(a)
				path(r, "Status", "StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Requester")
			},
		}))

		var se *samlsp.StatusError
		require.ErrorAs(t, err, &se)
		assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Requester", se.Code)
	})

	t.Run("a cut KeyInfo extends no trust", func(t *testing.T) {
		t.Parallel()

		reject(t, respOpts{
			assertionSig: sigOpts{signer: k.attacker},
			after:        keyInfoContent(assertionSignature, keyName),
		}, samlsp.ErrInvalidSignature)
	})

	t.Run("an Assertion KeyInfo covered by a signed Response is not cut", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})

		_, err := complete(e, lr, respond(t, lr.requestID, respOpts{
			signResponse: true,
			before: func(_, a *etree.Element) {
				ki := path(child(a, "Signature"), "KeyInfo")
				for _, c := range ki.ChildElements() {
					ki.RemoveChild(c)
				}

				keyName(ki)
			},
		}))
		requireRejected(t, e, lr, err, samlsp.ErrInvalidSignature)
		assert.Equal(t, samlsp.ErrInvalidSignature.Error()+
			" (a KeyInfo without certificate in an assertion covered by a signed Response)", err.Error())
	})
}
