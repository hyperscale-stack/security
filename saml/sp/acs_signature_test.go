// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"crypto"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowSHA1 opts the connection into SHA-1.
func allowSHA1(_ *samlsp.Config, c *samlsp.Connection) { c.InsecureAllowSHA1 = true }

// assertionSignature returns the ds:Signature of the assertion in resp.
func assertionSignature(resp *etree.Element) *etree.Element {
	return path(resp, "Assertion", "Signature")
}

func TestCompleteLogin_SignatureFailures(t *testing.T) {
	t.Parallel()

	k := keys(t)

	cases := []struct {
		name string
		o    respOpts
	}{
		{"no signature at all", respOpts{unsignedAssert: true}},
		{"untrusted signer", respOpts{assertionSig: sigOpts{signer: k.attacker}}},
		{"key of another IdP", respOpts{assertionSig: sigOpts{signer: k.idpB}}},
		{"untrusted response signer, unsigned assertion", respOpts{unsignedAssert: true, signResponse: true, responseSig: sigOpts{signer: k.attacker}}},
		{"NameID tampered after signing", respOpts{after: func(r *etree.Element) {
			path(r, "Assertion", "Subject", "NameID").SetText("admin")
		}}},
		{"attribute tampered after signing", respOpts{after: func(r *etree.Element) {
			path(r, "Assertion", "AttributeStatement", "Attribute", "AttributeValue").SetText("root@example.com")
		}}},
		{"conditions tampered after signing", respOpts{after: func(r *etree.Element) {
			path(r, "Assertion", "Conditions").CreateAttr("NotOnOrAfter", "2099-01-01T00:00:00Z")
		}}},
		{"signed response tampered", respOpts{unsignedAssert: true, signResponse: true, after: func(r *etree.Element) {
			path(r, "Assertion", "Subject", "NameID").SetText("admin")
		}}},
		{"signed response, assertion signed by an untrusted key", respOpts{signResponse: true, assertionSig: sigOpts{signer: k.attacker}}},
		{"signature value corrupted", respOpts{after: func(r *etree.Element) {
			sv := path(assertionSignature(r), "SignatureValue")
			sv.SetText(base64.StdEncoding.EncodeToString(make([]byte, 256)))
		}}},
		{"KeyInfo carries an untrusted certificate", respOpts{after: func(r *etree.Element) {
			path(assertionSignature(r), "KeyInfo", "X509Data", "X509Certificate").SetText(certB64(k.attacker.cert))
		}}},
		{"KeyInfo without certificate (KeyName only)", respOpts{after: func(r *etree.Element) {
			ki := path(assertionSignature(r), "KeyInfo")
			for _, c := range ki.ChildElements() {
				ki.RemoveChild(c)
			}

			ki.CreateElement("ds:KeyName").SetText("idp-key-1")
		}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reject(t, tc.o, samlsp.ErrInvalidSignature)
		})
	}
}

func TestCompleteLogin_AlgorithmPolicy(t *testing.T) {
	t.Parallel()

	k := keys(t)
	setAlg := func(tag, alg string) func(*etree.Element) {
		return func(r *etree.Element) {
			path(assertionSignature(r), "SignedInfo").FindElement(".//"+tag).CreateAttr("Algorithm", alg)
		}
	}

	refused := []struct {
		name string
		o    respOpts
		opts []envOption
	}{
		{"valid rsa-sha1 signature", respOpts{assertionSig: sigOpts{method: dsig.RSASHA1SignatureMethod}}, nil},
		{"valid ecdsa-sha1 signature", respOpts{assertionSig: sigOpts{signer: k.idpEC, method: dsig.ECDSASHA1SignatureMethod}}, []envOption{trustKeys(k.idpEC)}},
		{"inclusive C14N 1.0, even with the SHA-1 opt-in", respOpts{assertionSig: sigOpts{canon: dsig.MakeC14N10RecCanonicalizer()}}, []envOption{allowSHA1}},
		{"inclusive C14N 1.1", respOpts{assertionSig: sigOpts{canon: dsig.MakeC14N11Canonicalizer()}}, nil},
		{"SHA-1 response signature next to a SHA-256 assertion signature", respOpts{signResponse: true, responseSig: sigOpts{method: dsig.RSASHA1SignatureMethod}}, nil},
		{"sha1 digest", respOpts{after: setAlg("DigestMethod", "http://www.w3.org/2000/09/xmldsig#sha1")}, nil},
		{"md5 digest", respOpts{after: setAlg("DigestMethod", "http://www.w3.org/2001/04/xmldsig-more#md5")}, nil},
		{"hmac-sha256", respOpts{after: setAlg("SignatureMethod", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256")}, nil},
		{"dsa-sha1", respOpts{after: setAlg("SignatureMethod", "http://www.w3.org/2000/09/xmldsig#dsa-sha1")}, []envOption{allowSHA1}},
		{"unknown signature method", respOpts{after: setAlg("SignatureMethod", "urn:example:none")}, nil},
		{"unknown canonicalization", respOpts{after: setAlg("CanonicalizationMethod", "urn:example:c14n")}, nil},
	}

	refused = append(refused, struct {
		name string
		o    respOpts
		opts []envOption
	}{"inclusive C14N as the reference transform", respOpts{after: func(r *etree.Element) {
		path(assertionSignature(r), "SignedInfo", "Reference", "Transforms").ChildElements()[1].
			CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
	}}, nil})

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reject(t, tc.o, samlsp.ErrUnsupportedAlgorithm, tc.opts...)
		})
	}

	accepted := []struct {
		name string
		o    respOpts
		opts []envOption
	}{
		{"rsa-sha1 with the per-connection opt-in", respOpts{assertionSig: sigOpts{method: dsig.RSASHA1SignatureMethod}}, []envOption{allowSHA1}},
		{"ecdsa-sha1 with the opt-in", respOpts{assertionSig: sigOpts{signer: k.idpEC, method: dsig.ECDSASHA1SignatureMethod}}, []envOption{trustKeys(k.idpEC), allowSHA1}},
		{"rsa-sha384", respOpts{assertionSig: sigOpts{method: dsig.RSASHA384SignatureMethod}}, nil},
		{"ecdsa-sha512", respOpts{assertionSig: sigOpts{signer: k.idpEC, method: dsig.ECDSASHA512SignatureMethod}}, []envOption{trustKeys(k.idpEC)}},
	}

	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := flow(t, newEnv(t, tc.opts...), tc.o)
			require.NoError(t, err)
		})
	}
}

// resigned signs the assertion, lets edit change its SignedInfo, then
// re-signs SignedInfo with hash: a valid signature of a shape goxmldsig's
// signer cannot produce.
func resigned(t testing.TB, edit func(sig *etree.Element), hash crypto.Hash, signHash ...crypto.Hash) respOpts {
	return respOpts{
		assertionSig: sigOpts{method: methodFor(signHash)},
		before: func(_, a *etree.Element) {
			sig := child(a, "Signature")
			edit(sig)
			resign(t, sig, keys(t).idpA, hash)
		},
	}
}

func methodFor(h []crypto.Hash) string {
	if len(h) == 1 && h[0] == crypto.SHA1 {
		return dsig.RSASHA1SignatureMethod
	}

	return ""
}

func TestCompleteLogin_ResignedShapes(t *testing.T) {
	t.Parallel()

	setMethod := func(alg string) func(*etree.Element) {
		return func(sig *etree.Element) { path(sig, "SignedInfo", "SignatureMethod").CreateAttr("Algorithm", alg) }
	}

	// rsa-sha1 signature over a SHA-256 digest, and the reverse.
	sha1Method := resigned(t, setMethod(dsig.RSASHA1SignatureMethod), crypto.SHA1)
	sha1Digest := resigned(t, setMethod(dsig.RSASHA256SignatureMethod), crypto.SHA256, crypto.SHA1)

	reject(t, sha1Method, samlsp.ErrUnsupportedAlgorithm)
	reject(t, sha1Digest, samlsp.ErrUnsupportedAlgorithm)

	for _, o := range []respOpts{sha1Method, sha1Digest} {
		_, err := flow(t, newEnv(t, allowSHA1), o)
		require.NoError(t, err, "accepted with the opt-in: the resigned fixtures are valid")
	}

	// Three transforms that goxmldsig would process.
	reject(t, resigned(t, func(sig *etree.Element) {
		tr := path(sig, "SignedInfo", "Reference", "Transforms")
		tr.AddChild(tr.ChildElements()[1].Copy())
	}, crypto.SHA256), samlsp.ErrInvalidSignature)

	// A SignatureMethod child that goxmldsig would ignore.
	reject(t, resigned(t, func(sig *etree.Element) {
		path(sig, "SignedInfo", "SignatureMethod").CreateElement("ds:HMACOutputLength").SetText("8")
	}, crypto.SHA256), samlsp.ErrInvalidSignature)
}

func TestCompleteLogin_SignatureProfileBeyondGoxmldsig(t *testing.T) {
	t.Parallel()

	// A Signature-named element in a foreign namespace, signed over.
	reject(t, onAssertion(func(a *etree.Element) {
		el := path(a, "Subject").CreateElement("x:Signature")
		el.CreateAttr("xmlns:x", "urn:example:x")
	}), samlsp.ErrInvalidSignature)

	// A valid signature enveloped in another element (Extensions with an
	// ID): goxmldsig ignores it, the profile refuses it.
	reject(t, respOpts{before: func(r, _ *etree.Element) {
		ext := etree.NewElement("samlp:Extensions")
		ext.CreateAttr("xmlns:samlp", nsP)
		ext.CreateAttr("ID", "_ext")
		data := ext.CreateElement("x:Data")
		data.CreateAttr("xmlns:x", "urn:example:x")
		data.SetText("1")
		r.InsertChildAt(1, sign(t, ext, sigOpts{}))
	}}, samlsp.ErrInvalidSignature)

	// A foreign-namespace Signature carrying well-formed XML-DSig content
	// over the assertion: goxmldsig's namespace-aware lookup never sees it
	// (the signed Response alone would be verified), the profile refuses it.
	reject(t, respOpts{signResponse: true, unsignedAssert: true, before: func(_, a *etree.Element) {
		genuine := child(sign(t, a.Copy(), sigOpts{}), "Signature")
		fake := etree.NewElement("x:Signature")
		fake.CreateAttr("xmlns:x", "urn:example:x")
		fake.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

		for _, c := range genuine.ChildElements() {
			fake.AddChild(c.Copy())
		}

		a.InsertChildAt(1, fake)
	}}, samlsp.ErrInvalidSignature)

	// Two signatures on the Response, both shaped correctly: goxmldsig
	// would verify the first one only.
	reject(t, respOpts{signResponse: true, before: func(r, a *etree.Element) {
		extra := child(a, "Signature").Copy()
		path(extra, "SignedInfo", "Reference").CreateAttr("URI", "#"+responseID)
		r.AddChild(extra)
	}}, samlsp.ErrInvalidSignature)
}

func TestCompleteLogin_AttributeNameDifferential(t *testing.T) {
	t.Parallel()

	const sha256URI, sha1URI = "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2000/09/xmldsig#sha1"

	// A SHA-1 digest under a SignedInfo validly re-signed (rsa-sha256) by
	// the trusted key, whose DigestMethod also names SHA-256 through another
	// attribute of the same local name. etree's SelectAttr returns the
	// first such attribute whatever its prefix; encoding/xml, which decodes
	// goxmldsig's canonical SignedInfo, the last (code review F3).
	sha1Digest := func(edit func(dm *etree.Element)) respOpts {
		return resigned(t, func(sig *etree.Element) {
			path(sig, "SignedInfo", "SignatureMethod").CreateAttr("Algorithm", dsig.RSASHA256SignatureMethod)
			dm := path(sig, "SignedInfo", "Reference", "DigestMethod")
			dm.RemoveAttr("Algorithm")
			edit(dm)
		}, crypto.SHA256, crypto.SHA1)
	}

	cases := map[string]func(dm *etree.Element){
		"plain SHA-256, then prefixed SHA-1": func(dm *etree.Element) {
			dm.CreateAttr("Algorithm", sha256URI)
			dm.CreateAttr("xmlns:foo", "urn:example:foo")
			dm.CreateAttr("foo:Algorithm", sha1URI)
		},
		"prefixed SHA-1, then plain SHA-256": func(dm *etree.Element) {
			dm.CreateAttr("xmlns:foo", "urn:example:foo")
			dm.CreateAttr("foo:Algorithm", sha1URI)
			dm.CreateAttr("Algorithm", sha256URI)
		},
		"namespace declaration named Algorithm": func(dm *etree.Element) {
			dm.CreateAttr("xmlns:Algorithm", sha256URI)
			dm.CreateAttr("Algorithm", sha1URI)
		},
		"lone prefixed Algorithm": func(dm *etree.Element) {
			dm.CreateAttr("xmlns:foo", "urn:example:foo")
			dm.CreateAttr("foo:Algorithm", sha1URI)
		},
	}

	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reject(t, sha1Digest(edit), samlsp.ErrMalformedResponse)
		})
	}

	// Control: the same digest under a plain Algorithm is an algorithm
	// refusal, and is accepted with the opt-in.
	plain := sha1Digest(func(dm *etree.Element) { dm.CreateAttr("Algorithm", sha1URI) })
	reject(t, plain, samlsp.ErrUnsupportedAlgorithm)

	_, err := flow(t, newEnv(t, allowSHA1), plain)
	require.NoError(t, err)
}

func TestCompleteLogin_PrefixedSAMLAttributes(t *testing.T) {
	t.Parallel()

	// encoding/xml matches attributes by local name: gosaml2 would read
	// foo:Destination as the Destination. A prefixed attribute named like
	// a SAML or XML-DSig attribute is refused (code review F3).
	prefixed := func(el *etree.Element, name, value string) {
		el.CreateAttr("xmlns:foo", "urn:example:foo")
		el.CreateAttr("foo:"+name, value)
	}

	cases := map[string]respOpts{
		"Response Destination": onResponse(func(r *etree.Element) {
			r.RemoveAttr("Destination")
			prefixed(r, "Destination", "https://evil.example.com/acs")
		}),
		"SubjectConfirmationData NotBefore": onAssertion(func(a *etree.Element) {
			prefixed(path(a, "Subject", "SubjectConfirmation", "SubjectConfirmationData"), "NotBefore", "2026-10-12T09:00:00Z")
		}),
		"Reference Type": {before: func(_, a *etree.Element) {
			prefixed(path(child(a, "Signature"), "SignedInfo", "Reference"), "Type", "urn:x")
		}},
	}

	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reject(t, o, samlsp.ErrMalformedResponse)
		})
	}

	// Foreign attributes with other names are allowed (xsi:type, x500:Encoding...).
	_, err := flow(t, newEnv(t), onAssertion(func(a *etree.Element) {
		attr := path(a, "AttributeStatement", "Attribute")
		attr.CreateAttr("xmlns:x500", "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500")
		attr.CreateAttr("x500:Encoding", "LDAP")
	}))
	require.NoError(t, err)
}

// TestCompleteLogin_XMLNamespaceAttributes: the xml prefix is reserved and
// only xml:lang, xml:space, xml:base and xml:id are defined in its
// namespace. encoding/xml (gosaml2) matches attributes by local name, so
// xml:NotBefore, xml:Destination or xml:SessionNotOnOrAfter would be read
// as the SAML attributes the pre-check never saw (audit SAML-I1).
func TestCompleteLogin_XMLNamespaceAttributes(t *testing.T) {
	t.Parallel()

	refused := map[string]respOpts{
		// Profiles §4.1.4.2: a bearer SubjectConfirmationData MUST NOT carry NotBefore.
		"xml:NotBefore on the bearer confirmation": onAssertion(func(a *etree.Element) {
			scd(a).CreateAttr("xml:NotBefore", ts(-time.Minute))
		}),
		// Bindings §3.5.5.2: a signed Response must carry Destination.
		"xml:Destination standing for the Destination of a signed Response": {signResponse: true, before: func(r, _ *etree.Element) {
			r.RemoveAttr("Destination")
			r.CreateAttr("xml:Destination", acsURL)
		}},
		// Core §1.3.3: time values are UTC; the pre-check reads unprefixed attributes only.
		"xml:SessionNotOnOrAfter with an offset": onAssertion(func(a *etree.Element) {
			st := child(a, "AuthnStatement")
			st.RemoveAttr("SessionNotOnOrAfter")
			st.CreateAttr("xml:SessionNotOnOrAfter", "2026-10-12T20:00:00+05:00")
		}),
		"an undefined xml attribute on the Status": onResponse(func(r *etree.Element) {
			child(r, "Status").CreateAttr("xml:evil", "x")
		}),
	}

	for name, o := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			lr := begin(t, e, samlsp.LoginOptions{})

			res, err := complete(e, lr, respond(t, lr.requestID, o))
			assert.Nil(t, res)
			requireRejected(t, e, lr, err, samlsp.ErrMalformedResponse)
			assert.Contains(t, err.Error(), "attribute in the xml namespace other than xml:lang, xml:space, xml:base or xml:id")
		})
	}

	// The four names the XML namespace defines remain allowed.
	_, err := flow(t, newEnv(t), onAssertion(func(a *etree.Element) {
		attr := path(a, "AttributeStatement", "Attribute")
		attr.CreateAttr("xml:lang", "en")
		attr.CreateAttr("xml:space", "preserve")
		attr.CreateAttr("xml:base", "https://idp.example.com/")
		attr.CreateAttr("xml:id", "_attribute-1")
	}))
	require.NoError(t, err)
}

func TestCompleteLogin_SignatureStructureValidlySigned(t *testing.T) {
	t.Parallel()

	// Each shape below is validly signed by the trusted key, and goxmldsig
	// ignores the extra content: only the pre-check refuses it (code review
	// F6).
	foreign := func(parent *etree.Element) {
		el := parent.CreateElement("x:Extra")
		el.CreateAttr("xmlns:x", "urn:example:x")
	}
	transforms := func(sig *etree.Element) []*etree.Element {
		return path(sig, "SignedInfo", "Reference", "Transforms").ChildElements()
	}

	cases := map[string]respOpts{
		"element inside CanonicalizationMethod": resigned(t, func(sig *etree.Element) {
			foreign(path(sig, "SignedInfo", "CanonicalizationMethod"))
		}, crypto.SHA256),
		"element inside the enveloped-signature transform": resigned(t, func(sig *etree.Element) {
			transforms(sig)[0].CreateElement("ds:XPath").SetText("1")
		}, crypto.SHA256),
		"element inside DigestValue": resigned(t, func(sig *etree.Element) {
			path(sig, "SignedInfo", "Reference", "DigestValue").CreateElement("ds:Extra")
		}, crypto.SHA256),
		"element inside DigestMethod": resigned(t, func(sig *etree.Element) {
			foreign(path(sig, "SignedInfo", "Reference", "DigestMethod"))
		}, crypto.SHA256),
		"foreign element instead of InclusiveNamespaces": resigned(t, func(sig *etree.Element) {
			foreign(transforms(sig)[1])
		}, crypto.SHA256),
		"InclusiveNamespaces with a child": resigned(t, func(sig *etree.Element) {
			inc := transforms(sig)[1].CreateElement("ec:InclusiveNamespaces")
			inc.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
			inc.CreateAttr("PrefixList", "")
			foreign(inc)
		}, crypto.SHA256),
		"element inside SignatureValue": {after: func(r *etree.Element) {
			path(assertionSignature(r), "SignatureValue").CreateElement("ds:Extra")
		}},
	}

	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reject(t, o, samlsp.ErrInvalidSignature)
		})
	}
}

func TestCompleteLogin_InclusiveNamespacesPrefixList(t *testing.T) {
	t.Parallel()

	// OpenSAML-based IdPs (Shibboleth) emit an InclusiveNamespaces
	// PrefixList on the exclusive canonicalization transform.
	res, err := flow(t, newEnv(t), respOpts{assertionSig: sigOpts{inclusivePrefixes: "xs"}})
	require.NoError(t, err)
	assert.Equal(t, nameIDValue, res.Identity.NameID.Value)

	// The PrefixList is bounded like the in-scope prefixes: a validly signed
	// list of 32 prefixes passes, one of 33 is refused.
	prefixes := func(n int) string {
		list := make([]string, n)
		for i := range list {
			list[i] = "p" + strconv.Itoa(i)
		}

		return strings.Join(list, " ")
	}

	_, err = flow(t, newEnv(t), respOpts{assertionSig: sigOpts{inclusivePrefixes: prefixes(32)}})
	require.NoError(t, err)
	reject(t, respOpts{assertionSig: sigOpts{inclusivePrefixes: prefixes(33)}}, samlsp.ErrInvalidSignature)

	// The resigning helper is sound: a tampered SignedInfo fails.
	reject(t, respOpts{assertionSig: sigOpts{inclusivePrefixes: "xs"}, after: func(r *etree.Element) {
		path(assertionSignature(r), "SignedInfo", "Reference", "Transforms").ChildElements()[1].
			FindElement("./InclusiveNamespaces").CreateAttr("PrefixList", "xs xsi")
	}}, samlsp.ErrInvalidSignature)
}

func TestCompleteLogin_SignatureStructure(t *testing.T) {
	t.Parallel()

	inSig := func(f func(sig *etree.Element)) respOpts {
		return respOpts{after: func(r *etree.Element) { f(assertionSignature(r)) }}
	}
	reference := func(sig *etree.Element) *etree.Element { return path(sig, "SignedInfo", "Reference") }
	transforms := func(sig *etree.Element) *etree.Element { return path(reference(sig), "Transforms") }

	cases := []struct {
		name string
		o    respOpts
	}{
		{"ds:Object in the signature (errata E91)", inSig(func(sig *etree.Element) {
			sig.CreateElement("ds:Object").CreateElement("payload").SetText("unsigned")
		})},
		{"Reference URI empty", inSig(func(sig *etree.Element) { reference(sig).CreateAttr("URI", "") })},
		{"Reference URI without #", inSig(func(sig *etree.Element) { reference(sig).CreateAttr("URI", "x"+assertionID) })},
		{"Reference to another element", inSig(func(sig *etree.Element) { reference(sig).CreateAttr("URI", "#"+responseID) })},
		{"two References (Core §5.4.2)", inSig(func(sig *etree.Element) {
			path(sig, "SignedInfo").AddChild(reference(sig).Copy())
		})},
		{"enveloped transform only (Null canonicalizer, review F5)", inSig(func(sig *etree.Element) {
			tr := transforms(sig)
			tr.RemoveChild(tr.ChildElements()[1])
		})},
		{"transforms in reverse order", inSig(func(sig *etree.Element) {
			tr := transforms(sig)
			first := tr.ChildElements()[0]
			tr.RemoveChild(first)
			tr.AddChild(first)
		})},
		{"extra XPath transform", inSig(func(sig *etree.Element) {
			transforms(sig).CreateElement("ds:Transform").CreateAttr("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116")
		})},
		{"missing CanonicalizationMethod", inSig(func(sig *etree.Element) {
			si := path(sig, "SignedInfo")
			si.RemoveChild(path(si, "CanonicalizationMethod"))
		})},
		{"two SignatureMethods", inSig(func(sig *etree.Element) {
			si := path(sig, "SignedInfo")
			si.AddChild(path(si, "SignatureMethod").Copy())
		})},
		{"HMACOutputLength", inSig(func(sig *etree.Element) {
			path(sig, "SignedInfo", "SignatureMethod").CreateElement("ds:HMACOutputLength").SetText("8")
		})},
		{"unknown SignedInfo child", inSig(func(sig *etree.Element) { path(sig, "SignedInfo").CreateElement("ds:Manifest") })},
		{"foreign element inside the signature", inSig(func(sig *etree.Element) {
			el := path(sig, "SignedInfo", "Reference").CreateElement("x:Note")
			el.CreateAttr("xmlns:x", "urn:example:x")
		})},
		{"missing SignatureValue", inSig(func(sig *etree.Element) { sig.RemoveChild(path(sig, "SignatureValue")) })},
		{"two KeyInfo", inSig(func(sig *etree.Element) { sig.AddChild(path(sig, "KeyInfo").Copy()) })},
		{"foreign element in the canonicalization method", inSig(func(sig *etree.Element) {
			el := path(sig, "SignedInfo", "CanonicalizationMethod").CreateElement("x:Extra")
			el.CreateAttr("xmlns:x", "urn:example:x")
		})},
		{"two InclusiveNamespaces", inSig(func(sig *etree.Element) {
			tr := transforms(sig).ChildElements()[1]
			for i := 0; i < 2; i++ {
				inc := tr.CreateElement("ec:InclusiveNamespaces")
				inc.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
			}
		})},
		{"non-transform child of Transforms", inSig(func(sig *etree.Element) {
			tr := transforms(sig)
			tr.InsertChildAt(0, etree.NewElement("ds:DigestMethod"))
			tr.RemoveChild(tr.ChildElements()[2])
		})},
		{"enveloped transform with a child", inSig(func(sig *etree.Element) {
			transforms(sig).ChildElements()[0].CreateElement("ds:XPath")
		})},
		{"missing DigestValue", inSig(func(sig *etree.Element) {
			ref := reference(sig)
			ref.RemoveChild(path(ref, "DigestValue"))
		})},
		{"DigestValue with a child", inSig(func(sig *etree.Element) {
			path(reference(sig), "DigestValue").CreateElement("ds:X")
		})},
		{"DigestMethod with a child", inSig(func(sig *etree.Element) {
			path(reference(sig), "DigestMethod").CreateElement("ds:X")
		})},
		{"Reference without URI", inSig(func(sig *etree.Element) { reference(sig).RemoveAttr("URI") })},
		{"too many inclusive namespace prefixes", inSig(func(sig *etree.Element) {
			inc := transforms(sig).ChildElements()[1].CreateElement("ec:InclusiveNamespaces")
			inc.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
			inc.CreateAttr("PrefixList", strings.TrimSpace(strings.Repeat("p ", 33)))
		})},
		{"two signatures on the assertion", respOpts{after: func(r *etree.Element) {
			a := child(r, "Assertion")
			a.AddChild(path(a, "Signature").Copy())
		}}},
		{"signature moved into the Subject", respOpts{after: func(r *etree.Element) {
			a := child(r, "Assertion")
			sig := path(a, "Signature")
			a.RemoveChild(sig)
			path(a, "Subject").AddChild(sig)
		}}},
		{"response signature moved into Status", respOpts{unsignedAssert: true, signResponse: true, after: func(r *etree.Element) {
			sig := child(r, "Signature")
			r.RemoveChild(sig)
			child(r, "Status").AddChild(sig)
		}}},
		{"response signature moved into the Assertion", respOpts{unsignedAssert: true, signResponse: true, after: func(r *etree.Element) {
			sig := child(r, "Signature")
			r.RemoveChild(sig)
			child(r, "Assertion").AddChild(sig)
		}}},
		{"Signature element in a foreign namespace", respOpts{after: func(r *etree.Element) {
			el := path(r, "Assertion", "Subject").CreateElement("x:Signature")
			el.CreateAttr("xmlns:x", "urn:example:x")
		}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reject(t, tc.o, samlsp.ErrInvalidSignature)
		})
	}
}

func TestCompleteLogin_XMLSignatureWrapping(t *testing.T) {
	t.Parallel()

	// forged is an unsigned assertion naming another user.
	forged := func() *etree.Element {
		a := buildAssertion(respParams{requestID: "_ignored", issued: t0})
		a.CreateAttr("ID", "_forged")
		path(a, "Subject", "NameID").SetText("admin")

		return a
	}

	cases := []struct {
		name string
		o    respOpts
		want error
	}{
		{"original moved into Extensions, forged assertion in its place", respOpts{after: func(r *etree.Element) {
			orig := child(r, "Assertion")
			r.RemoveChild(orig)
			ext := etree.NewElement("samlp:Extensions")
			ext.AddChild(orig)
			r.InsertChildAt(1, ext)
			r.AddChild(forged())
		}}, samlsp.ErrMalformedResponse},
		{"clone with the same ID", respOpts{after: func(r *etree.Element) {
			clone := child(r, "Assertion").Copy()
			path(clone, "Subject", "NameID").SetText("admin")
			r.AddChild(clone)
		}}, samlsp.ErrMalformedResponse},
		{"assertion injected into a signed Response", respOpts{signResponse: true, after: func(r *etree.Element) {
			r.AddChild(forged())
		}}, samlsp.ErrMalformedResponse},
		{"forged assertion before the signed one", respOpts{after: func(r *etree.Element) {
			r.InsertChildAt(2, forged())
		}}, samlsp.ErrMalformedResponse},
		{"original hidden in the Advice of the forged one", respOpts{after: func(r *etree.Element) {
			orig := child(r, "Assertion")
			r.RemoveChild(orig)
			f := forged()
			adv := f.CreateElement("saml:Advice")
			adv.AddChild(orig)
			r.AddChild(f)
		}}, samlsp.ErrMalformedResponse},
		{"original hidden in a ds:Object", respOpts{after: func(r *etree.Element) {
			orig := child(r, "Assertion")
			r.RemoveChild(orig)
			f := forged()
			sig := path(orig, "Signature").Copy()
			sig.CreateElement("ds:Object").AddChild(orig)
			f.InsertChildAt(1, sig)
			r.AddChild(f)
		}}, samlsp.ErrMalformedResponse},
		{"duplicate ID on another element", respOpts{after: func(r *etree.Element) {
			path(r, "Status").CreateAttr("ID", assertionID)
		}}, samlsp.ErrMalformedResponse},
		{"Response and Assertion share an ID", respOpts{before: func(r, _ *etree.Element) {
			r.CreateAttr("ID", assertionID)
		}}, samlsp.ErrMalformedResponse},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reject(t, tc.o, tc.want)
		})
	}
}

func TestCompleteLogin_CommentInNameIDIsCanonical(t *testing.T) {
	t.Parallel()

	// exc-c14n without comments: the comment is outside the digest, so the
	// signature still verifies. A parser reading only the first text node
	// would see "alice-pair" (CVE-2017-11427 class); the identity must be
	// the full canonical value.
	res, err := flow(t, newEnv(t), respOpts{raw: func(s string) string {
		return strings.Replace(s, ">"+nameIDValue+"<", ">alice-pair<!-- x -->wise-0001<", 1)
	}})
	require.NoError(t, err)
	assert.Equal(t, nameIDValue, res.Identity.NameID.Value)

	// With exc-c14n#WithComments the comment is signed content: injecting
	// one breaks the signature.
	reject(t, respOpts{assertionSig: sigOpts{canon: exclusiveWithComments()}, raw: func(s string) string {
		return strings.Replace(s, ">"+nameIDValue+"<", ">alice-pair<!-- x -->wise-0001<", 1)
	}}, samlsp.ErrInvalidSignature)
}

func TestCompleteLogin_CertificateRollover(t *testing.T) {
	t.Parallel()

	k := keys(t)

	accepted := []struct {
		name string
		o    respOpts
		opts []envOption
	}{
		{"new key, KeyInfo present", respOpts{assertionSig: sigOpts{signer: k.idpB}}, []envOption{trustKeys(k.idpA, k.idpB)}},
		{"old key, no KeyInfo (retried per certificate)", respOpts{assertionSig: sigOpts{noKeyInfo: true}}, []envOption{trustKeys(k.idpA, k.idpB)}},
		{"new key, no KeyInfo", respOpts{assertionSig: sigOpts{signer: k.idpB, noKeyInfo: true}}, []envOption{trustKeys(k.idpA, k.idpB)}},
		{"single key, no KeyInfo", respOpts{assertionSig: sigOpts{noKeyInfo: true}}, nil},
		{"response signed, no KeyInfo, two keys", respOpts{unsignedAssert: true, signResponse: true, responseSig: sigOpts{signer: k.idpB, noKeyInfo: true}}, []envOption{trustKeys(k.idpA, k.idpB)}},
		{"valid key next to an expired one, no KeyInfo", respOpts{assertionSig: sigOpts{noKeyInfo: true}}, []envOption{trustKeys(k.expired, k.idpA)}},
	}

	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := flow(t, newEnv(t, tc.opts...), tc.o)
			require.NoError(t, err)
		})
	}

	refused := []struct {
		name string
		o    respOpts
		opts []envOption
	}{
		{"untrusted key, no KeyInfo", respOpts{assertionSig: sigOpts{signer: k.attacker, noKeyInfo: true}}, []envOption{trustKeys(k.idpA, k.idpB)}},
		{"expired key, no KeyInfo: expired certificates are not retried", respOpts{assertionSig: sigOpts{signer: k.expired, noKeyInfo: true}}, []envOption{trustKeys(k.expired, k.idpA)}},
		{"expired trusted certificate (goxmldsig validity window)", respOpts{assertionSig: sigOpts{signer: k.expired}}, []envOption{trustKeys(k.expired)}},
		{"only expired certificates, no KeyInfo", respOpts{assertionSig: sigOpts{signer: k.expired, noKeyInfo: true}}, []envOption{trustKeys(k.expired, newExpired(t))}},
	}

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reject(t, tc.o, samlsp.ErrInvalidSignature, tc.opts...)
		})
	}
}

// newExpired returns another key whose certificate expired before t0.
func newExpired(t *testing.T) keyPair {
	t.Helper()

	return newRSAPair(2048, "expired-2", t0.Add(-72*time.Hour), t0.Add(-48*time.Hour))
}
