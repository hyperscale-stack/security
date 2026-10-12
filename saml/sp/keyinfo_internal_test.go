// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyInfoDoc renders a Response whose Response signature (respKI) and
// Assertion signature (assertKI) carry the given KeyInfo markup ("" for
// none), with extra markup in the envelope and in the assertion.
func keyInfoDoc(respKI, assertKI, envelope, inAssertion string) string {
	return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_r">` +
		`<ds:Signature><ds:SignedInfo/>` + respKI + `</ds:Signature>` + envelope +
		`<saml:Assertion ID="_a"><ds:Signature><ds:SignedInfo/>` + assertKI + `</ds:Signature>` + inAssertion + `</saml:Assertion>` +
		`</samlp:Response>`
}

// spanText returns the bytes of each recorded span, by position.
func spanText(t *testing.T, doc string) map[keyInfoPosition]string {
	t.Helper()

	scan, err := scanXML([]byte(doc), responseLimits)
	require.NoError(t, err)

	out := map[keyInfoPosition]string{}

	for _, s := range scan.keyInfo {
		_, dup := out[s.pos]
		require.False(t, dup, "one span per position")

		out[s.pos] = doc[s.start:s.end]
		assert.Equal(t, doc[s.start:s.end], doc[s.start:s.end])
	}

	return out
}

// TestScanXML_KeyInfoSpans: the gate records a span only for a ds:KeyInfo
// child of the signature of the root Response or of its Assertion, whatever
// its spelling, and never elsewhere (plan review F2, H1).
func TestScanXML_KeyInfoSpans(t *testing.T) {
	t.Parallel()

	const (
		name     = `<ds:KeyInfo><ds:KeyName>k</ds:KeyName></ds:KeyInfo>`
		selfie   = `<ds:KeyInfo/>`
		dflt     = `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><KeyName>k</KeyName></KeyInfo>`
		rebound  = `<x:KeyInfo xmlns:x="http://www.w3.org/2000/09/xmldsig#"><x:KeyName>k</x:KeyName></x:KeyInfo>`
		comments = `<ds:KeyInfo><!-- <ds:X509Certificate> --><ds:KeyName><![CDATA[<ds:X509Certificate>]]></ds:KeyName></ds:KeyInfo>`
		withCert = `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>AA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`
		foreign  = `<ds:KeyInfo><ds:X509Data><f:X509Certificate xmlns:f="urn:f">AA==</f:X509Certificate></ds:X509Data></ds:KeyInfo>`
	)

	for _, ki := range []string{name, selfie, dflt, rebound, comments, withCert, foreign} {
		got := spanText(t, keyInfoDoc(ki, ki, "", ""))
		assert.Equal(t, map[keyInfoPosition]string{keyInfoResponse: ki, keyInfoAssertion: ki}, got, ki)
	}

	scan, err := scanXML([]byte(keyInfoDoc(name, withCert, "", "")), responseLimits)
	require.NoError(t, err)
	require.Len(t, scan.keyInfo, 2)
	assert.False(t, scan.keyInfo[0].hasCert)
	assert.True(t, scan.keyInfo[1].hasCert)

	scan, err = scanXML([]byte(keyInfoDoc(foreign, comments, "", "")), responseLimits)
	require.NoError(t, err)
	assert.True(t, scan.keyInfo[0].hasCert, "an X509Certificate of another namespace is still a certificate to goxmldsig")
	assert.False(t, scan.keyInfo[1].hasCert, "comments and CDATA hold no element")

	// A ds:KeyInfo nested deeper in a signature is not at a position.
	nested := `<ds:SignedInfo><ds:KeyInfo/></ds:SignedInfo><ds:Object><ds:KeyInfo><ds:KeyName>n</ds:KeyName></ds:KeyInfo></ds:Object>` + name
	doc := strings.ReplaceAll(keyInfoDoc(nested, nested, "", ""), `<ds:Signature><ds:SignedInfo/>`, `<ds:Signature>`)
	assert.Equal(t, map[keyInfoPosition]string{keyInfoResponse: name, keyInfoAssertion: name}, spanText(t, doc))

	// Not a ds:KeyInfo at a signature position: nothing recorded.
	for _, doc := range []string{
		keyInfoDoc(`<KeyInfo xmlns=""/>`, `<y:KeyInfo xmlns:y="urn:not-dsig"/>`, "", ""),
		keyInfoDoc("", "", `<samlp:Extensions>`+name+`</samlp:Extensions>`, `<saml:Subject>`+name+`</saml:Subject>`),
		strings.Replace(keyInfoDoc(name, name, "", ""), `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`,
			`<samlp:Response xmlns:samlp="urn:not-the-protocol"`, 1),
	} {
		assert.Empty(t, spanText(t, doc), doc)
	}
}

// TestKeyInfoCuts_CrossCheck: the tree and the gate must agree on every
// position before anything is cut (plan review F2, H2).
func TestKeyInfoCuts_CrossCheck(t *testing.T) {
	t.Parallel()

	certless := keyInfoState{present: true, certless: true}
	span := keyInfoSpan{pos: keyInfoResponse, start: 0, end: 10, qname: "ds:KeyInfo"}

	raw := &rawResponse{}
	raw.keyInfo[keyInfoResponse] = certless

	cuts, err := keyInfoCuts(raw, &gateScan{keyInfo: []keyInfoSpan{span}})
	require.NoError(t, err)
	require.Len(t, cuts, 1)

	for name, scan := range map[string]*gateScan{
		"no span":             {},
		"span with a cert":    {keyInfo: []keyInfoSpan{{pos: keyInfoResponse, end: 10, qname: "ds:KeyInfo", hasCert: true}}},
		"two spans":           {keyInfo: []keyInfoSpan{span, span}},
		"span at the other":   {keyInfo: []keyInfoSpan{span, {pos: keyInfoAssertion, end: 10, qname: "ds:KeyInfo"}}},
		"span elsewhere only": {keyInfo: []keyInfoSpan{{pos: keyInfoAssertion, end: 10, qname: "ds:KeyInfo"}}},
	} {
		_, err := keyInfoCuts(raw, scan)
		require.ErrorIs(t, err, ErrMalformedResponse, name)
		require.ErrorContains(t, err, errKeyInfoDifferential, name)
	}

	// A KeyInfo with a certificate is never cut.
	withCert := &rawResponse{}
	withCert.keyInfo[keyInfoResponse] = keyInfoState{present: true}
	cuts, err = keyInfoCuts(withCert, &gateScan{keyInfo: []keyInfoSpan{{pos: keyInfoResponse, end: 10, qname: "ds:KeyInfo", hasCert: true}}})
	require.NoError(t, err)
	assert.Empty(t, cuts)
}

// TestSplice_ChecksSpans: a span must be exactly an element of the recorded
// name, spans never overlap, and they are cut from the last (H3).
func TestSplice_ChecksSpans(t *testing.T) {
	t.Parallel()

	const one, two = `<ds:KeyInfo a="1">x</ds:KeyInfo>`, `<ds:KeyInfo/>`

	doc := []byte(`<r>` + one + `<b/>` + two + `</r>`)
	at := func(s string) (int64, int64) {
		i := int64(strings.Index(string(doc), s))

		return i, i + int64(len(s))
	}

	s1, e1 := at(one)
	s2, e2 := at(two)
	first := keyInfoSpan{pos: keyInfoResponse, start: s1, end: e1, qname: "ds:KeyInfo"}
	second := keyInfoSpan{pos: keyInfoAssertion, start: s2, end: e2, qname: "ds:KeyInfo"}

	out, err := splice(doc, []keyInfoSpan{first, second})
	require.NoError(t, err)
	assert.Equal(t, `<r><b/></r>`, string(out))
	assert.Equal(t, `<r><ds:KeyInfo a="1">x</ds:KeyInfo><b/><ds:KeyInfo/></r>`, string(doc), "the input is not modified")

	for name, s := range map[string]keyInfoSpan{
		"not at a tag":      {start: s1 + 1, end: e1, qname: "ds:KeyInfo"},
		"not ending a tag":  {start: s1, end: e1 - 1, qname: "ds:KeyInfo"},
		"another name":      {start: s1, end: e1, qname: "ds:KeyName"},
		"a prefix of name":  {start: s1, end: e1, qname: "ds:Key"},
		"past the end":      {start: s2, end: int64(len(doc)) + 1, qname: "ds:KeyInfo"},
		"negative":          {start: -1, end: e1, qname: "ds:KeyInfo"},
		"shorter than name": {start: s1, end: s1 + 5, qname: "ds:KeyInfo"},
	} {
		_, err := splice(doc, []keyInfoSpan{s})
		require.ErrorContains(t, err, errKeyInfoSpan, name)
	}

	_, err = splice(doc, []keyInfoSpan{first, {start: s1, end: e2, qname: "ds:KeyInfo"}})
	require.ErrorContains(t, err, errKeyInfoSpan, "overlapping spans")
}

// TestCutCertificatelessKeyInfo_RechecksTheCut: a cut that leaves a
// certificate-less KeyInfo — here a span pointing at a decoy KeyInfo of the
// envelope instead of the Assertion's — is refused by the re-check of the
// cut document (H4), although that document passes every other check.
func TestCutCertificatelessKeyInfo_RechecksTheCut(t *testing.T) {
	t.Parallel()

	signed, err := os.ReadFile("testdata/corpus/keys/keyinfo-keyname-only.xml")
	require.NoError(t, err)

	const decoy = `<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyName>decoy</ds:KeyName></ds:KeyInfo>`

	doc := strings.Replace(string(signed), "<samlp:Status>", "<samlp:Extensions>"+decoy+"</samlp:Extensions><samlp:Status>", 1)
	require.NotEqual(t, string(signed), doc)

	raw, err := precheckTree([]byte(doc), false)
	require.NoError(t, err)
	require.Equal(t, keyInfoState{present: true, certless: true}, raw.keyInfo[keyInfoAssertion])

	start := int64(strings.Index(doc, decoy))
	scan := &gateScan{keyInfo: []keyInfoSpan{{pos: keyInfoAssertion, start: start, end: start + int64(len(decoy)), qname: "ds:KeyInfo"}}}

	_, err = cutCertificatelessKeyInfo(raw, scan, false)
	require.ErrorIs(t, err, ErrMalformedResponse)
	require.ErrorContains(t, err, errKeyInfoLeft)

	// The genuine span is cut and the document checked again.
	genuine, err := scanXML([]byte(doc), responseLimits)
	require.NoError(t, err)

	cut, err := cutCertificatelessKeyInfo(raw, genuine, false)
	require.NoError(t, err)
	assert.False(t, cut.keyInfo[keyInfoAssertion].present)
	assert.True(t, cut.keyInfoMissing)
	assert.Less(t, len(cut.data), len(doc))
}

// isSubsequence reports whether sub is seq with some bytes removed.
func isSubsequence(sub, seq []byte) bool {
	i := 0

	for _, b := range seq {
		if i < len(sub) && sub[i] == b {
			i++
		}
	}

	return i == len(sub)
}

// FuzzPrecheck runs the gate and the structural pre-check, KeyInfo cut
// included, over arbitrary bytes seeded with the adversarial corpus: no
// panic; an accepted document is the input with bytes removed, passes the
// gate again, and a Success keeps no certificate-less KeyInfo at a
// signature position (plan review F2, H5).
func FuzzPrecheck(f *testing.F) {
	files, err := filepath.Glob("testdata/corpus/*/*.xml")
	require.NoError(f, err)

	for _, file := range files {
		b, err := os.ReadFile(file) //nolint:gosec // test corpus
		require.NoError(f, err)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		data = stripBOM(data)

		for _, sha1 := range []bool{false, true} {
			raw, err := precheck(data, sha1)
			if err != nil {
				continue
			}

			if !isSubsequence(raw.data, data) {
				t.Fatalf("the checked bytes are not the input with bytes removed")
			}

			if _, err := scanXML(raw.data, responseLimits); err != nil {
				t.Fatalf("the checked bytes do not pass the gate: %v", err)
			}

			if !raw.status.success() {
				continue
			}

			for _, pos := range []keyInfoPosition{keyInfoResponse, keyInfoAssertion} {
				if raw.keyInfo[pos].certless {
					t.Fatalf("a certificate-less KeyInfo is left at position %d", pos)
				}
			}

			if len(raw.data) != len(data) && !raw.keyInfoMissing {
				t.Fatalf("bytes were cut but no signature lacks KeyInfo")
			}
		}
	})
}
