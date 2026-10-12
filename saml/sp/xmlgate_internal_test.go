// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gateResult classifies a checkXML outcome.
func gateResult(err error) string {
	var ge *gateError

	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &ge) && ge.tooLarge:
		return "too-large"
	case errors.As(err, &ge):
		return "malformed"
	default:
		return "other: " + err.Error()
	}
}

// repeatAttrs renders n attributes named prefix0..prefixN-1.
func repeatAttrs(n int, format string) string {
	var b strings.Builder

	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, format, i, i)
	}

	return b.String()
}

// nested renders depth nested <e> elements.
func nested(depth int) string {
	return strings.Repeat("<e>", depth) + strings.Repeat("</e>", depth)
}

func TestCheckXML_Hygiene(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, doc, want string
	}{
		{"minimal", `<r/>`, "ok"},
		{"declaration", `<?xml version="1.0" encoding="UTF-8"?><r/>`, "ok"},
		{"declaration without encoding", `<?xml version="1.0"?><r/>`, "ok"},
		{"comments and whitespace around the root", "<!-- c -->\n<r/>\n<!-- d -->", "ok"},
		{"namespaces", `<p:r xmlns:p="urn:p" xmlns="urn:d"><p:a p:x="1" y="2"/><b xml:lang="en" xml:id="i"/></p:r>`, "ok"},
		{"xml prefix declared to its namespace", `<r xmlns:xml="http://www.w3.org/XML/1998/namespace"/>`, "ok"},
		{"default namespace undeclared", `<r xmlns=""/>`, "ok"},
		{"unprefixed Id attribute", `<r Id="a" ID="b" id="c"/>`, "ok"},

		{"DOCTYPE", `<!DOCTYPE r><r/>`, "malformed"},
		{"DOCTYPE with internal entity", `<!DOCTYPE r [<!ENTITY x "y">]><r/>`, "malformed"},
		{"DOCTYPE with external entity", `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`, "malformed"},
		{"undefined entity", `<r>&x;</r>`, "malformed"},
		{"processing instruction", `<r><?php echo 1 ?></r>`, "malformed"},
		{"stylesheet instruction", `<?xml-stylesheet href="x"?><r/>`, "malformed"},
		{"late XML declaration", ` <?xml version="1.0"?><r/>`, "malformed"},
		{"non-UTF-8 encoding", `<?xml version="1.0" encoding="ISO-8859-1"?><r/>`, "malformed"},
		{"XML 1.1", `<?xml version="1.1"?><r/>`, "malformed"},
		{"text before the root", `x<r/>`, "malformed"},
		{"text after the root", `<r/>x`, "malformed"},
		{"non-breaking space after the root", "<r/> ", "malformed"},
		{"two roots", `<r/><s/>`, "malformed"},
		{"no root", `<!-- only a comment -->`, "malformed"},
		{"empty", ``, "malformed"},
		{"unclosed root", `<r>`, "malformed"},
		{"mismatched end tag", `<r></s>`, "malformed"},
		{"mismatched prefix on end tag", `<a:r xmlns:a="urn:a" xmlns:b="urn:a"></b:r>`, "malformed"},
		{"stray end tag", `</r>`, "malformed"},
		{"duplicate attribute", `<r a="1" a="2"/>`, "malformed"},
		{"duplicate prefixed attribute", `<r xmlns:p="urn:p" p:a="1" p:a="2"/>`, "malformed"},
		{"duplicate after namespace resolution", `<r xmlns:a="urn:x" xmlns:b="urn:x" a:k="1" b:k="2"/>`, "malformed"},
		{"duplicate namespace declaration", `<r xmlns:a="urn:x" xmlns:a="urn:y"/>`, "malformed"},
		// etree's SelectAttr returns the first attribute of a local name
		// whatever its prefix, encoding/xml the last: two attributes of one
		// local name are refused, whatever their namespaces (code review F3).
		{"same local name, different namespaces", `<r xmlns:a="urn:a" xmlns:b="urn:b" a:x="1" b:x="2"/>`, "malformed"},
		{"plain and prefixed attribute", `<r x="1" xmlns:p="urn:p" p:x="2"/>`, "malformed"},
		{"prefixed then plain attribute", `<r xmlns:p="urn:p" p:Algorithm="a" Algorithm="b"/>`, "malformed"},
		{"declaration named like an attribute", `<r xmlns:Algorithm="urn:a" Algorithm="b"/>`, "malformed"},
		{"prefixed ID", `<r xmlns:foo="urn:foo" foo:ID="_x" ID="_y"/>`, "malformed"},
		{"prefixed Id", `<r xmlns:foo="urn:foo" foo:Id="_x"/>`, "malformed"},
		{"prefixed id", `<r xmlns:foo="urn:foo" foo:id="_x"/>`, "malformed"},
		{"undeclared element prefix", `<p:r/>`, "malformed"},
		{"undeclared attribute prefix", `<r p:a="1"/>`, "malformed"},
		{"prefix out of scope", `<r><a xmlns:p="urn:p"/><p:b/></r>`, "malformed"},
		{"xmlns prefix declared", `<r xmlns:xmlns="urn:x"/>`, "malformed"},
		{"xml prefix rebound", `<r xmlns:xml="urn:x"/>`, "malformed"},
		{"XML namespace bound to another prefix", `<r xmlns:p="http://www.w3.org/XML/1998/namespace"/>`, "malformed"},
		{"xmlns namespace bound", `<r xmlns:p="http://www.w3.org/2000/xmlns/"/>`, "malformed"},
		{"xmlns namespace as default", `<r xmlns="http://www.w3.org/2000/xmlns/"/>`, "malformed"},
		{"XML namespace as default", `<r xmlns="http://www.w3.org/XML/1998/namespace"/>`, "malformed"},
		{"empty prefixed declaration", `<r xmlns:p=""/>`, "malformed"},
		{"element in the xml namespace", `<xml:r/>`, "malformed"},
		{"element in the xmlns namespace", `<xmlns:r/>`, "malformed"},
		{"invalid character reference", `<r>&#0;</r>`, "malformed"},
		{"not XML", `{"json":true}`, "malformed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, gateResult(checkXML([]byte(tc.doc), responseLimits)))
		})
	}
}

func TestCheckXML_Limits(t *testing.T) {
	t.Parallel()

	lim := responseLimits

	elements := func(n int) string {
		return "<r>" + strings.Repeat("<e/>", n-1) + "</r>"
	}

	cases := []struct {
		name, doc, want string
	}{
		{"elements at the cap", elements(lim.maxElements), "ok"},
		{"elements over the cap", elements(lim.maxElements + 1), "too-large"},
		{"depth at the cap", nested(lim.maxDepth), "ok"},
		{"depth over the cap", nested(lim.maxDepth + 1), "too-large"},
		{"attributes at the cap", `<r` + repeatAttrs(lim.maxAttrs, ` a%d="%d"`) + `/>`, "ok"},
		{"attributes over the cap", `<r` + repeatAttrs(lim.maxAttrs+1, ` a%d="%d"`) + `/>`, "too-large"},
		{"declarations at the cap", `<r` + repeatAttrs(lim.maxNSDecls, ` xmlns:p%d="urn:%d"`) + `/>`, "ok"},
		{"in-scope prefixes at the cap", `<r` + repeatAttrs(16, ` xmlns:p%d="urn:%d"`) + `><e` +
			repeatAttrs(16, ` xmlns:q%d="urn:%d"`) + `/></r>`, "ok"},
		{"in-scope prefixes over the cap", `<r` + repeatAttrs(16, ` xmlns:p%d="urn:%d"`) + `><e` +
			repeatAttrs(16, ` xmlns:q%d="urn:%d"`) + `><f xmlns:z="urn:z"/></e></r>`, "too-large"},
		{"redeclarations do not accumulate", strings.Repeat(`<e xmlns:x="urn:x" xmlns:y="urn:y">`, 40) +
			strings.Repeat(`</e>`, 40), "ok"},
		{"attribute value at the cap", `<r a="` + strings.Repeat("v", lim.maxAttrValueLen) + `"/>`, "ok"},
		{"attribute value over the cap", `<r a="` + strings.Repeat("v", lim.maxAttrValueLen+1) + `"/>`, "too-large"},
		{"tokens over the cap", `<r>` + strings.Repeat("<!---->", lim.maxTokens) + `</r>`, "too-large"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, gateResult(checkXML([]byte(tc.doc), lim)))
		})
	}
}

func TestCheckXML_SiblingScopesDoNotLeak(t *testing.T) {
	t.Parallel()

	// 30 siblings each declaring 2 prefixes: never more than 2 in scope.
	doc := "<r>" + strings.Repeat(`<e xmlns:x="urn:x" xmlns:y="urn:y"><x:a/></e>`, 30) + "</r>"
	require.NoError(t, checkXML([]byte(doc), responseLimits))
}

func TestCheckXML_ByteBound(t *testing.T) {
	t.Parallel()

	// The gate bounds the document size itself (code review F2).
	lim := responseLimits
	lim.maxBytes = 32

	doc := func(n int) []byte { return []byte("<r>" + strings.Repeat("x", n-len("<r></r>")) + "</r>") }

	assert.Equal(t, "ok", gateResult(checkXML(doc(32), lim)))
	assert.Equal(t, "too-large", gateResult(checkXML(doc(33), lim)))
	assert.Equal(t, int64(MaxMaxResponseSize), responseLimits.maxBytes, "responses: the configurable ceiling")
}

func TestGateError(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "DTD or directive", checkXML([]byte(`<!DOCTYPE r><r/>`), responseLimits).Error())
	assert.Equal(t, []byte("<r/>"), stripBOM([]byte("\xEF\xBB\xBF<r/>")))
	assert.Equal(t, []byte("<r/>"), stripBOM([]byte("<r/>")))
}

func TestCheckXML_DeclarationCapIndependentOfAttributeCap(t *testing.T) {
	t.Parallel()

	// With a higher attribute cap, the declaration cap still applies.
	lim := responseLimits
	lim.maxAttrs = 64

	assert.Equal(t, "ok", gateResult(checkXML([]byte(`<r`+repeatAttrs(lim.maxNSDecls, ` xmlns:p%d="urn:%d"`)+`/>`), lim)))
	assert.Equal(t, "too-large", gateResult(checkXML([]byte(`<r`+repeatAttrs(lim.maxNSDecls+1, ` xmlns:p%d="urn:%d"`)+`/>`), lim)))
}
