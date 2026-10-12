// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

// Size, depth, count and encoding limits of the corpus: for every lexical
// limit an at-cap fixture that must be accepted and an over-cap fixture
// that must be refused, so that an off-by-one in either direction fails.

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/require"
)

// algExcWithSpace is the exclusive C14N URI with a trailing space.
const algExcWithSpace = "http://www.w3.org/2001/10/xml-exc-c14n# "

// Lexical limits of the gate (xmlgate.go responseLimits).
const (
	capElements   = samlsp.MaxResponseElements
	capDepth      = 64
	capAttributes = 16
	capInScope    = 32
	capAttrValue  = 8 << 10
	capTokens     = 4096
)

// countElements counts the elements of an XML document.
func countXMLElements(t require.TestingT, data []byte) int {
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(data))

	n := 0

	var walk func(el *etree.Element)
	walk = func(el *etree.Element) {
		n++

		for _, c := range el.ChildElements() {
			walk(c)
		}
	}

	walk(doc.Root())

	return n
}

// countXMLTokens counts the raw tokens as the gate does.
func countXMLTokens(t require.TestingT, data []byte) int {
	dec := xml.NewDecoder(bytes.NewReader(data))
	n := 0

	for {
		_, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			return n
		}

		require.NoError(t, err)

		n++
	}
}

// gateShape measures what the gate counts: the most attributes on one
// element and the most distinct prefixes in scope at one element.
func gateShape(t require.TestingT, data []byte) (maxAttrs, maxInScope int) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	inScope := map[string]int{}

	var stack [][]string

	for {
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			return maxAttrs, maxInScope
		}

		require.NoError(t, err)

		switch e := tok.(type) {
		case xml.StartElement:
			maxAttrs = max(maxAttrs, len(e.Attr))

			var own []string

			for _, a := range e.Attr {
				if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
					p := a.Name.Local
					if a.Name.Space == "" {
						p = ""
					}

					inScope[p]++
					own = append(own, p)
				}
			}

			stack = append(stack, own)
			maxInScope = max(maxInScope, len(inScope))
		case xml.EndElement:
			for _, p := range stack[len(stack)-1] {
				if inScope[p]--; inScope[p] == 0 {
					delete(inScope, p)
				}
			}

			stack = stack[:len(stack)-1]
		}
	}
}

// extensions inserts, in the unsigned Response envelope (so exclusive
// C14N cannot prune unused declarations), a samlp:Extensions element
// carrying attrs, with nested children carrying nested[i] declarations
// each.
func extensions(attrs []string, nested ...int) func(r *etree.Element) {
	return func(r *etree.Element) {
		ext := etree.NewElement("samlp:Extensions")

		for i, a := range attrs {
			ext.CreateAttr(a, fmt.Sprintf("urn:example:e%d", i))
		}

		el, seq := ext, 0

		for _, n := range nested {
			el = el.CreateElement("samlp:Extensions")

			for i := 0; i < n; i++ {
				el.CreateAttr(fmt.Sprintf("xmlns:n%d", seq), fmt.Sprintf("urn:example:n%d", seq))
				seq++
			}
		}

		r.InsertChildAt(child(r, "Issuer").Index()+1, ext)
	}
}

// names returns n attribute names prefix0..prefixN-1.
func names(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}

	return out
}

// paddingAttribute adds an Attribute named name with n values "p".
func paddingAttribute(name string, n int) func(a *etree.Element) {
	return func(a *etree.Element) {
		attr := path(a, "AttributeStatement").CreateElement("saml:Attribute")
		attr.CreateAttr("Name", name)

		for i := 0; i < n; i++ {
			attr.CreateElement("saml:AttributeValue").SetText("p")
		}
	}
}

// withAttribute returns the baseline identity plus one attribute.
func withAttribute(attr samlsp.Attribute) samlsp.Identity {
	id := baselineIdentity()
	id.Attributes = append(id.Attributes, attr)

	return id
}

// repeated returns n copies of v.
func repeated(v string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = v
	}

	return out
}

func (g *corpusGen) cappedLimitSpecs() []corpusSpec {
	refs := []string{"#87 plan review F1/F2 (lexical gate)", refOWASP}

	// Elements: the padding attribute's own element plus n values.
	baseElements := countXMLElements(g.t, g.xml("acme", onAssertion(paddingAttribute("padding", 0))))
	pad := capElements - baseElements

	// Depth: AttributeValue sits at depth 5 (Response, Assertion,
	// AttributeStatement, Attribute, AttributeValue).
	nested := func(levels int) func(a *etree.Element) {
		return func(a *etree.Element) {
			attr := path(a, "AttributeStatement").CreateElement("saml:Attribute")
			attr.CreateAttr("Name", "depth")
			el := attr.CreateElement("saml:AttributeValue")
			first := true

			for i := 0; i < levels; i++ {
				el = el.CreateElement("x:n")
				if first {
					el.CreateAttr("xmlns:x", "urn:example:depth")
					first = false
				}
			}
		}
	}

	// Attributes and namespace declarations go to the unsigned envelope:
	// inside the signed assertion, exclusive C14N would prune the unused
	// declarations and the count would not be what the gate sees.
	measured := func(data []byte, wantAttrs, wantScope int) []byte {
		attrs, scope := gateShape(g.t, data)
		if wantAttrs > 0 {
			require.Equal(g.t, wantAttrs, attrs, "attributes on the busiest element")
		}

		if wantScope > 0 {
			require.Equal(g.t, wantScope, scope, "prefixes in scope")
		}

		return data
	}
	// In the Extensions chain, the prefixes in scope are the Response
	// root's declarations plus the chain's own.
	rootDoc := etree.NewDocument()
	require.NoError(g.t, rootDoc.ReadFromBytes(g.xml("acme", respOpts{})))

	baseScope := 0

	for _, a := range rootDoc.Root().Attr {
		if a.Space == "xmlns" || a.Space == "" && a.Key == "xmlns" {
			baseScope++
		}
	}

	attrValue := func(n int) func(a *etree.Element) {
		return func(a *etree.Element) {
			path(a, "AttributeStatement", "Attribute", "AttributeValue").CreateAttr("pad", strings.Repeat("v", n))
		}
	}

	// Tokens: comments in the (unsigned) Response envelope.
	baseTokens := countXMLTokens(g.t, g.xml("acme", respOpts{}))
	comments := func(n int) func(r *etree.Element) {
		return func(r *etree.Element) {
			at := child(r, "Status").Index()
			for i := 0; i < n; i++ {
				r.InsertChildAt(at, etree.NewComment("p"))
			}
		}
	}

	depthIdentity := withAttribute(samlsp.Attribute{Name: "depth", Values: []string{""}})

	return []corpusSpec{
		{
			id: "limits/elements-at-cap", attack: fmt.Sprintf("exactly %d elements (MaxResponseElements)", capElements), refs: refs,
			build: func() []byte {
				data := g.xml("acme", onAssertion(paddingAttribute("padding", pad)))
				require.Equal(g.t, capElements, countXMLElements(g.t, data))

				return data
			},
			expect: accepted(withAttribute(samlsp.Attribute{Name: "padding", Values: repeated("p", pad)})),
		},
		{
			id: "limits/elements-over-cap", attack: fmt.Sprintf("%d elements", capElements+1), refs: refs,
			build:  func() []byte { return g.xml("acme", onAssertion(paddingAttribute("padding", pad+1))) },
			expect: rejected("ErrResponseTooLarge", "too many XML elements"),
		},
		{
			id: "limits/depth-at-cap", attack: fmt.Sprintf("nesting depth %d", capDepth), refs: refs,
			build:  func() []byte { return g.xml("acme", onAssertion(nested(capDepth-5))) },
			expect: accepted(depthIdentity),
		},
		{
			id: "limits/depth-over-cap", attack: fmt.Sprintf("nesting depth %d", capDepth+1), refs: refs,
			build:  func() []byte { return g.xml("acme", onAssertion(nested(capDepth-4))) },
			expect: rejected("ErrResponseTooLarge", "XML nesting too deep"),
		},
		{
			id: "limits/attributes-at-cap", attack: fmt.Sprintf("%d attributes on one element", capAttributes), refs: refs,
			build: func() []byte {
				return measured(g.xml("acme", onResponse(extensions(names("a", capAttributes)))), capAttributes, 0)
			},
			expect: accepted(baselineIdentity()),
		},
		{
			id: "limits/attributes-over-cap", attack: fmt.Sprintf("%d attributes on one element", capAttributes+1), refs: refs,
			build: func() []byte {
				return measured(g.xml("acme", onResponse(extensions(names("a", capAttributes+1)))), capAttributes+1, 0)
			},
			expect: rejected("ErrResponseTooLarge", "too many attributes on an element"),
		},
		{
			id: "limits/namespace-declarations-at-cap", attack: fmt.Sprintf("%d namespace declarations on one element", capAttributes),
			refs: refs,
			build: func() []byte {
				return measured(g.xml("acme", onResponse(extensions(names("xmlns:d", capAttributes)))), capAttributes, 0)
			},
			expect: accepted(baselineIdentity()),
		},
		{
			id: "limits/prefixes-in-scope-at-cap", attack: fmt.Sprintf("%d distinct prefixes in scope", capInScope), refs: refs,
			build: func() []byte {
				extra := capInScope - baseScope
				return measured(g.xml("acme", onResponse(extensions(nil, capAttributes, extra-capAttributes))), 0, capInScope)
			},
			expect: accepted(baselineIdentity()),
		},
		{
			id: "limits/prefixes-in-scope-over-cap", attack: fmt.Sprintf("%d distinct prefixes in scope", capInScope+1), refs: refs,
			build: func() []byte {
				extra := capInScope + 1 - baseScope
				return measured(g.xml("acme", onResponse(extensions(nil, capAttributes, extra-capAttributes))), 0, capInScope+1)
			},
			expect: rejected("ErrResponseTooLarge", "too many namespace prefixes in scope"),
		},
		{
			id: "limits/attribute-value-at-cap", attack: fmt.Sprintf("a %d-byte attribute value", capAttrValue), refs: refs,
			build:  func() []byte { return g.xml("acme", onAssertion(attrValue(capAttrValue))) },
			expect: accepted(baselineIdentity()),
		},
		{
			id: "limits/attribute-value-over-cap", attack: fmt.Sprintf("a %d-byte attribute value", capAttrValue+1), refs: refs,
			build:  func() []byte { return g.xml("acme", onAssertion(attrValue(capAttrValue+1))) },
			expect: rejected("ErrResponseTooLarge", "attribute value too long"),
		},
		{
			id: "limits/tokens-at-cap", attack: fmt.Sprintf("exactly %d XML tokens", capTokens), refs: refs,
			build: func() []byte {
				data := g.xml("acme", onResponse(comments(capTokens-baseTokens)))
				require.Equal(g.t, capTokens, countXMLTokens(g.t, data))

				return data
			},
			expect: accepted(baselineIdentity()),
		},
		{
			id: "limits/tokens-over-cap", attack: fmt.Sprintf("%d XML tokens", capTokens+1), refs: refs,
			build:  func() []byte { return g.xml("acme", onResponse(comments(capTokens-baseTokens+1))) },
			expect: rejected("ErrResponseTooLarge", "too many XML tokens"),
		},
		{
			id: "limits/attacker-signed-attribute-flood", attack: "900 attribute values signed by an attacker key (verifier traversal budget)",
			refs: refs,
			build: func() []byte {
				return g.xml("acme", respOpts{
					assertionSig:    sigOpts{signer: g.keys["attacker"]},
					beforeAssertion: paddingAttribute("flood", 900),
				})
			},
			expect: rejected("ErrResponseTooLarge", "too many XML elements"),
		},
		{
			id: "limits/namespace-declaration-flood", attack: "16 000 namespace declarations on the Response (goxmldsig SubContext amplification)",
			refs: append(refs, "#87 plan review F1"), knobs: corpusKnobs{MaxResponseSize: samlsp.MaxMaxResponseSize},
			build: func() []byte {
				var b strings.Builder
				for i := 0; i < 16000; i++ {
					fmt.Fprintf(&b, ` xmlns:p%d="urn:p:%d"`, i, i)
				}

				return []byte(strings.Replace(string(g.xml("acme", compact(respOpts{}))), "<samlp:Response ", "<samlp:Response"+b.String()+" ", 1))
			},
			expect: rejected("ErrResponseTooLarge", "too many attributes on an element"),
		},
		{
			id: "limits/prefixed-attribute-flood", attack: "2 000 prefixed attributes on one element (round-trip validator)",
			refs: refs, knobs: corpusKnobs{MaxResponseSize: samlsp.MaxMaxResponseSize},
			build: func() []byte {
				var b strings.Builder
				b.WriteString(` xmlns:p="urn:p"`)
				for i := 0; i < 2000; i++ {
					fmt.Fprintf(&b, ` p:a%d="v"`, i)
				}

				return []byte(strings.Replace(string(g.xml("acme", compact(respOpts{}))), "<samlp:Status>", "<samlp:Status"+b.String()+">", 1))
			},
			expect: rejected("ErrResponseTooLarge", "too many attributes on an element"),
		},
		{
			id: "limits/empty-element-flood", attack: "16 000 empty elements", refs: refs,
			knobs: corpusKnobs{MaxResponseSize: samlsp.MaxMaxResponseSize},
			build: func() []byte {
				return []byte(strings.Replace(string(g.xml("acme", compact(respOpts{}))), "<samlp:Status>",
					strings.Repeat("<samlp:Extensions/>", 16000)+"<samlp:Status>", 1))
			},
			expect: rejected("ErrResponseTooLarge", "too many XML elements"),
		},
		{
			id: "limits/body-over-max-response-size", attack: "a 300 KiB comment pushes the request over MaxResponseSize (256 KiB)",
			refs: append(refs, "#87 code review F2 (pre-parsed forms)"),
			build: func() []byte {
				return []byte(strings.Replace(string(g.xml("acme", compact(respOpts{}))), "<samlp:Status>",
					"<!--"+strings.Repeat("x", 300<<10)+"--><samlp:Status>", 1))
			},
			expect: corpusExpect{
				Outcome: outcomeRejected, Sentinel: "ErrResponseTooLarge",
				Detail: "request body over MaxResponseSize", PreparsedDetail: "SAMLResponse over MaxResponseSize",
			},
		},
	}
}

func (g *corpusGen) encodingLimitSpecs() []corpusSpec {
	refs := []string{"SAML Bindings §3.5.4 (HTTP-POST is base64, never DEFLATE)", "gosaml2 GHSA-6gc3-crp7-25w5 (DEFLATE bomb)"}
	baseline := func() []byte { return g.xml("acme", respOpts{}) }

	return []corpusSpec{
		{
			id: "limits/deflated-post", attack: "DEFLATE-encoded SAMLResponse on the POST binding (never inflated)", refs: refs,
			knobs: corpusKnobs{Encoding: "deflate"}, build: baseline, file: "baseline/assertion-signed.xml.gz",
			expect: rejected("ErrMalformedResponse", "not well-formed XML"),
		},
		{
			id: "limits/gzip-post", attack: "gzip-encoded SAMLResponse", refs: refs,
			knobs: corpusKnobs{Encoding: "gzip"}, build: baseline, file: "baseline/assertion-signed.xml.gz",
			expect: rejected("ErrMalformedResponse", "not well-formed XML"),
		},
		{
			id: "limits/deflate-bomb", attack: "base64 of 10 MiB of zeros deflated to a few KiB (decompression bomb)", refs: refs,
			knobs: corpusKnobs{Encoding: "asis"},
			build: func() []byte {
				var buf bytes.Buffer

				fw, err := flate.NewWriter(&buf, flate.BestCompression)
				require.NoError(g.t, err)
				_, err = fw.Write(make([]byte, 10<<20))
				require.NoError(g.t, err)
				require.NoError(g.t, fw.Close())

				return []byte(base64.StdEncoding.EncodeToString(buf.Bytes()))
			},
			expect: rejected("ErrMalformedResponse", "not well-formed XML"),
		},
		{
			id: "limits/not-base64", attack: "SAMLResponse that is not base64", refs: refs,
			knobs: corpusKnobs{Encoding: "garbage"}, build: baseline, file: "baseline/assertion-signed.xml.gz",
			expect: rejected("ErrMalformedResponse", "SAMLResponse is not base64"),
		},
		{
			id: "limits/spaces-in-base64", attack: "spaces inside the base64", refs: refs,
			knobs: corpusKnobs{Encoding: "spaces"}, build: baseline, file: "baseline/assertion-signed.xml.gz",
			expect: rejected("ErrMalformedResponse", "SAMLResponse is not base64"),
		},
		{
			id: "limits/line-wrapped-base64", attack: "base64 wrapped at 76 characters with CRLF (Bindings §3.5.4 tolerance)",
			refs: refs, knobs: corpusKnobs{Encoding: "wrapped76"}, build: baseline, file: "baseline/assertion-signed.xml.gz",
			expect: accepted(baselineIdentity()),
		},
	}
}
