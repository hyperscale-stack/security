// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// xmlLimits bounds the shape of an untrusted XML document before it is
// parsed into a tree, canonicalized or verified. They exist because the
// cost of goxmldsig's namespace-aware traversals, of its canonicalization
// and of the round-trip validator gosaml2 runs grows with the number of
// elements times the number of in-scope prefixes, and with the number of
// attributes per element (plan review F1/F2).
type xmlLimits struct {
	maxElements     int // whole document
	maxTokens       int // whole document: elements, text, comments, ...
	maxDepth        int
	maxAttrs        int   // per element, namespace declarations included
	maxNSDecls      int   // per element
	maxInScope      int   // distinct prefixes in scope at any element
	maxAttrValueLen int   // bytes
	maxBytes        int64 // whole document
}

// MaxResponseElements is the most elements a SAMLResponse may contain.
// goxmldsig v1.6.1 gives each namespace-aware traversal a budget of 1 000
// nodes and gosaml2 v0.12.0 spends it twice on the assertion subtree
// (detach, then descent), so a response of up to this many elements always
// fits the budget whatever is signed; a larger one is refused with
// [ErrResponseTooLarge] before any signature work. Identity providers that
// emit very large attribute lists (hundreds of group values) must filter
// them; see LIMITATIONS.md.
const MaxResponseElements = 450

// responseLimits apply to every SAMLResponse.
// Mainstream IdPs put at most about 11 attributes, namespace declarations
// included, on an element (the Response root); 16 leaves headroom while
// halving the attribute volume an attacker can feed to the verifier.
var responseLimits = xmlLimits{
	maxElements:     MaxResponseElements,
	maxTokens:       4096,
	maxDepth:        64,
	maxAttrs:        16,
	maxNSDecls:      16,
	maxInScope:      32,
	maxAttrValueLen: 8 << 10,
	maxBytes:        MaxMaxResponseSize,
}

// metadataLimits apply to imported IdP metadata, which is configuration
// rather than attacker traffic but still bounded (maxBytes is the
// MetadataOptions.MaxSize of the call).
var metadataLimits = xmlLimits{
	maxElements:     20000,
	maxTokens:       100000,
	maxDepth:        64,
	maxAttrs:        64,
	maxNSDecls:      64,
	maxInScope:      64,
	maxAttrValueLen: 64 << 10,
}

// gateError is a refusal of the lexical gate: tooLarge distinguishes
// resource limits from malformed input. The message is static.
type gateError struct {
	tooLarge bool
	msg      string
}

func (e *gateError) Error() string { return e.msg }

func gateMalformed(msg string) error { return &gateError{msg: msg} }
func gateTooLarge(msg string) error  { return &gateError{tooLarge: true, msg: msg} }

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// stripBOM removes a leading UTF-8 byte order mark.
func stripBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, utf8BOM)
}

// Reserved prefixes (Namespaces in XML 1.0 §3).
const (
	prefixXML   = "xml"
	prefixXMLNS = "xmlns"
)

// nsScope tracks the prefixes in scope while streaming: for each prefix the
// stack of URIs it is bound to, innermost last.
type nsScope map[string][]string

func (s nsScope) push(own map[string]string) {
	for p, u := range own {
		s[p] = append(s[p], u)
	}
}

func (s nsScope) pop(own map[string]string) {
	for p := range own {
		st := s[p][:len(s[p])-1]
		if len(st) == 0 {
			delete(s, p)

			continue
		}

		s[p] = st
	}
}

// lookup resolves a prefix; "xml" is implicitly bound (Namespaces §3).
func (s nsScope) lookup(prefix string) (string, bool) {
	if prefix == prefixXML {
		return nsXML, true
	}

	st := s[prefix]
	if len(st) == 0 {
		return "", false
	}

	return st[len(st)-1], true
}

// gateFrame is an open element.
type gateFrame struct {
	name xml.Name // raw name (prefix in Space)
	ns   string   // namespace URI the name resolves to ("" for none)
	own  map[string]string
}

// keyInfoPosition is a place of a response where the gate records a
// ds:KeyInfo: the only two places a signature may sit (pre-check).
type keyInfoPosition int

const (
	keyInfoResponse  keyInfoPosition = iota + 1 // Response/Signature/KeyInfo
	keyInfoAssertion                            // Response/Assertion/Signature/KeyInfo
)

// keyInfoSpan is a ds:KeyInfo the gate met at a keyInfoPosition: its bytes
// are data[start:end], its raw name qname, and hasCert reports a descendant
// element named X509Certificate in any namespace — wider than the XML-DSig
// namespace goxmldsig reads it from, so that a KeyInfo goxmldsig could take
// a certificate from is never cut.
type keyInfoSpan struct {
	pos        keyInfoPosition
	start, end int64
	qname      string
	hasCert    bool
}

// gateScan is what the gate learned while streaming a document.
type gateScan struct {
	keyInfo []keyInfoSpan
}

// gate streams data with a strict encoding/xml decoder (no entity map, no
// charset conversion: a declared encoding other than UTF-8 is refused) and
// enforces XML hygiene and the limits before the document is turned into a
// tree. It refuses documents over maxBytes, DOCTYPE and every other
// directive, processing instructions other than a leading XML declaration,
// text outside the root, more than one root, two attributes of one local
// name on an element (whatever their prefixes, namespace declarations
// included), prefixed ID attributes other than xml:id, undeclared prefixes, misuse of
// the reserved xml/xmlns prefixes and namespaces, empty prefixed
// declarations, and names that are not namespace-well-formed (an empty
// prefix or local part).
type gate struct {
	lim      xmlLimits
	scope    nsScope
	stack    []gateFrame
	elements int
	rootSeen bool
	scan     gateScan
	// openKeyInfo is the index in scan.keyInfo of the ds:KeyInfo being
	// read, -1 when none.
	openKeyInfo int
}

// checkXML runs the gate over data (BOM already stripped).
func checkXML(data []byte, lim xmlLimits) error {
	_, err := scanXML(data, lim)

	return err
}

// scanXML runs the gate over data (BOM already stripped) and returns what
// it recorded on the way.
func scanXML(data []byte, lim xmlLimits) (*gateScan, error) {
	if int64(len(data)) > lim.maxBytes {
		return nil, gateTooLarge("XML document too large")
	}

	g := &gate{lim: lim, scope: nsScope{}, openKeyInfo: -1}

	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true

	for tokens := 0; ; tokens++ {
		// InputOffset is the end of the previous token, so the start of
		// this one; after RawToken, the end of this one.
		start := dec.InputOffset()

		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, gateMalformed("not well-formed XML")
		}

		if tokens >= lim.maxTokens {
			return nil, gateTooLarge("too many XML tokens")
		}

		if err := g.token(tok, tokens == 0, start, dec.InputOffset()); err != nil {
			return nil, err
		}
	}

	if !g.rootSeen || len(g.stack) != 0 {
		return nil, gateMalformed("missing or unclosed root element")
	}

	return &g.scan, nil
}

// token checks one token spanning data[start:end].
func (g *gate) token(tok xml.Token, first bool, start, end int64) error {
	switch t := tok.(type) {
	case xml.StartElement:
		return g.start(t, start)
	case xml.EndElement:
		return g.end(t, end)
	case xml.CharData:
		if len(g.stack) == 0 && !isXMLSpace(t) {
			return gateMalformed("text outside the root element")
		}
	case xml.ProcInst:
		if t.Target != prefixXML || !first {
			return gateMalformed("processing instruction")
		}
	case xml.Directive:
		return gateMalformed("DTD or directive")
	}

	return nil
}

// isXMLSpace reports whether b only holds XML white space (XML 1.0 §2.3 S).
func isXMLSpace(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}

	return true
}

// start checks a start tag found at offset and opens its namespace scope.
func (g *gate) start(t xml.StartElement, offset int64) error {
	if len(g.stack) == 0 {
		if g.rootSeen {
			return gateMalformed("more than one root element")
		}

		g.rootSeen = true
	}

	g.elements++

	switch {
	case g.elements > g.lim.maxElements:
		return gateTooLarge("too many XML elements")
	case len(g.stack)+1 > g.lim.maxDepth:
		return gateTooLarge("XML nesting too deep")
	case len(t.Attr) > g.lim.maxAttrs:
		return gateTooLarge("too many attributes on an element")
	}

	if !wellFormedName(t.Name) {
		return gateMalformed(errNotNSWellFormed)
	}

	own, err := g.declarations(t.Attr)
	if err != nil {
		return err
	}

	g.scope.push(own)
	g.stack = append(g.stack, gateFrame{name: t.Name, own: own})

	if len(g.scope) > g.lim.maxInScope {
		return gateTooLarge("too many namespace prefixes in scope")
	}

	if err := g.checkElementName(t.Name); err != nil {
		return err
	}

	if err := g.checkAttributes(t.Attr); err != nil {
		return err
	}

	g.trackKeyInfo(t.Name, offset)

	return nil
}

// trackKeyInfo resolves the namespace of the element just opened (the
// default namespace included) and records a ds:KeyInfo found at a
// keyInfoPosition, or an X509Certificate inside the one being read. The
// pre-check cross-checks these records with its own tree before any
// KeyInfo is cut (Core §5.4.5; see precheck_keyinfo.go).
func (g *gate) trackKeyInfo(n xml.Name, offset int64) {
	top := &g.stack[len(g.stack)-1]
	top.ns, _ = g.scope.lookup(n.Space)

	if g.openKeyInfo >= 0 && n.Local == tagX509Certificate {
		g.scan.keyInfo[g.openKeyInfo].hasCert = true
	}

	pos := g.keyInfoPosition()
	if pos == 0 {
		return
	}

	qname := n.Local
	if n.Space != "" {
		qname = n.Space + ":" + n.Local
	}

	g.scan.keyInfo = append(g.scan.keyInfo, keyInfoSpan{pos: pos, start: offset, qname: qname})
	g.openKeyInfo = len(g.scan.keyInfo) - 1
}

// keyInfoPosition reports where the element on top of the stack is, when it
// is a ds:KeyInfo child of the ds:Signature of the root Response or of an
// Assertion child of that root; 0 otherwise.
func (g *gate) keyInfoPosition() keyInfoPosition {
	is := func(f gateFrame, ns, local string) bool { return f.ns == ns && f.name.Local == local }

	st := g.stack

	switch {
	case !is(st[len(st)-1], nsDSig, "KeyInfo") || !is(st[0], nsProtocol, "Response"):
		return 0
	case len(st) == 3 && is(st[1], nsDSig, tagSignature):
		return keyInfoResponse
	case len(st) == 4 && is(st[1], nsAssertion, "Assertion") && is(st[2], nsDSig, tagSignature):
		return keyInfoAssertion
	default:
		return 0
	}
}

// declarations collects the namespace declarations of a start tag and
// checks their count, the reserved names, the attribute value lengths and
// the uniqueness of local names.
//
// Two attributes of one local name are refused whatever their prefixes:
// etree's SelectAttr returns the first in document order, encoding/xml
// (with which goxmldsig and gosaml2 decode) the last, and exclusive C14N
// reorders them, so readers could disagree on the value (code review F3).
// Namespace declarations count: encoding/xml matches xmlns:Algorithm
// against an Algorithm field too.
func (g *gate) declarations(attrs []xml.Attr) (map[string]string, error) {
	own := map[string]string{}
	locals := make(map[string]struct{}, len(attrs))

	for _, a := range attrs {
		if !wellFormedName(a.Name) {
			return nil, gateMalformed(errNotNSWellFormed)
		}

		if _, dup := locals[a.Name.Local]; dup {
			return nil, gateMalformed("two attributes of one local name")
		}

		locals[a.Name.Local] = struct{}{}

		if len(a.Value) > g.lim.maxAttrValueLen {
			return nil, gateTooLarge("attribute value too long")
		}

		prefix, isDecl := declaredPrefix(a.Name)
		if !isDecl {
			continue
		}

		if err := checkDeclaration(prefix, a.Value); err != nil {
			return nil, err
		}

		own[prefix] = a.Value
	}

	if len(own) > g.lim.maxNSDecls {
		return nil, gateTooLarge("too many namespace declarations on an element")
	}

	return own, nil
}

// errNotNSWellFormed refuses a name whose prefix or local part is empty.
const errNotNSWellFormed = "name not namespace-well-formed"

// wellFormedName reports whether n is a QName of Namespaces in XML 1.0 §3:
// a prefix, when present, and a local part that are both non-empty. The
// raw tokenizer splits a name at its colon only when both parts are
// non-empty, and keeps any other name whole, colon included, in no
// namespace (a name with two colons is a syntax error): such a document is
// not namespace-well-formed (§7), and readers could disagree on it.
func wellFormedName(n xml.Name) bool { return !strings.Contains(n.Local, ":") }

// declaredPrefix reports whether an attribute is a namespace declaration
// and which prefix it declares ("" for the default namespace).
func declaredPrefix(n xml.Name) (string, bool) {
	switch {
	case n.Space == prefixXMLNS:
		return n.Local, true
	case n.Space == "" && n.Local == prefixXMLNS:
		return "", true
	default:
		return "", false
	}
}

// checkDeclaration enforces Namespaces in XML 1.0 §3 constraints on a
// declaration.
func checkDeclaration(prefix, uri string) error {
	switch {
	case prefix == prefixXMLNS:
		return gateMalformed("declaration of the reserved xmlns prefix")
	case prefix == prefixXML && uri != nsXML:
		return gateMalformed("rebinding of the reserved xml prefix")
	case prefix != prefixXML && uri == nsXML:
		return gateMalformed("binding of the XML namespace to another prefix")
	case uri == nsXMLNS:
		return gateMalformed("binding of the xmlns namespace")
	case prefix != "" && uri == "":
		return gateMalformed("empty prefixed namespace declaration")
	}

	return nil
}

// checkElementName requires a declared, non-reserved element prefix.
func (g *gate) checkElementName(n xml.Name) error {
	if n.Space == "" {
		return nil
	}

	if n.Space == prefixXML || n.Space == prefixXMLNS {
		return gateMalformed("element in a reserved namespace")
	}

	if _, ok := g.scope.lookup(n.Space); !ok {
		return gateMalformed("undeclared namespace prefix")
	}

	return nil
}

// checkAttributes requires declared attribute prefixes and refuses prefixed
// ID attributes other than xml:id. Unique local names (checked by
// declarations) imply the Namespaces §6.3 uniqueness.
func (g *gate) checkAttributes(attrs []xml.Attr) error {
	for _, a := range attrs {
		if _, isDecl := declaredPrefix(a.Name); isDecl || a.Name.Space == "" {
			continue
		}

		if _, ok := g.scope.lookup(a.Name.Space); !ok {
			return gateMalformed("undeclared namespace prefix")
		}

		if isIDName(a.Name.Local) && (a.Name.Space != prefixXML || a.Name.Local != "id") {
			return gateMalformed("prefixed ID attribute")
		}
	}

	return nil
}

// isIDName reports the local names goxmldsig, etree or XML-DSig may treat
// as identifiers.
func isIDName(local string) bool {
	return local == "ID" || local == "Id" || local == "id"
}

// end checks that an end tag, ending at offset, matches its start tag and
// closes its scope.
func (g *gate) end(t xml.EndElement, offset int64) error {
	if len(g.stack) == 0 {
		return gateMalformed("unbalanced end tag")
	}

	top := g.stack[len(g.stack)-1]
	if top.name != t.Name {
		return gateMalformed("mismatched end tag")
	}

	if g.openKeyInfo >= 0 && g.keyInfoPosition() != 0 {
		g.scan.keyInfo[g.openKeyInfo].end = offset
		g.openKeyInfo = -1
	}

	g.stack = g.stack[:len(g.stack)-1]
	g.scope.pop(top.own)

	return nil
}
