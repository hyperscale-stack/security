// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"errors"
	"strings"

	"github.com/beevik/etree"
)

// maxInclusivePrefixes bounds an InclusiveNamespaces PrefixList (it can
// only name in-scope prefixes, at most 32 of them).
const maxInclusivePrefixes = 32

// Algorithm policy (Core §5.4, errata E81 lets the deployer choose). SHA-1
// is only accepted from a connection that opted in; inclusive C14N, HMAC,
// DSA and anything unknown never are. goxmldsig has no allowlist of its
// own: the policy is enforced here, on every signature, before it runs.
var (
	signatureMethods = map[string]bool{
		algRSASHA256: true, algRSASHA384: true, algRSASHA512: true,
		algECDSASHA256: true, algECDSASHA384: true, algECDSASHA512: true,
	}
	sha1SignatureMethods = map[string]bool{algRSASHA1: true, algECDSASHA1: true}
	digestMethods        = map[string]bool{algDigestSHA256: true, algDigestSHA384: true, algDigestSHA512: true}
	canonicalizations    = map[string]bool{algExcC14N: true, algExcC14NComments: true}
)

// signaturePolicy evaluates algorithms for one connection.
type signaturePolicy struct{ allowSHA1 bool }

func (p signaturePolicy) signatureMethod(alg string) bool {
	return signatureMethods[alg] || (p.allowSHA1 && sha1SignatureMethods[alg])
}

func (p signaturePolicy) digestMethod(alg string) bool {
	return digestMethods[alg] || (p.allowSHA1 && alg == algDigestSHA1)
}

// errSignatureStructure is the detail of every structural refusal.
const errSignatureStructure = "signature does not follow the SAML XML-DSig profile"

func invalidSignature(detail string) error { return reject(ErrInvalidSignature, detail, nil) }

func unsupportedAlgorithm() error { return reject(ErrUnsupportedAlgorithm, "", nil) }

// checkSignatures enforces the SAML XML-DSig profile (Core §5.4 and errata
// E91) on every signature of the document and records in raw whether the
// Response is signed, whether a signature lacks KeyInfo, and the KeyInfo of
// each signature. Signatures may only be enveloped in the Response or in its
// single Assertion (one each), their content must be in the XML-DSig
// namespace, carry exactly one Reference to their parent's ID, the
// transforms [enveloped, exclusive C14N] in that order, and allowed
// algorithms. An element named Signature in another namespace is refused so
// that no namespace trick hides a signature from these checks.
func checkSignatures(root, assertion *etree.Element, allowSHA1 bool, raw *rawResponse) error {
	policy := signaturePolicy{allowSHA1: allowSHA1}
	signed := map[*etree.Element]bool{}

	err := walk(root, func(el *etree.Element) error {
		if el.Tag != tagSignature {
			return nil
		}

		if el.NamespaceURI() != nsDSig {
			return invalidSignature("Signature element outside the XML-DSig namespace")
		}

		parent := el.Parent()
		if (parent != root && parent != assertion) || signed[parent] {
			return invalidSignature("misplaced or repeated signature")
		}

		signed[parent] = true

		keyInfo, err := checkSignature(el, attrValue(parent, "ID"), policy)
		if err != nil {
			return err
		}

		pos := keyInfoAssertion
		if parent == root {
			pos, raw.responseSigned = keyInfoResponse, true
		}

		raw.keyInfo[pos] = keyInfoState{present: keyInfo != nil, certless: keyInfo != nil && !holdsCertificate(keyInfo)}
		raw.keyInfoMissing = raw.keyInfoMissing || keyInfo == nil

		return nil
	})
	if err != nil {
		return err
	}

	if len(signed) == 0 {
		return invalidSignature("neither the Response nor the Assertion is signed")
	}

	return nil
}

// holdsCertificate reports whether a KeyInfo holds an element named
// X509Certificate, in any namespace: wider than the XML-DSig namespace
// goxmldsig reads it from, so a KeyInfo it could take a certificate from is
// never treated as certificate-less.
func holdsCertificate(keyInfo *etree.Element) bool {
	return walk(keyInfo, func(el *etree.Element) error {
		if el != keyInfo && el.Tag == tagX509Certificate {
			return errFound
		}

		return nil
	}) != nil
}

// errFound stops a walk once its target is found.
var errFound = errors.New("found")

// dsigChildren returns el's children, which must all be XML-DSig elements
// with distinct names from allowed.
func dsigChildren(el *etree.Element, allowed ...string) (map[string]*etree.Element, error) {
	out := map[string]*etree.Element{}

	for _, c := range el.ChildElements() {
		if c.NamespaceURI() != nsDSig || !contains(allowed, c.Tag) {
			return nil, invalidSignature(errSignatureStructure)
		}

		if _, dup := out[c.Tag]; dup {
			return nil, invalidSignature(errSignatureStructure)
		}

		out[c.Tag] = c
	}

	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}

	return false
}

// checkSignature checks one ds:Signature (no ds:Object, errata E91) and
// returns its KeyInfo (nil when absent).
func checkSignature(sig *etree.Element, parentID string, policy signaturePolicy) (*etree.Element, error) {
	parts, err := dsigChildren(sig, "SignedInfo", "SignatureValue", "KeyInfo")
	if err != nil {
		return nil, err
	}

	signedInfo, value := parts["SignedInfo"], parts["SignatureValue"]
	if signedInfo == nil || value == nil || len(value.ChildElements()) != 0 {
		return nil, invalidSignature(errSignatureStructure)
	}

	if err := checkSignedInfo(signedInfo, parentID, policy); err != nil {
		return nil, err
	}

	return parts["KeyInfo"], nil
}

// checkSignedInfo checks the canonicalization, the signature method and the
// single Reference (Core §5.4.2).
func checkSignedInfo(si *etree.Element, parentID string, policy signaturePolicy) error {
	parts, err := dsigChildren(si, "CanonicalizationMethod", "SignatureMethod", "Reference")
	if err != nil {
		return err
	}

	c14n, method, ref := parts["CanonicalizationMethod"], parts["SignatureMethod"], parts["Reference"]
	if c14n == nil || method == nil || ref == nil {
		return invalidSignature(errSignatureStructure)
	}

	if !canonicalizations[algorithm(c14n)] {
		return unsupportedAlgorithm()
	}

	if err := checkInclusiveNamespaces(c14n); err != nil {
		return err
	}

	if !policy.signatureMethod(algorithm(method)) {
		return unsupportedAlgorithm()
	}

	if len(method.ChildElements()) != 0 {
		return invalidSignature(errSignatureStructure)
	}

	return checkReference(ref, parentID, policy)
}

// algorithm returns the Algorithm attribute.
func algorithm(el *etree.Element) string { return attrValue(el, "Algorithm") }

// checkInclusiveNamespaces allows at most one exc-c14n InclusiveNamespaces
// child with a bounded PrefixList.
func checkInclusiveNamespaces(el *etree.Element) error {
	kids := el.ChildElements()

	switch {
	case len(kids) == 0:
		return nil
	case len(kids) > 1 || !inNS(kids[0], nsExcC14N, "InclusiveNamespaces") || len(kids[0].ChildElements()) != 0:
		return invalidSignature(errSignatureStructure)
	case len(strings.Fields(attrValue(kids[0], "PrefixList"))) > maxInclusivePrefixes:
		return invalidSignature("too many inclusive namespace prefixes")
	}

	return nil
}

// checkReference requires URI = "#" + the signed element's ID, the
// transforms [enveloped-signature, exclusive C14N] and an allowed digest.
func checkReference(ref *etree.Element, parentID string, policy signaturePolicy) error {
	if uri, ok := attr(ref, "URI"); parentID == "" || !ok || uri != "#"+parentID {
		return invalidSignature("the Reference does not point at the signed element")
	}

	parts, err := dsigChildren(ref, "Transforms", "DigestMethod", "DigestValue")
	if err != nil {
		return err
	}

	transforms, digest, value := parts["Transforms"], parts["DigestMethod"], parts["DigestValue"]
	if transforms == nil || digest == nil || value == nil || len(value.ChildElements()) != 0 {
		return invalidSignature(errSignatureStructure)
	}

	if err := checkTransforms(transforms); err != nil {
		return err
	}

	if !policy.digestMethod(algorithm(digest)) {
		return unsupportedAlgorithm()
	}

	if len(digest.ChildElements()) != 0 {
		return invalidSignature(errSignatureStructure)
	}

	return nil
}

// checkTransforms requires exactly [enveloped-signature, exc-c14n] in that
// order (Core §5.4.4): without the canonicalization transform goxmldsig
// would fall back to its non-standard Null canonicalizer (plan review F5).
func checkTransforms(tr *etree.Element) error {
	list := tr.ChildElements()
	if len(list) != 2 {
		return invalidSignature("transforms must be exactly enveloped-signature then exclusive C14N")
	}

	for _, t := range list {
		if !inNS(t, nsDSig, "Transform") {
			return invalidSignature(errSignatureStructure)
		}
	}

	if algorithm(list[0]) != algEnvelopedSigning || len(list[0].ChildElements()) != 0 {
		return invalidSignature("transforms must be exactly enveloped-signature then exclusive C14N")
	}

	if !canonicalizations[algorithm(list[1])] {
		return unsupportedAlgorithm()
	}

	return checkInclusiveNamespaces(list[1])
}
