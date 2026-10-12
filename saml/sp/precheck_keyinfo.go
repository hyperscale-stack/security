// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"cmp"
	"slices"
)

// Core §5.4.5: "SAML does not require the use of <ds:KeyInfo>, nor does it
// impose any restrictions on its use". goxmldsig, however, refuses a
// KeyInfo that carries no X509Certificate ("missing X509Certificate within
// KeyInfo"), even when the connection trusts a single certificate, and has
// no option to ignore KeyInfo. Such a KeyInfo selects nothing, so it is cut
// from the bytes to verify, and the signature is then KeyInfo-less: the
// trusted certificates are tried as for an absent KeyInfo.
//
// The cut is neutral when no digest covers the KeyInfo. A signature never
// covers its own KeyInfo (the enveloped-signature transform removes the
// whole Signature; SignatureValue covers SignedInfo only; the profile
// allows one Reference, to the parent's ID). Nothing covers the Response
// signature's KeyInfo. The Assertion signature's KeyInfo is covered by a
// Response signature: a certificate-less KeyInfo there is refused instead.
//
// The KeyInfo elements are identified structurally by two parsers: the
// gate records each ds:KeyInfo child of the ds:Signature of the root
// Response or of its Assertion (keyInfoPosition), with its byte span; the
// tree records the KeyInfo of each signature it validated. They must agree
// on every position before anything is cut, the spans are checked against
// the bytes, and the cut document is checked again from scratch. Cutting
// bytes cannot extend trust: removing covered content breaks a digest, and
// removing uncovered content changes nothing gosaml2 trusts.

// Static details of the refusals of the cut.
const (
	errKeyInfoDifferential = "KeyInfo seen differently by the tokenizer and the tree"
	errKeyInfoSpan         = "KeyInfo span does not match the document"
	errKeyInfoLeft         = "a KeyInfo without certificate is left after the cut"
)

// cutCertificatelessKeyInfo returns raw unchanged unless a validated
// signature of a Success response has a KeyInfo without certificate; then
// it returns the pre-check of the response with those KeyInfo elements
// cut, or a refusal.
func cutCertificatelessKeyInfo(raw *rawResponse, scan *gateScan, allowSHA1 bool) (*rawResponse, error) {
	if !raw.status.success() {
		return raw, nil
	}

	cuts, err := keyInfoCuts(raw, scan)
	if err != nil || len(cuts) == 0 {
		return raw, err
	}

	data, err := splice(raw.data, cuts)
	if err != nil {
		return nil, err
	}

	rescan, err := scanXML(data, responseLimits)
	if err != nil {
		return nil, gateRejection(err)
	}

	cut, err := precheckTree(data, allowSHA1)
	if err != nil {
		return nil, err
	}

	// The cut positions now lack KeyInfo, and nothing is left to cut.
	again, err := keyInfoCuts(cut, rescan)
	if err != nil {
		return nil, err
	}

	if len(again) != 0 || slices.ContainsFunc(cuts, func(c keyInfoSpan) bool { return cut.keyInfo[c.pos].present }) {
		return nil, reject(ErrMalformedResponse, errKeyInfoLeft, nil)
	}

	return cut, nil
}

// keyInfoCuts cross-checks the KeyInfo of each signature position as the
// tree and the gate saw it, and returns the spans of the certificate-less
// ones to cut (a refusal for one covered by a Response signature).
func keyInfoCuts(raw *rawResponse, scan *gateScan) ([]keyInfoSpan, error) {
	var spans [3]*keyInfoSpan

	for i := range scan.keyInfo {
		s := &scan.keyInfo[i]
		if spans[s.pos] != nil {
			return nil, reject(ErrMalformedResponse, errKeyInfoDifferential, nil)
		}

		spans[s.pos] = s
	}

	var cuts []keyInfoSpan

	for _, pos := range []keyInfoPosition{keyInfoResponse, keyInfoAssertion} {
		state, span := raw.keyInfo[pos], spans[pos]

		if state.present != (span != nil) || (span != nil && state.certless == span.hasCert) {
			return nil, reject(ErrMalformedResponse, errKeyInfoDifferential, nil)
		}

		if !state.certless {
			continue
		}

		if pos == keyInfoAssertion && raw.responseSigned {
			return nil, reject(ErrInvalidSignature,
				"a KeyInfo without certificate in an assertion covered by a signed Response", nil)
		}

		cuts = append(cuts, *span)
	}

	return cuts, nil
}

// splice returns a copy of data without the spans, after checking that each
// one is exactly an element whose start tag carries the recorded name.
func splice(data []byte, spans []keyInfoSpan) ([]byte, error) {
	spans = slices.Clone(spans)
	slices.SortFunc(spans, func(a, b keyInfoSpan) int { return cmp.Compare(b.start, a.start) })

	out := slices.Clone(data)
	limit := int64(len(data))

	for _, s := range spans {
		if !spanMatches(data, s, limit) {
			return nil, reject(ErrMalformedResponse, errKeyInfoSpan, nil)
		}

		out = append(out[:s.start], out[s.end:]...)
		limit = s.start
	}

	return out, nil
}

// spanMatches reports whether data[s.start:s.end] is within limit, starts
// with "<" and the recorded name followed by white space, ">" or "/", and
// ends with ">".
func spanMatches(data []byte, s keyInfoSpan, limit int64) bool {
	name := int64(len(s.qname))

	if s.start < 0 || s.end > limit || s.start+name+2 > s.end || data[s.start] != '<' || data[s.end-1] != '>' {
		return false
	}

	if string(data[s.start+1:s.start+1+name]) != s.qname {
		return false
	}

	switch data[s.start+1+name] {
	case ' ', '\t', '\r', '\n', '>', '/':
		return true
	default:
		return false
	}
}
