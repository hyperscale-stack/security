// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The pre-check refuses an unsigned document itself (gosaml2 would too:
// the profile must not depend on it).
func TestPrecheck_RefusesUnsignedDocuments(t *testing.T) {
	t.Parallel()

	doc := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2026-10-12T10:00:00Z">` +
		`<saml:Issuer>https://idp</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`<saml:Assertion ID="_a" Version="2.0" IssueInstant="2026-10-12T10:00:00Z"><saml:Issuer>https://idp</saml:Issuer></saml:Assertion>` +
		`</samlp:Response>`

	_, err := precheck([]byte(doc), false)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

// TestPrecheckTree_RefusesDirectives: a DTD or a processing instruction is
// refused by the parsed-tree check too, not only by the lexical gate. With
// the gate bypassed (audit SAML-I10: mutating it away let the DTD/XXE
// corpus entries through as logins, since etree, gosaml2, goxmldsig and the
// round-trip validator all ignore a DTD), the structural pre-check still
// refuses every such document before any signature work.
func TestPrecheckTree_RefusesDirectives(t *testing.T) {
	t.Parallel()

	const body = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0" IssueInstant="2026-10-12T10:00:00Z">` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status></samlp:Response>`

	refused := map[string]string{
		"internal DTD":           `<!DOCTYPE r [<!ENTITY x "y">]>` + body,
		"external entity":        `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` + body,
		"external DTD":           `<!DOCTYPE samlp:Response SYSTEM "http://attacker.example/evil.dtd">` + body,
		"declaration then DTD":   `<?xml version="1.0"?><!DOCTYPE r>` + body,
		"processing instruction": `<?evil x?>` + body,
		"second declaration":     `<?xml version="1.0"?><?xml version="1.0"?>` + body,
		"instruction inside":     strings.Replace(body, `<samlp:Status>`, `<samlp:Status><?evil x?>`, 1),
		"directive inside":       strings.Replace(body, `<samlp:Status>`, `<samlp:Status><!ENTITY x "y">`, 1),
	}

	for name, doc := range refused {
		_, err := precheckTree([]byte(doc), false)
		require.ErrorIs(t, err, ErrMalformedResponse, name)
		require.EqualError(t, err, ErrMalformedResponse.Error()+" (DTD or processing instruction in the parsed document)", name)
	}

	// The XML declaration alone, first, is the one instruction allowed.
	raw, err := precheckTree([]byte(`<?xml version="1.0" encoding="UTF-8"?>`+body), false)
	require.NoError(t, err)
	require.False(t, raw.status.success())
}
