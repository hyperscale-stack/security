// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
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
