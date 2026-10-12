// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"testing"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
)

func TestIdentity_AttributeValues(t *testing.T) {
	t.Parallel()

	id := &samlsp.Identity{Attributes: []samlsp.Attribute{
		{Name: "groups", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", Values: []string{"a", "b"}},
		{Name: "mail", Values: []string{"alice@example.com"}},
		{Name: "groups", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", Values: []string{"c"}},
	}}

	assert.Equal(t, []string{"a", "b", "c"}, id.AttributeValues("groups"))
	assert.Equal(t, []string{"alice@example.com"}, id.AttributeValues("mail"))
	assert.Nil(t, id.AttributeValues("missing"))
}
