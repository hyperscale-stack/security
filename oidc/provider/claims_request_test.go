// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func raw(s string) json.RawMessage { return json.RawMessage(s) }

// TestClaimsParameterParsing pins OIDC Core §5.5 and §5.5.1: the userinfo
// and id_token members, null or object per claim, essential, value and
// values, unknown members ignored, member names case-sensitive.
func TestClaimsParameterParsing(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	claims := `{
		"id_token": {"auth_time": {"essential": true}, "acr": {"values": ["urn:a", "urn:b"]}, "email": null},
		"userinfo": {"email": null, "name#fr": {"value": "Alice", "extension": 1}, "picture": {"essential": false}},
		"other": {"x": [1, 2]}
	}`

	require.NotEmpty(t, redirect(t, e.authorize(with(authorizeQuery(), "claims", claims))).Get("code"))

	assert.Equal(t, oidcprovider.ClaimsRequest{
		IDToken: []oidcprovider.ClaimRequest{
			{Name: "auth_time", Essential: true},
			{Name: "acr", Values: []json.RawMessage{raw(`"urn:a"`), raw(`"urn:b"`)}},
			{Name: "email"},
		},
		UserInfo: []oidcprovider.ClaimRequest{
			{Name: "email"},
			{Name: "name#fr", Values: []json.RawMessage{raw(`"Alice"`)}},
			{Name: "picture"},
		},
	}, e.lastRequest().Claims)
	assert.Empty(t, e.lastRequest().EssentialACR, "a voluntary acr request is not enforced")

	require.NotEmpty(t, redirect(t, e.authorize(with(authorizeQuery(), "claims", `{"ID_TOKEN": {"email": null}}`))).Get("code"))
	assert.Equal(t, oidcprovider.ClaimsRequest{}, e.lastRequest().Claims, "member names are case-sensitive")
}

func TestClaimsParameterDerivedRequirements(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.ACR = "urn:b" }, nil)

	claims := `{"id_token": {"acr": {"essential": true, "value": "urn:a", "values": ["urn:b"]}, "sub": {"value": "alice"}},
		"userinfo": {"sub": {"values": ["alice", "bob"]}}}`

	require.NotEmpty(t, redirect(t, e.authorize(with(authorizeQuery(), "claims", claims))).Get("code"))

	req := e.lastRequest()
	assert.Equal(t, []string{"urn:a", "urn:b"}, req.EssentialACR, "value and values (Core §5.5.1.1)")
	assert.Equal(t, []string{"alice"}, req.Subjects, "every sub constraint holds (Core §5.5.1)")
}

func TestClaimsParameterRefusals(t *testing.T) {
	t.Parallel()

	manyClaims := make([]string, 33)
	for i := range manyClaims {
		manyClaims[i] = fmt.Sprintf(`"c%d": null`, i)
	}

	manyValues := make([]string, 17)
	for i := range manyValues {
		manyValues[i] = fmt.Sprintf(`"v%d"`, i)
	}

	bigNames := make([]string, 20)
	for i := range bigNames {
		bigNames[i] = fmt.Sprintf(`"%s%02d": {"essential": true}`, strings.Repeat("n", 150), i)
	}

	cases := map[string]string{
		"not JSON":                        `{"id_token":`,
		"an array":                        `[]`,
		"a string":                        `"x"`,
		"trailing data":                   `{}{}`,
		"member not an object":            `{"id_token": ["email"]}`,
		"member null":                     `{"userinfo": null}`,
		"claim neither null nor object":   `{"userinfo": {"email": true}}`,
		"essential not a boolean":         `{"userinfo": {"email": {"essential": "yes"}}}`,
		"values not an array":             `{"userinfo": {"email": {"values": "a"}}}`,
		"duplicated member":               `{"userinfo": {}, "userinfo": {}}`,
		"duplicated claim":                `{"userinfo": {"email": null, "email": null}}`,
		"duplicated claim member":         `{"userinfo": {"email": {"essential": true, "essential": false}}}`,
		"empty claim name":                `{"userinfo": {"": null}}`,
		"claim name with a control char":  `{"userinfo": {"e\u0001mail": null}}`,
		"claim name over 255 bytes":       `{"userinfo": {"` + strings.Repeat("n", 256) + `": null}}`,
		"more than 32 claims":             `{"userinfo": {` + strings.Join(manyClaims, ",") + `}}`,
		"more than 16 values":             `{"userinfo": {"email": {"values": [` + strings.Join(manyValues, ",") + `]}}}`,
		"value over 255 bytes":            `{"userinfo": {"email": {"value": "` + strings.Repeat("v", 256) + `"}}}`,
		"sub value not a string":          `{"id_token": {"sub": {"value": 42}}}`,
		"acr value not a string":          `{"id_token": {"acr": {"essential": true, "values": [1]}}}`,
		"disjoint sub constraints":        `{"id_token": {"sub": {"value": "alice"}}, "userinfo": {"sub": {"value": "bob"}}}`,
		"over 4096 bytes":                 `{"userinfo": {"x": {"value": "` + strings.Repeat("v", 4100) + `"}}}`,
		"over 4096 bytes, ignored member": `{"other": "` + strings.Repeat("v", 4100) + `", "userinfo": {"email": null}}`,
		"stored form over its budget":     `{"id_token": {` + strings.Join(bigNames, ",") + `}}`,
		"invalid UTF-8":                   "{\"userinfo\": {\"e\xffmail\": null}}",
	}

	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			params := redirect(t, e.authorize(with(authorizeQuery(), "claims", claims)))
			assert.Equal(t, oauth2.CodeInvalidRequest, params.Get("error"))

			interactive, silent := e.interaction.calls()
			assert.Empty(t, interactive)
			assert.Empty(t, silent)
		})
	}
}
