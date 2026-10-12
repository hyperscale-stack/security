// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"encoding/json"
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// profile reads two claims an application commonly trusts.
type profile struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// TestLoneCaseVariantClaimIsIgnored pins the documented behaviour of a
// claim whose name differs from a known one only by case: it is another
// claim (OpenID Connect Core §14 compares names code point by code point),
// which Core §2 and RFC 7519 §4 require ignoring. The login succeeds;
// DecodeClaims and a map read the names exactly; encoding/json into a
// struct, matching names case-insensitively, reads the variant as the
// canonical claim — what the documentation warns about.
func TestLoneCaseVariantClaimIsIgnored(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) {
		op.claimsHook = func(_ *grant, c map[string]any) {
			delete(c, "email")
			c["EMAIL"] = "victim@example.com"
			c["EMAIL_VERIFIED"] = true
		}
	})

	id, err := op.login(t, op.client(t))
	require.NoError(t, err)

	var exact profile
	require.NoError(t, id.DecodeClaims(&exact))
	assert.Equal(t, profile{}, exact, "DecodeClaims matches member names exactly")

	var names map[string]any
	require.NoError(t, json.Unmarshal(id.Claims, &names))
	assert.NotContains(t, names, "email_verified", "a map keeps the names as they are")
	assert.Equal(t, true, names["EMAIL_VERIFIED"])

	var lax profile
	require.NoError(t, json.Unmarshal(id.Claims, &lax))
	assert.Equal(t, profile{Email: "victim@example.com", EmailVerified: true}, lax,
		"encoding/json reads the case variants: never decode claims with it")
}

// TestUserInfoDecodeMatchesNamesExactly checks the same for UserInfo.
func TestUserInfoDecodeMatchesNamesExactly(t *testing.T) {
	t.Parallel()

	ui := oidcclient.UserInfo{
		Subject: testSubject,
		Claims:  json.RawMessage(`{"sub":"` + testSubject + `","EMAIL_VERIFIED":true}`),
	}

	var exact profile
	require.NoError(t, ui.Decode(&exact))
	assert.False(t, exact.EmailVerified)
}
