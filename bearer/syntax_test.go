// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit F-17. RFC 6750 §2.1:
//
//	b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
//	credentials = "Bearer" 1*SP b64token
//
// A Bearer credential that breaks this syntax is a malformed request
// (§3.1 invalid_request, 400); a token over the length cap is "invalid for
// other reasons" (§3.1 invalid_token, 401). Neither reaches the verifier.
func TestExtractorEnforcesTheB64tokenSyntax(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header string
		token  string // a valid credential
		class  string // a refusal ("" with an empty token: another scheme)
	}{
		{name: "every b64token character", header: "Bearer abc.DEF-ghi_~+/09==", token: "abc.DEF-ghi_~+/09=="},
		{name: "lower-case scheme", header: "bearer abc", token: "abc"},
		{name: "upper-case scheme", header: "BEARER abc", token: "abc"},
		{name: "several spaces", header: "Bearer   abc", token: "abc"},
		{name: "another scheme", header: "Basic Zm9vOmJhcg=="},
		{name: "a longer scheme", header: "BearerX abc"},
		{name: "scheme alone", header: "Bearer", class: security.ErrorClassInvalidRequest},
		{name: "scheme and space", header: "Bearer ", class: security.ErrorClassInvalidRequest},
		{name: "scheme and spaces", header: "Bearer    ", class: security.ErrorClassInvalidRequest},
		{name: "tab separator", header: "Bearer\tabc", class: security.ErrorClassInvalidRequest},
		{name: "space inside the token", header: "Bearer abc def", class: security.ErrorClassInvalidRequest},
		{name: "trailing space", header: "Bearer abc ", class: security.ErrorClassInvalidRequest},
		{name: "second credential", header: "Bearer abc, Basic Zm9vOmJhcg==", class: security.ErrorClassInvalidRequest},
		{name: "quote and backslash", header: `Bearer a"b\c`, class: security.ErrorClassInvalidRequest},
		{name: "outside the alphabet", header: "Bearer a!b#c$d%e", class: security.ErrorClassInvalidRequest},
		{name: "padding in the middle", header: "Bearer a=b", class: security.ErrorClassInvalidRequest},
		{name: "padding alone", header: "Bearer ==", class: security.ErrorClassInvalidRequest},
		{name: "non-ASCII", header: "Bearer töken", class: security.ErrorClassInvalidRequest},
		{name: "control character", header: "Bearer ab\x01c", class: security.ErrorClassInvalidRequest},
		{name: "exactly 16 KiB", header: "Bearer " + strings.Repeat("A", 16<<10), token: strings.Repeat("A", 16<<10)},
		{name: "over 16 KiB", header: "Bearer " + strings.Repeat("A", 16<<10+1), class: security.ErrorClassInvalidCredentials},
		// The cap is checked first: an over-length value is not scanned.
		{name: "over 16 KiB, not a b64token", header: "Bearer " + strings.Repeat("!", 16<<10+1),
			class: security.ErrorClassInvalidCredentials},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			carrier := newCarrier()
			carrier.Set("Authorization", c.header)

			for _, ex := range []bearer.Extractor{bearer.NewExtractor(), {}} {
				got, err := ex.Extract(context.Background(), carrier)

				switch {
				case c.token != "":
					require.NoError(t, err)
					require.NotNil(t, got)
					assert.Equal(t, c.token, got.(bearer.Authentication).Token())
				case c.class != "":
					assert.Nil(t, got)
					assert.Equal(t, c.class, security.ErrorClass(err))
					assert.NotContains(t, err.Error(), "abc", "the reason never quotes the token")
				default:
					require.NoError(t, err)
					assert.Nil(t, got, "another scheme: the next extractor tries")
				}
			}
		})
	}
}

func TestWithMaxTokenLength(t *testing.T) {
	t.Parallel()

	ex := bearer.NewExtractor(bearer.WithMaxTokenLength(8))

	for token, ok := range map[string]bool{"abcdefgh": true, "abcdefgh=": false, "abcdefghi": false} {
		carrier := newCarrier()
		carrier.Set("Authorization", "Bearer "+token)

		got, err := ex.Extract(context.Background(), carrier)
		if ok {
			require.NoError(t, err)
			assert.NotNil(t, got)

			continue
		}

		assert.Equal(t, security.ErrorClassInvalidCredentials, security.ErrorClass(err), token)
	}

	assert.Panics(t, func() { bearer.WithMaxTokenLength(0) })
	assert.Panics(t, func() { bearer.WithMaxTokenLength(-1) })
}

// A refused credential never reaches the verifier (the generated mock fails
// on any call).
func TestMalformedTokensNeverReachTheVerifier(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager(bearer.NewAuthenticator(bearer.NewMockTokenVerifier(t))),
		bearer.NewExtractor())

	for _, header := range []string{"Bearer", "Bearer  a b", "Bearer a!b", "Bearer " + strings.Repeat("A", 16<<10+1)} {
		carrier := newCarrier()
		carrier.Set("Authorization", header)

		_, auth, err := engine.Process(context.Background(), carrier)
		require.Error(t, err)
		assert.False(t, auth.IsAuthenticated())
	}
}
