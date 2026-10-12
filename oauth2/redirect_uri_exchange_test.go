// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenRedirectURIFollowsTheAuthorizationRequest drives RFC 6749 §4.1.3
// through both endpoints: a client with a single registered redirect URI
// may omit redirect_uri at /authorize, and then at /token too; whenever the
// token request carries it, it must be the URI the code was delivered to.
func TestTokenRedirectURIFollowsTheAuthorizationRequest(t *testing.T) {
	t.Parallel()

	const other = "https://app.example/other"

	cases := []struct {
		name        string
		atAuthorize bool
		atToken     string
		status      int
	}{
		{"omitted in both", false, "", http.StatusOK},
		{"omitted at /authorize, the registered URI at /token", false, redirectURI, http.StatusOK},
		{"omitted at /authorize, another URI at /token", false, other, http.StatusBadRequest},
		{"sent at /authorize, omitted at /token", true, "", http.StatusBadRequest},
		{"sent in both", true, redirectURI, http.StatusOK},
		{"sent at /authorize, another URI at /token", true, other, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newPolicyEnv(t, oauth2.Profile20BCP,
				confidentialClient([]string{oauth2.GrantTypeAuthorizationCode}, []string{"read"}))

			q := machineQuery()
			if !tc.atAuthorize {
				q.Del("redirect_uri")
			}

			rec := runAuthorize(env.srv, q, approve)
			require.Equal(t, http.StatusFound, rec.Code)

			form := codeExchangeForm(mustLocation(t, rec).Query().Get("code"))
			form.Del("redirect_uri")

			if tc.atToken != "" {
				form.Set("redirect_uri", tc.atToken)
			}

			rec = env.token(form, "machine", "machine-secret")
			require.Equal(t, tc.status, rec.Code, rec.Body.String())

			if tc.status != http.StatusOK {
				assert.Equal(t, oauth2.CodeInvalidGrant, jsonBody(t, rec)["error"])
				assert.Equal(t, "redirect_uri mismatch", jsonBody(t, rec)["error_description"])
				assert.NotContains(t, rec.Body.String(), "access_token")
			}
		})
	}
}
