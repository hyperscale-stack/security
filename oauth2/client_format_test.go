// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
)

// TestDefaultClientRedactsTheSecret: a DefaultClient — or a pointer to one
// — printed with any fmt verb, or logged through slog, never reveals its
// secret; every verb prints the redacted form. (%p of a value is left out:
// fmt prints the fields of a value for that invalid verb before any
// method, which no type can redact.)
func TestDefaultClientRedactsTheSecret(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-of-the-client"

	client := &oauth2.DefaultClient{
		IDValue: "client-1", Secret: secret, TypeValue: oauth2.ClientConfidential,
		RedirectURIValues: []string{"https://rp.example/cb"}, GrantTypeValues: []string{oauth2.GrantTypeAuthorizationCode},
		ScopeValues: []string{"openid"}, AuthMethodValues: []string{"client_secret_basic"}, IssuerValues: []string{"https://op.example"},
	}

	want := `oauth2.DefaultClient{ID: "client-1", Type: "confidential", Secret: REDACTED, ` +
		`RedirectURIs: ["https://rp.example/cb"], GrantTypes: ["authorization_code"], Scopes: ["openid"], ` +
		`AuthMethods: ["client_secret_basic"], Issuers: ["https://op.example"]}`

	for _, v := range []any{client, *client} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%o", "%b", "%e", "%U", "%c"} {
			assert.Equal(t, want, fmt.Sprintf(verb, v), "%T printed with %s", v, verb)
		}

		var text, js strings.Builder

		slog.New(slog.NewTextHandler(&text, nil)).Info("client", "client", v)
		slog.New(slog.NewJSONHandler(&js, nil)).Info("client", "client", v)

		for name, out := range map[string]string{"slog text": text.String(), "slog JSON": js.String()} {
			assert.NotContains(t, out, secret, "%T logged with %s", v, name)
			assert.Contains(t, out, "client-1", "%T logged with %s names the client", v, name)
		}
	}

	assert.Contains(t, fmt.Sprintf("%p", client), "0x", "a pointer prints as an address")
	assert.Contains(t, fmt.Sprint(oauth2.DefaultClient{IDValue: "public"}), `Secret: ""`, "no secret to redact")
}
