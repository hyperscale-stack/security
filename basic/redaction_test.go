// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderings prints v every way an application could log it.
func renderings(t *testing.T, v any) []string {
	t.Helper()

	var out []string

	nested := struct{ Field any }{v}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%o", "%b", "%e", "%U", "%c"} {
		out = append(out, fmt.Sprintf(verb, v), fmt.Sprintf(verb, nested))
	}

	var text, js bytes.Buffer

	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "v", v, "nested", nested)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "v", v, "nested", nested)

	out = append(out, text.String(), js.String())

	for _, x := range []any{v, nested} {
		b, err := json.Marshal(x)
		require.NoError(t, err)

		out = append(out, string(b))
	}

	return out
}

// Audit CORE-15 (probe TestZZAuditBasicPrintsPassword): a basic
// Authentication printed `{username:alice password:S3cr3t! …}`, and once
// authenticated its PasswordUser — the application's user record, password
// hash included. It now prints its Name (the subject, or "basic"), its
// state and authorities, never the typed user-id, the password or the user.
func TestAuthenticationRedactsCredentials(t *testing.T) {
	t.Parallel()

	user := &stubUser{subject: "alice", passwordHash: "$2a$04$HASH-OF-THE-USER", enabled: true}
	a := basic.NewAuthenticator(&stubLoader{user: user}, &recordingHasher{always: true})

	pending := basic.New("Summer2026!-typed-in-the-user-field", "S3cr3t!")

	authed, err := a.Authenticate(context.Background(), basic.New("alice", "S3cr3t!"))
	require.NoError(t, err)

	for _, v := range []any{pending, &pending, authed} {
		for _, out := range renderings(t, v) {
			assert.NotContains(t, out, "S3cr3t!")
			assert.NotContains(t, out, "Summer2026")
			assert.NotContains(t, out, "HASH-OF-THE-USER")
		}
	}

	assert.Equal(t, `basic.Authentication{Name: "basic", Authenticated: false, Authorities: [], Credentials: REDACTED}`, fmt.Sprint(pending))
	assert.Equal(t, `basic.Authentication{Name: "alice", Authenticated: true, Authorities: [], Credentials: ""}`, fmt.Sprint(authed))
}
