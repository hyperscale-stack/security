// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// renderings prints v every way an application could log it: every fmt
// verb, alone and nested in an exported struct field, through slog's text
// and JSON handlers (top level and nested), and with encoding/json.
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

// Audit CORE-15 (probe TestZZAuditSessionPrinting): the exported fields of a
// Session revealed its CSRF token (and its raw ID, a credential the module
// never puts on a span) through %+v and encoding/json. A Session now
// prints, logs and encodes its ID fingerprint, the keys of its values (not
// the values: tokens, personal data) and its times — never the token.
func TestSessionRedactsItself(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	s, err := mgr.Login(context.Background(), newCarrier(), principal{sub: "alice@example.com"})
	require.NoError(t, err)

	s.Values["access_token"] = "eyJhbGciOiJ-SECRET-TOKEN"

	for _, v := range []any{*s, s} {
		for _, out := range renderings(t, v) {
			assert.NotContains(t, out, s.CSRFToken)
			assert.NotContains(t, out, s.ID)
			assert.NotContains(t, out, "SECRET-TOKEN")
			assert.NotContains(t, out, "alice@example.com")
		}
	}

	str := fmt.Sprint(*s)
	assert.Contains(t, str, "session.Session{ID: ")
	assert.Contains(t, str, "Values: [access_token sub]")
	assert.Contains(t, str, "CSRFToken: REDACTED")

	b, err := json.Marshal(s)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Equal(t, "REDACTED", decoded["CSRFToken"])
	assert.Equal(t, []any{"access_token", "sub"}, decoded["Values"])
	assert.NotEmpty(t, decoded["IDHash"])
	assert.NotContains(t, decoded, "ID")

	// The cookie itself still carries everything: the redaction applies to
	// printing and encoding/json only.
	c := newCarrier()
	require.NoError(t, mgr.Touch(context.Background(), c, s))

	got, err := mgr.Get(context.Background(), c.replay())
	require.NoError(t, err)
	assert.Equal(t, s.CSRFToken, got.CSRFToken)
	assert.Equal(t, "eyJhbGciOiJ-SECRET-TOKEN", got.GetString("access_token"))
}

func TestEmptySessionPrints(t *testing.T) {
	t.Parallel()

	var s session.Session

	assert.Equal(t, `session.Session{ID: "", Values: [], CSRFToken: "", CreatedAt: 0001-01-01T00:00:00Z, LastAccessed: 0001-01-01T00:00:00Z, ExpiresAt: 0001-01-01T00:00:00Z}`, fmt.Sprint(s))
}

// The session Authentication holds the Session and the application's
// principal: it prints neither the CSRF token nor the principal's fields.
func TestSessionAuthenticationRedactsItself(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	c := newCarrier()
	s, err := mgr.Login(context.Background(), c, principal{sub: "alice"})
	require.NoError(t, err)

	// The loader resolves the session's subject into a userRecord.
	loader := session.NewMockPrincipalLoader(t)
	loader.EXPECT().Load(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, values map[string]any) (security.Principal, []string, error) {
			sub, _ := values["sub"].(string)

			return userRecord{sub: sub, passwordHash: "$2a$10$HASH-OF-THE-USER"}, []string{"ROLE_USER"}, nil
		}).Once()

	engine := security.NewEngine(security.NewManager(session.NewAuthenticator(loader)), session.NewExtractor(mgr))

	_, auth, err := engine.Process(context.Background(), c.replay())
	require.NoError(t, err)

	pending, err := session.NewExtractor(mgr).Extract(context.Background(), c.replay())
	require.NoError(t, err)

	for _, v := range []any{auth, pending} {
		for _, out := range renderings(t, v) {
			assert.NotContains(t, out, s.CSRFToken)
			assert.NotContains(t, out, s.ID)
			assert.NotContains(t, out, "HASH-OF-THE-USER", "the principal's fields are never printed")
		}
	}

	assert.Equal(t, `session.Authentication{Name: "alice", Authenticated: true, Authorities: ["ROLE_USER"]}`, fmt.Sprint(auth))
	assert.Equal(t, `session.Authentication{Name: "session", Authenticated: false, Authorities: []}`, fmt.Sprint(pending))
}

// userRecord is an application principal holding a secret field, as a user
// record loaded from a store does. It is hand-written: security.Principal
// belongs to the core package, whose generated mocks exist only in the
// core's own test binary, and the test needs the secret in a field fmt
// would print.
type userRecord struct {
	sub          string
	passwordHash string
}

func (u userRecord) Subject() string { return u.sub }
