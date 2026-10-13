// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bearer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/bearer"
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

const secretToken = "eyJhbGciOiJFZERTQSJ9.SECRET-PAYLOAD.SIG"

// Audit CORE-15: a bearer Authentication printed the bearer token, and kept
// it after authentication although Token()'s documentation promised a
// redaction. WithAuthenticated now drops the token, and the value prints and
// logs without it.
func TestAuthenticationRedactsTheToken(t *testing.T) {
	t.Parallel()

	pending := bearer.New(secretToken)
	authed := pending.WithAuthenticated(principal{sub: "alice"}, []string{"scope:read"}, "alice")

	for _, v := range []any{pending, &pending, authed} {
		for _, out := range renderings(t, v) {
			assert.NotContains(t, out, "SECRET-PAYLOAD")
		}
	}

	assert.Equal(t, `bearer.Authentication{Name: "bearer", Authenticated: false, Authorities: [], Token: REDACTED}`, fmt.Sprint(pending))
	assert.Equal(t, `bearer.Authentication{Name: "alice", Authenticated: true, Authorities: ["scope:read"], Token: ""}`, fmt.Sprint(authed))
}

func TestWithAuthenticatedDropsTheToken(t *testing.T) {
	t.Parallel()

	authed := bearer.New(secretToken).WithAuthenticated(principal{sub: "alice"}, nil, "")

	assert.Empty(t, authed.Token(), "the token never outlives its verification")
	assert.Nil(t, authed.Credentials())

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(_ context.Context, token string) (security.Authentication, error) {
		return bearer.New(token).WithAuthenticated(principal{sub: "alice"}, nil, ""), nil
	}))

	out, err := a.Authenticate(context.Background(), bearer.New(secretToken))
	require.NoError(t, err)

	ba, ok := out.(bearer.Authentication)
	require.True(t, ok)
	assert.Empty(t, ba.Token())
}

// A failed Authenticate returns security.Anonymous(), never its input — the
// token.
func TestAuthenticatorFailureReturnsAnonymous(t *testing.T) {
	t.Parallel()

	a := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
		return nil, security.ErrTokenExpired
	}))

	for _, in := range []security.Authentication{bearer.New(secretToken), security.Anonymous()} {
		out, err := a.Authenticate(context.Background(), in)
		require.Error(t, err)
		assert.Equal(t, security.Anonymous(), out)
	}

	nilVerifier := bearer.NewAuthenticator(bearer.VerifierFunc(func(context.Context, string) (security.Authentication, error) {
		return nil, nil
	}))

	out, err := nilVerifier.Authenticate(context.Background(), bearer.New(secretToken))
	require.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.Equal(t, security.Anonymous(), out)
}

// Name falls back to the principal's subject, then to the scheme label.
func TestAuthenticationNameFallbacks(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "bob", bearer.New("t").WithAuthenticated(principal{sub: "bob"}, nil, "").Name())
	assert.Equal(t, "", bearer.New("t").WithAuthenticated(principal{sub: ""}, nil, "").Name())
	assert.Equal(t, "bearer", bearer.New("t").Name())
}
