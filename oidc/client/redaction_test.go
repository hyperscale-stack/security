// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verbs are the fmt verbs a value holding secrets is checked with: every
// verb fmt accepts for a struct or a pointer. %p of a value is left out:
// fmt handles it before any method of the value and prints its fields for
// that invalid verb — no type can redact it.
var verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%o", "%b", "%e", "%U", "%c"}

// renderings renders v the ways an application may print or log it, by
// way: every verb, and slog's text and JSON handlers.
func renderings(v any) map[string]string {
	out := map[string]string{}

	for _, verb := range verbs {
		out[verb] = fmt.Sprintf(verb, v)
	}

	if reflect.ValueOf(v).Kind() == reflect.Pointer {
		out["%p"] = fmt.Sprintf("%p", v)
	}

	var text, js strings.Builder

	slog.New(slog.NewTextHandler(&text, nil)).Info("value", "v", v)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("value", "v", v)
	out["slog text"], out["slog JSON"] = text.String(), js.String()

	return out
}

// logged renders v every way at once, for the checks that it does say
// something.
func logged(v any) string {
	var out strings.Builder

	for _, r := range renderings(v) {
		out.WriteString(r + "|")
	}

	return out.String()
}

// assertRedacted fails for every rendering of v that contains one of the
// secrets, naming the way, and for every verb that does not print v's
// redacted form — String, or GoString for %#v.
func assertRedacted(t *testing.T, v any, secrets ...string) {
	t.Helper()

	for way, rendered := range renderings(v) {
		for _, secret := range secrets {
			assert.False(t, strings.Contains(rendered, secret), "%T printed with %s reveals a secret", v, way)
		}
	}

	redacted, ok := v.(interface {
		fmt.Stringer
		fmt.GoStringer
	})
	require.True(t, ok, "%T has a redacted form", v)

	for _, verb := range verbs {
		want := redacted.String()
		if verb == "%#v" {
			want = redacted.GoString()
		}

		assert.Equal(t, want, fmt.Sprintf(verb, v), "%T printed with %s", v, verb)
	}
}

func TestSecretsAreRedacted(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)
	ar, code := op.begin(t, c, oidcclient.AuthOptions{})

	assertRedacted(t, *ar, ar.Binding)
	assertRedacted(t, ar, ar.Binding)
	assert.Contains(t, logged(*ar), "REDACTED")

	cb := callbackFor(ar, code)
	require.Contains(t, cb.URL.RawQuery, code, "the received URL carries the response in query mode")

	assertRedacted(t, cb, ar.Binding, code, ar.State)
	assertRedacted(t, &cb, ar.Binding, code, ar.State)
	assert.Contains(t, logged(cb), testRedirectURL, "the URL is logged without its query")
	assert.Contains(t, logged(oidcclient.Callback{}), `URL: ""`, "a callback without URL")

	id, err := c.Complete(context.Background(), cb)
	require.NoError(t, err)

	for _, v := range []any{id.Tokens, &id.Tokens, *id, id} {
		assertRedacted(t, v, id.Tokens.AccessToken, id.Tokens.IDToken)
	}

	assert.Contains(t, logged(id), id.Subject, "an identity stays recognizable")
}

func TestDefaultClock(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.Now = nil })

	ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(oidcclient.DefaultTransactionTTL), ar.ExpiresAt, 2*time.Second)
}

func TestDecodeClaimsError(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	id, err := op.login(t, op.client(t))
	require.NoError(t, err)

	var wrong struct {
		Sub int `json:"sub"`
	}

	require.Error(t, id.DecodeClaims(&wrong))
}

// TestConfigRedactsSecrets checks that a Config — which holds the client
// secret and the transaction keys — and the *Client built from it never
// print or log them, whatever the verb.
func TestConfigRedactsSecrets(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	cfg := op.config()

	secrets := []string{
		testClientSecret, string(testTransactionKey),
		fmt.Sprint(testTransactionKey)[1:20], // the key bytes as fmt prints them
		fmt.Sprintf("%x", testTransactionKey)[:16], fmt.Sprintf("%X", testTransactionKey)[:16],
		fmt.Sprintf("%#v", testTransactionKey)[8:30], // []byte{0x30, …}
	}

	for _, v := range []any{cfg, &cfg, op.client(t)} {
		assertRedacted(t, v, secrets...)
		assert.Contains(t, logged(v), "REDACTED")
		assert.Contains(t, logged(v), testConnection, "the identifying fields stay readable")
	}

	public := op.config(func(c *oidcclient.Config) { c.AuthMethod, c.ClientSecret = oidcclient.AuthMethodNone, "" })
	assert.Contains(t, public.String(), `ClientSecret: ""`, "a public client has no secret to redact")

	var none *oidcclient.Client

	assert.Equal(t, "oidcclient.Client(nil)", fmt.Sprintf("%v", none))
	assert.Contains(t, logged(none), "oidcclient.Client(nil)", "a nil *Client prints, and logs, without panicking")
}
