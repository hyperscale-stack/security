// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verbs are the fmt verbs a value holding secrets is checked with: every
// verb fmt accepts for a struct or a pointer. %p of a value is left out:
// fmt handles it before any method of the value and prints its fields for
// that invalid verb — no type can redact it.
var verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%o", "%b", "%e", "%U", "%c"}

// renderings renders v the ways an application may print or log it: every
// verb, %p for a pointer, and slog's text and JSON handlers.
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

// assertRedacted fails for every rendering of v that contains one of the
// secrets, and for every verb that does not print v's redacted form.
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

// TestSecretsAreRedacted: a Config or a *ServiceProvider printed or logged
// in any way never shows the transaction keys nor the signing key (review
// F1: String alone leaves %d, %o, %b… and unexported fields to fmt).
func TestSecretsAreRedacted(t *testing.T) {
	t.Parallel()

	k := keys(t)
	key := []byte("a transaction key that must never be printed")

	e := newEnv(t, withSigningKey(t), func(c *samlsp.Config, _ *samlsp.Connection) {
		c.TransactionKeys = [][]byte{key}
	})

	priv, ok := k.sp.signer.(*rsa.PrivateKey)
	require.True(t, ok)

	secrets := []string{string(key), hex.EncodeToString(key), fmt.Sprint(key), priv.D.String(), fmt.Sprintf("%x", priv.D)}

	cfg := samlsp.Config{TransactionKeys: [][]byte{key}, SigningKey: k.sp.signer, SigningCertificate: k.sp.cert}

	for _, v := range []any{cfg, &cfg, e.sp} {
		assertRedacted(t, v, secrets...)
	}

	assert.Contains(t, fmt.Sprint(e.sp), "TransactionKeys: 1 REDACTED")
	assert.Contains(t, fmt.Sprint(e.sp), "SigningKey: REDACTED")
	assert.Contains(t, fmt.Sprint(samlsp.Config{}), "SigningKey: none")

	var nilSP *samlsp.ServiceProvider

	assert.Equal(t, "samlsp.ServiceProvider(nil)", fmt.Sprint(nilSP))
	assert.Equal(t, "samlsp.ServiceProvider(nil)", nilSP.LogValue().String())
}
