// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// everyVerb is every fmt verb, with flags and widths, an application may
// print a value with — including the verbs a struct or a pointer does not
// take, for which fmt reports a bad verb and prints the value again.
var everyVerb = []string{
	"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%e", "%c", "%U", "%b", "%o", "%p", "%10s", "%-q", "%08.3f",
}

// secretForms are the ways fmt may spell secret: the text itself, its hex
// encodings and the per-byte lists fmt prints for a byte slice.
func secretForms(secret string) []string {
	forms := []string{secret, hex.EncodeToString([]byte(secret)), strings.ToUpper(hex.EncodeToString([]byte(secret)))}

	for _, verb := range []string{"%d", "%o", "%b", "%c", "%U"} {
		forms = append(forms, strings.Trim(fmt.Sprintf(verb, []byte(secret)), "[]"))
	}

	return forms
}

// everyRendering renders v with every verb, log/slog's text and JSON
// handlers, encoding/json, encoding/gob and encoding/xml.
func everyRendering(v any) map[string]string {
	out := map[string]string{}

	for _, verb := range everyVerb {
		out[verb] = fmt.Sprintf(verb, v)
	}

	var text, js strings.Builder

	slog.New(slog.NewTextHandler(&text, nil)).Info("value", "v", v)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("value", "v", v)
	out["slog text"], out["slog JSON"] = text.String(), js.String()

	encoded, _ := json.Marshal(v)
	out["encoding/json"] = string(encoded)

	var g bytes.Buffer

	_ = gob.NewEncoder(&g).Encode(v)
	out["encoding/gob"] = g.String()

	encoded, _ = xml.Marshal(v)
	out["encoding/xml"] = string(encoded)

	return out
}

// TestSecretsNeverPrint checks every secret of the package's values — the
// client secret, the transaction keys, the binding secret, the tokens —
// under every verb and encoder, wherever the value sits: printed directly,
// in a slice or a map, in an exported field, and in an unexported field of
// an application's struct, which fmt prints by reflection without calling
// any method of the value.
func TestSecretsNeverPrint(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) {
		op.accessToken = "an-access-token-long-enough-to-be-unmistakable"
		op.tokenHook = func(_ *grant, body map[string]any) {
			body["refresh_token"] = "a-refresh-token-long-enough-to-be-unmistakable"
		}
	})
	cfg := op.config()
	c := op.client(t)

	ar, code := op.begin(t, c, oidcclient.AuthOptions{})
	cb := callbackFor(ar, code)

	id, err := c.Complete(context.Background(), cb)
	require.NoError(t, err)
	require.NotEmpty(t, id.Tokens.RefreshToken)

	configSecrets := []string{testClientSecret, string(testTransactionKey)}
	tokens := []string{id.Tokens.AccessToken.Reveal(), id.Tokens.RefreshToken.Reveal(), id.Tokens.IDToken.Reveal()}
	hint := oidcclient.AuthOptions{IDTokenHint: id.Tokens.IDToken}

	secret := oidcclient.NewSecret(testClientSecret)

	shapes := []struct {
		name    string
		value   any
		secrets []string
	}{
		{"Secret", secret, configSecrets},
		{"pointer to a Secret", &secret, configSecrets},
		{"slice of Secrets", []oidcclient.Secret{secret}, configSecrets},
		{"Secret in a map", map[string]oidcclient.Secret{"k": secret}, configSecrets},
		{"Secret in an unexported field", struct{ s oidcclient.Secret }{secret}, configSecrets},
		{"pointer to a Secret in an unexported field", struct{ s *oidcclient.Secret }{&secret}, configSecrets},
		{"Client value", *c, configSecrets},
		{"Client in an unexported field", struct{ c oidcclient.Client }{*c}, configSecrets},
		{"slice of Client values", []oidcclient.Client{*c}, configSecrets},
		{"Config", cfg, configSecrets},
		{"Config in an unexported field", struct{ cfg oidcclient.Config }{cfg}, configSecrets},
		{"Config in a map", map[string]oidcclient.Config{"acme": cfg}, configSecrets},
		{"AuthRequest in an unexported field", struct{ ar oidcclient.AuthRequest }{*ar}, []string{ar.Binding.Reveal()}},
		{"Callback in an unexported field", struct{ cb oidcclient.Callback }{cb}, []string{ar.Binding.Reveal()}},
		{"Identity in an unexported field", struct{ id oidcclient.Identity }{*id}, tokens},
		{"Identity in an exported field", struct{ ID oidcclient.Identity }{*id}, tokens},
		{"Tokens in an unexported field", struct{ t oidcclient.Tokens }{id.Tokens}, tokens},
		{"Tokens in an exported field", struct{ T *oidcclient.Tokens }{&id.Tokens}, tokens},
		{"AuthOptions with an ID Token hint", hint, tokens[2:]},
		{"AuthOptions in an unexported field", struct{ o oidcclient.AuthOptions }{hint}, tokens[2:]},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			t.Parallel()

			for way, rendered := range everyRendering(shape.value) {
				for _, secret := range shape.secrets {
					for _, form := range secretForms(secret) {
						assert.NotContains(t, rendered, form, "%s reveals a secret", way)
					}
				}
			}
		})
	}
}

// TestSecret checks the Secret type itself: its value, its renderings and
// its encodings, empty and not.
func TestSecret(t *testing.T) {
	t.Parallel()

	secret := oidcclient.NewSecret("s3cr3t")
	assert.Equal(t, "s3cr3t", secret.Reveal())
	assert.Equal(t, oidcclient.Secret{}, oidcclient.NewSecret(""), "the empty Secret is the zero Secret")
	assert.Empty(t, oidcclient.Secret{}.Reveal())

	for _, verb := range everyVerb {
		if verb == "%p" { // fmt handles %p before any method: the address of the value
			continue
		}

		assert.Equal(t, "REDACTED", fmt.Sprintf(verb, secret), verb)
		assert.Equal(t, `""`, fmt.Sprintf(verb, oidcclient.Secret{}), verb)
	}

	assert.Equal(t, "REDACTED", secret.LogValue().String())
	assert.Equal(t, `""`, oidcclient.Secret{}.LogValue().String())

	var text strings.Builder

	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "secret", secret)
	assert.Contains(t, text.String(), "secret=REDACTED")

	encoded, err := json.Marshal(struct{ A, B oidcclient.Secret }{secret, oidcclient.Secret{}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"A":"REDACTED","B":""}`, string(encoded))

	var back struct{ A oidcclient.Secret }
	require.Error(t, json.Unmarshal(encoded, &back), "a Secret never decodes from JSON")

	require.Error(t, gob.NewEncoder(&bytes.Buffer{}).Encode(secret), "encoding/gob refuses a Secret")
}
