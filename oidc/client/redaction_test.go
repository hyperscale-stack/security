// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
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

	assertRedacted(t, *ar, ar.Binding.Reveal())
	assertRedacted(t, ar, ar.Binding.Reveal())
	assert.Contains(t, logged(*ar), "REDACTED")

	cb := callbackFor(ar, code)
	require.Contains(t, cb.URL.RawQuery, code, "the received URL carries the response in query mode")

	assertRedacted(t, cb, ar.Binding.Reveal(), code, ar.State)
	assertRedacted(t, &cb, ar.Binding.Reveal(), code, ar.State)
	assert.Contains(t, logged(cb), testRedirectURL, "the URL is logged without its query")
	assert.Contains(t, logged(oidcclient.Callback{}), `URL: ""`, "a callback without URL")

	id, err := c.Complete(context.Background(), cb)
	require.NoError(t, err)

	for _, v := range []any{id.Tokens, &id.Tokens, *id, id} {
		assertRedacted(t, v, id.Tokens.AccessToken.Reveal(), id.Tokens.IDToken.Reveal())
	}

	assert.Contains(t, logged(id), id.Subject, "an identity stays recognizable")
}

// TestAuthRequestRenderingsOmitTheState checks that an AuthRequest prints
// and logs without its state — with a leaked state, a request to the
// callback through the victim's browser burns the pending login — nor the
// rest of the authorization request's query (hints included): the URL is
// rendered without its query. Its JSON encoding, the hand-off of the
// request to a front end, keeps them.
func TestAuthRequestRenderingsOmitTheState(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{LoginHint: "jane@example.com"})
	require.NoError(t, err)

	endpoint, err := url.Parse(ar.URL)
	require.NoError(t, err)

	endpoint.RawQuery = ""

	for _, v := range []any{*ar, ar} {
		for way, rendered := range renderings(v) {
			assert.NotContains(t, rendered, ar.State, "%s reveals the state", way)
			assert.NotContains(t, rendered, "&state=", way)
			assert.NotContains(t, rendered, "?", "%s renders the URL with its query", way)
			assert.NotContains(t, rendered, "jane", "%s reveals the login hint", way)
			assert.NotContains(t, rendered, ar.Binding.Reveal(), way)
		}

		assert.Contains(t, logged(v), endpoint.String(), "the authorization endpoint stays readable")
		assert.Contains(t, fmt.Sprint(v), "State: REDACTED")
	}

	b, err := json.Marshal(ar)
	require.NoError(t, err)
	assert.Contains(t, string(b), ar.State, "the JSON hand-off keeps the state")

	unparsable := oidcclient.AuthRequest{URL: "https://op.example/authorize?state=secret-state\x7f\n%zz"}
	assert.Contains(t, unparsable.String(), `URL: "REDACTED"`)
	assert.NotContains(t, logged(unparsable), "secret-state")
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

	public := op.config(func(c *oidcclient.Config) {
		c.AuthMethod, c.ClientSecret = oidcclient.AuthMethodNone, oidcclient.Secret{}
	})
	assert.Contains(t, public.String(), `ClientSecret: ""`, "a public client has no secret to redact")

	var none *oidcclient.Client

	assert.Equal(t, "oidcclient.Client(nil)", fmt.Sprintf("%v", none))
	assert.Contains(t, logged(none), "oidcclient.Client(nil)", "a nil *Client prints, and logs, without panicking")
}

// encodings renders v the ways encoding/json reaches it: directly, as a
// field of another value, and nested in a value that log/slog's JSON (and
// text) handler logs — slog calls LogValue for attribute values only, and
// encodes nested values with encoding/json.
func encodings(t *testing.T, v any) map[string]string {
	t.Helper()

	out := map[string]string{}

	direct, err := json.Marshal(v)
	require.NoError(t, err, "%T encodes", v)

	field, err := json.Marshal(struct{ V any }{v})
	require.NoError(t, err)

	out["json"], out["json field"] = string(direct), string(field)

	var text, js strings.Builder

	slog.New(slog.NewTextHandler(&text, nil)).Info("value", "wrapper", struct{ V any }{v})
	slog.New(slog.NewJSONHandler(&js, nil)).Info("value", "wrapper", struct{ V any }{v})
	out["slog text nested"], out["slog JSON nested"] = text.String(), js.String()

	return out
}

// assertEncodedRedacted fails for every encoding of v that contains one of
// the secrets.
func assertEncodedRedacted(t *testing.T, v any, secrets ...string) {
	t.Helper()

	for way, encoded := range encodings(t, v) {
		for _, secret := range secrets {
			assert.False(t, strings.Contains(encoded, secret), "%T encoded with %s reveals a secret", v, way)
		}
	}
}

// TestLoginSecretsStayOutOfJSON checks that the values holding a login's
// secrets — the binding secret of an AuthRequest, the binding, code and
// state of a Callback, the client secret and transaction keys of a Config —
// encode without them, including nested in a value slog's JSON handler
// logs, and pins the documents they encode as.
func TestLoginSecretsStayOutOfJSON(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)
	ar, code := op.begin(t, c, oidcclient.AuthOptions{})
	cb := callbackFor(ar, code)

	for _, v := range []any{*ar, ar} {
		assertEncodedRedacted(t, v, ar.Binding.Reveal())

		b, err := json.Marshal(v)
		require.NoError(t, err)
		assert.JSONEq(t, fmt.Sprintf(`{"URL":%q,"State":%q,"ExpiresAt":%q,"Binding":"REDACTED"}`,
			ar.URL, ar.State, ar.ExpiresAt.Format(time.RFC3339Nano)), string(b))
	}

	for _, v := range []any{cb, &cb} {
		assertEncodedRedacted(t, v, ar.Binding.Reveal(), code, ar.State)

		b, err := json.Marshal(v)
		require.NoError(t, err)
		assert.JSONEq(t, `{"Mode":"query","URL":"`+testRedirectURL+`","Params":2,"Binding":"REDACTED"}`, string(b))
	}

	b, err := json.Marshal(oidcclient.Callback{})
	require.NoError(t, err)
	assert.JSONEq(t, `{"Mode":"","URL":"","Params":0,"Binding":"REDACTED"}`, string(b), "a callback without URL")

	cfg := op.config()
	secrets := []string{testClientSecret, string(testTransactionKey), fmt.Sprintf("%x", testTransactionKey)[:16]}

	for _, v := range []any{cfg, &cfg} {
		assertEncodedRedacted(t, v, secrets...)

		b, err := json.Marshal(v)
		require.NoError(t, err)
		assert.JSONEq(t, fmt.Sprintf(`{"ConnectionID":%q,"Issuer":%q,"ClientID":%q,"ClientSecret":"REDACTED",`+
			`"AuthMethod":"client_secret_basic","RedirectURL":%q,"ResponseMode":"","TransactionKeys":1}`,
			testConnection, op.issuer, testClientID, testRedirectURL), string(b))
	}

	public := op.config(func(c *oidcclient.Config) {
		c.AuthMethod, c.ClientSecret = oidcclient.AuthMethodNone, oidcclient.Secret{}
	})
	b, err = json.Marshal(public)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"ClientSecret":""`, "a public client has no secret to redact")

	assertEncodedRedacted(t, c, secrets...)

	b, err = json.Marshal(c)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(b), "a *Client has no exported field")
}

// TestEmbeddingPromotesTheRedactedEncoding pins what embedding does: the
// struct is promoted the MarshalJSON of AuthRequest and Callback, so it
// encodes as the embedded value alone — name the field instead.
func TestEmbeddingPromotesTheRedactedEncoding(t *testing.T) {
	t.Parallel()

	ar := oidcclient.AuthRequest{URL: "https://op.example/authorize", State: "s", Binding: oidcclient.NewSecret("secret-binding")}

	type loginState struct {
		oidcclient.AuthRequest

		ReturnTo string
	}

	embedded, err := json.Marshal(loginState{AuthRequest: ar, ReturnTo: "/account"})
	require.NoError(t, err)

	alone, err := json.Marshal(ar)
	require.NoError(t, err)
	assert.JSONEq(t, string(alone), string(embedded), "the embedding struct encodes as the AuthRequest")
	assert.NotContains(t, string(embedded), "/account")

	type namedField struct {
		Login    oidcclient.AuthRequest
		ReturnTo string
	}

	named, err := json.Marshal(namedField{Login: ar, ReturnTo: "/account"})
	require.NoError(t, err)
	assert.Contains(t, string(named), `"ReturnTo":"/account"`)
	assert.NotContains(t, string(named), "secret-binding")

	// Another type with a MarshalJSON embedded at the same depth makes the
	// promotion ambiguous: neither method is promoted, and encoding/json
	// writes the exported fields of both. The secrets stay out all the same.
	type withStamp struct {
		oidcclient.AuthRequest
		stamp
	}

	flat, err := json.Marshal(withStamp{AuthRequest: ar, stamp: stamp{At: "now"}})
	require.NoError(t, err)
	assert.Contains(t, string(flat), `"State":"s"`, "flattened")
	assert.NotContains(t, string(flat), "secret-binding")

	received, err := url.Parse(testRedirectURL + "?code=code-xyz&state=state-xyz")
	require.NoError(t, err)

	cb := oidcclient.Callback{
		Mode: oidcclient.ResponseModeQuery, URL: received, Binding: oidcclient.NewSecret("callback-binding"),
		Params: url.Values{"code": {"code-xyz"}, "state": {"state-xyz"}},
	}

	type both struct {
		oidcclient.AuthRequest
		oidcclient.Callback
	}

	flat, err = json.Marshal(both{AuthRequest: ar, Callback: cb})
	require.NoError(t, err)
	assert.Contains(t, string(flat), `"Mode":"query"`, "flattened")

	for _, secret := range []string{"secret-binding", "callback-binding", "code-xyz", "state-xyz"} {
		assert.NotContains(t, string(flat), secret)
	}

	type callbackWithStamp struct {
		oidcclient.Callback
		stamp
	}

	flat, err = json.Marshal(callbackWithStamp{Callback: cb, stamp: stamp{At: "now"}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"Mode":"query","At":"now"}`, string(flat), "the URL, its query included, stays out")
}

// stamp has a value-receiver MarshalJSON, like many types an application
// embeds (time.Time has a MarshalText, which wins over both).
type stamp struct{ At string }

func (s stamp) MarshalJSON() ([]byte, error) { return json.Marshal(s.At) }

// TestIdentityEncodesWithoutItsTokens checks that an Identity encodes to
// JSON with its tokens REDACTED (they are Secrets) and its other fields as
// they are, and that the document does not decode back into an Identity:
// an application persists tokens by revealing them explicitly.
func TestIdentityEncodesWithoutItsTokens(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	id, err := op.login(t, op.client(t))
	require.NoError(t, err)

	b, err := json.Marshal(id)
	require.NoError(t, err)

	var doc struct {
		Subject string
		Claims  json.RawMessage
		Tokens  map[string]any
	}

	require.NoError(t, json.Unmarshal(b, &doc))
	assert.Equal(t, id.Subject, doc.Subject)
	assert.JSONEq(t, string(id.Claims), string(doc.Claims), "claims are not secrets")
	assert.Equal(t, "REDACTED", doc.Tokens["AccessToken"])
	assert.Equal(t, "REDACTED", doc.Tokens["RefreshToken"])
	assert.Equal(t, "REDACTED", doc.Tokens["IDToken"])
	assert.Equal(t, "Bearer", doc.Tokens["TokenType"])
	assert.NotContains(t, string(b), id.Tokens.IDToken.Reveal())

	var back oidcclient.Identity
	require.Error(t, json.Unmarshal(b, &back), "a redacted document never decodes back into credentials")
}

// TestUserInfoIsRedacted checks that UserInfo prints and logs its subject
// only: its claims are personal data.
func TestUserInfoIsRedacted(t *testing.T) {
	t.Parallel()

	ui := oidcclient.UserInfo{
		Subject: testSubject,
		Claims:  json.RawMessage(`{"sub":"` + testSubject + `","email":"jane@example.com","phone_number":"+1 555 0100"}`),
	}

	assertRedacted(t, ui, "jane@example.com", "555 0100")
	assertRedacted(t, &ui, "jane@example.com", "555 0100")
	assert.Equal(t, `oidcclient.UserInfo{Subject: "`+testSubject+`"}`, fmt.Sprintf("%v", ui))
	assert.Contains(t, logged(ui), testSubject, "the user stays recognizable")
}
