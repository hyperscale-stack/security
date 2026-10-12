// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loginResult is what a BeginLogin call produced.
type loginResult struct {
	url        *url.URL
	rawQuery   map[string]string // raw (still URL-encoded) query values
	relayState string
	request    *etree.Element // decoded AuthnRequest
	requestID  string
	cookie     *http.Cookie
}

// rawQueryValues splits a raw query into its still-encoded values.
func rawQueryValues(raw string) map[string]string {
	out := map[string]string{}

	for _, kv := range strings.Split(raw, "&") {
		k, v, _ := strings.Cut(kv, "=")
		out[k] = v
	}

	return out
}

// decodeAuthnRequest inflates and parses the SAMLRequest of a redirect URL.
func decodeAuthnRequest(t testing.TB, u *url.URL) *etree.Element {
	t.Helper()

	deflated, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	require.NoError(t, err)

	xmlBytes, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	require.NoError(t, err, "SAMLRequest must be raw DEFLATE (RFC 1951)")

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(xmlBytes))

	return doc.Root()
}

// begin runs BeginLogin with the given request cookies and decodes the
// outcome.
func begin(t testing.TB, e *env, opts samlsp.LoginOptions, cookies ...*http.Cookie) loginResult {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()

	raw, err := e.sp.BeginLogin(context.Background(), rec, req, connID, opts)
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)

	res := loginResult{url: u, rawQuery: rawQueryValues(u.RawQuery), relayState: u.Query().Get("RelayState")}
	res.request = decodeAuthnRequest(t, u)
	res.requestID = res.request.SelectAttrValue("ID", "")

	for _, c := range rec.Result().Cookies() {
		if c.Name == samlsp.DefaultCookieName {
			res.cookie = c
		}
	}

	require.NotNil(t, res.cookie, "BeginLogin must set the browser-binding cookie")

	return res
}

// digestHex mirrors the documented key derivation: SHA-256 over the parts
// joined by NUL bytes.
func digestHex(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))

	return hex.EncodeToString(sum[:])
}

func txKey(conn, relayState string) string {
	return digestHex("samlsp-v1/transaction", conn, relayState)
}
func bindingKey(cookie string) string { return digestHex("samlsp-v1/binding", cookie) }

var (
	requestIDPattern = regexp.MustCompile(`^_[0-9a-f]{64}$`)
	handlePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

func TestBeginLogin_AuthnRequestContent(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	res := begin(t, e, samlsp.LoginOptions{})

	assert.Equal(t, "https", res.url.Scheme)
	assert.Equal(t, "idp.example.com", res.url.Host)
	assert.Equal(t, "/sso", res.url.Path)
	assert.Equal(t, "acme", res.url.Query().Get("tenant"), "existing SSO URL parameters are preserved")
	assert.Empty(t, res.url.Query().Get("SigAlg"), "unsigned without an SP key")
	assert.Empty(t, res.url.Query().Get("Signature"))

	r := res.request
	assert.Equal(t, "AuthnRequest", r.Tag)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:protocol", r.NamespaceURI())
	assert.Regexp(t, requestIDPattern, res.requestID, "256-bit ID (Core §1.3.4)")
	assert.Equal(t, "2.0", r.SelectAttrValue("Version", ""))
	assert.Equal(t, "2026-10-12T10:00:00Z", r.SelectAttrValue("IssueInstant", ""))
	assert.Equal(t, ssoURL, r.SelectAttrValue("Destination", ""))
	assert.Equal(t, acsURL, r.SelectAttrValue("AssertionConsumerServiceURL", ""))
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", r.SelectAttrValue("ProtocolBinding", ""))
	assert.Nil(t, r.SelectAttr("ForceAuthn"))
	assert.Nil(t, r.SelectAttr("IsPassive"))

	issuer := r.FindElement("./Issuer")
	require.NotNil(t, issuer)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:assertion", issuer.NamespaceURI())
	assert.Equal(t, spEntityID, issuer.Text())
	assert.Nil(t, issuer.SelectAttr("Format"), "Format omitted (Profiles §4.1.4.1)")

	policy := r.FindElement("./NameIDPolicy")
	require.NotNil(t, policy)
	assert.Equal(t, "true", policy.SelectAttrValue("AllowCreate", ""))
	assert.Nil(t, policy.SelectAttr("Format"))

	assert.Nil(t, r.FindElement(".//Signature"), "no XML signature on the Redirect binding (Bindings §3.4.4.1)")
	assert.Nil(t, r.FindElement("./RequestedAuthnContext"))

	assert.Regexp(t, handlePattern, res.relayState)
	assert.LessOrEqual(t, len(res.relayState), 80, "Bindings §3.4.3")
}

func TestBeginLogin_Options(t *testing.T) {
	t.Parallel()

	e := newEnv(t, func(_ *samlsp.Config, c *samlsp.Connection) { c.NameIDFormat = samlsp.NameIDFormatPersistent })
	res := begin(t, e, samlsp.LoginOptions{
		ForceAuthn:            true,
		IsPassive:             true,
		RequestedAuthnContext: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:X509", "urn:example:mfa"},
	})

	r := res.request
	assert.Equal(t, "true", r.SelectAttrValue("ForceAuthn", ""))
	assert.Equal(t, "true", r.SelectAttrValue("IsPassive", ""))
	assert.Equal(t, samlsp.NameIDFormatPersistent, r.FindElement("./NameIDPolicy").SelectAttrValue("Format", ""))

	rac := r.FindElement("./RequestedAuthnContext")
	require.NotNil(t, rac)
	assert.Equal(t, "exact", rac.SelectAttrValue("Comparison", ""))

	var refs []string
	for _, el := range rac.FindElements("./AuthnContextClassRef") {
		refs = append(refs, el.Text())
	}

	assert.Equal(t, []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:X509", "urn:example:mfa"}, refs)
}

func TestBeginLogin_RequestIDEntropyAndUniqueness(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	seenIDs, seenHandles := map[string]bool{}, map[string]bool{}

	for i := 0; i < 200; i++ {
		res := begin(t, e, samlsp.LoginOptions{})
		require.Regexp(t, requestIDPattern, res.requestID)
		require.False(t, seenIDs[res.requestID], "request IDs never repeat")
		require.False(t, seenHandles[res.relayState], "RelayState handles never repeat")
		seenIDs[res.requestID], seenHandles[res.relayState] = true, true
	}
}

func TestBeginLogin_SignsRedirectQuery(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withSigningKey(t))
	res := begin(t, e, samlsp.LoginOptions{AppState: "/after"})

	sigAlg, err := url.QueryUnescape(res.rawQuery["SigAlg"])
	require.NoError(t, err)
	assert.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", sigAlg)

	// Bindings §3.4.4.1: the octets are the URL-encoded values exactly as
	// sent, in the order SAMLRequest, RelayState, SigAlg.
	octets := "SAMLRequest=" + res.rawQuery["SAMLRequest"] + "&RelayState=" + res.rawQuery["RelayState"] +
		"&SigAlg=" + res.rawQuery["SigAlg"]

	rawSig, err := url.QueryUnescape(res.rawQuery["Signature"])
	require.NoError(t, err)

	sig, err := base64.StdEncoding.DecodeString(rawSig)
	require.NoError(t, err)

	pub, ok := keys(t).sp.cert.PublicKey.(*rsa.PublicKey)
	require.True(t, ok)

	digest := sha256.Sum256([]byte(octets))
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig), "signature over the exact octets")

	tampered := sha256.Sum256([]byte(octets + "x"))
	require.Error(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, tampered[:], sig))

	assert.Nil(t, res.request.FindElement(".//Signature"), "the XML itself carries no signature")
}

func TestBeginLogin_PersistsBoundTransaction(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	res := begin(t, e, samlsp.LoginOptions{AppState: "/projects/42?tab=1", ForceAuthn: true})

	rec, err := e.store.LookupTransaction(context.Background(), txKey(connID, res.relayState))
	require.NoError(t, err, "the transaction is keyed by (connection, RelayState handle)")

	assert.Equal(t, bindingKey(res.cookie.Value), rec.BindingHash)
	assert.True(t, rec.ExpiresAt.Equal(t0.Add(samlsp.DefaultTransactionTTL)))
	assert.Equal(t, integrityHex(testTransactionKeys[0], rec), rec.Integrity,
		"the documented MAC under the first transaction key, computed independently")
	assert.NotContains(t, rec.Payload, res.relayState, "the raw handle is never stored")
	assert.NotContains(t, rec.Payload, res.cookie.Value, "the cookie value is never stored")

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(rec.Payload), &payload))
	assert.Equal(t, res.requestID, payload["req"])
	assert.Equal(t, connID, payload["conn"])
	assert.Equal(t, idpEntity, payload["idp"])
	assert.Equal(t, spEntityID, payload["sp"])
	assert.Equal(t, acsURL, payload["acs"])
	assert.InDelta(t, float64(t0.Unix()), payload["iat"], 0)
	assert.Equal(t, "/projects/42?tab=1", payload["app"])
	assert.Equal(t, true, payload["fa"])
}

func TestBeginLogin_BindingCookie(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	first := begin(t, e, samlsp.LoginOptions{})

	c := first.cookie
	assert.Regexp(t, handlePattern, c.Value, "256-bit random value")
	assert.Equal(t, "/", c.Path)
	assert.Empty(t, c.Domain, "__Host- forbids Domain")
	assert.True(t, c.Secure)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteNoneMode, c.SameSite, "sent on the IdP's cross-site POST")
	assert.Equal(t, int(samlsp.DefaultTransactionTTL/time.Second), c.MaxAge)

	// A second login from the same browser reuses the binding value, so
	// concurrent tabs keep working.
	second := begin(t, e, samlsp.LoginOptions{}, &http.Cookie{Name: samlsp.DefaultCookieName, Value: c.Value})
	assert.Equal(t, c.Value, second.cookie.Value)

	for _, res := range []loginResult{first, second} {
		rec, err := e.store.LookupTransaction(context.Background(), txKey(connID, res.relayState))
		require.NoError(t, err)
		assert.Equal(t, bindingKey(c.Value), rec.BindingHash)
	}

	// A malformed cookie is replaced.
	third := begin(t, e, samlsp.LoginOptions{}, &http.Cookie{Name: samlsp.DefaultCookieName, Value: "short"})
	assert.NotEqual(t, "short", third.cookie.Value)
	assert.Regexp(t, handlePattern, third.cookie.Value)
}

func TestBeginLogin_CustomCookieAndTTL(t *testing.T) {
	t.Parallel()

	e := newEnv(t, func(c *samlsp.Config, _ *samlsp.Connection) {
		c.CookieName = "__Host-tenant"
		c.TransactionTTL = 90 * time.Second
	})

	rec := httptest.NewRecorder()
	_, err := e.sp.BeginLogin(context.Background(), rec, httptest.NewRequest(http.MethodGet, "/", nil), connID, samlsp.LoginOptions{})
	require.NoError(t, err)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "__Host-tenant", cookies[0].Name)
	assert.Equal(t, 90, cookies[0].MaxAge)
}

// failingStore fails SaveTransaction.
type failingStore struct {
	samlsp.Storage
	err error
}

func (f failingStore) SaveTransaction(context.Context, *samlsp.TransactionRecord) error { return f.err }

func TestBeginLogin_Failures(t *testing.T) {
	t.Parallel()

	boom := errors.New("store down")
	longContext := "urn:" + strings.Repeat("x", 1021)

	cases := []struct {
		name   string
		setup  func(*env)
		conn   string
		opts   samlsp.LoginOptions
		target error
	}{
		{name: "unknown connection", conn: "nope", target: samlsp.ErrUnknownConnection},
		{name: "invalid connection", setup: func(e *env) {
			c := newConnection(t)
			c.ACSURL = "http://sp.example.com/acs"
			e.resolver.set(c)
		}, target: samlsp.ErrInvalidConnection},
		{name: "expired metadata", setup: func(e *env) {
			c := newConnection(t)
			c.IdentityProvider.ValidUntil = t0
			e.resolver.set(c)
		}, target: samlsp.ErrMetadataExpired},
		{name: "IdP wants signed requests", setup: func(e *env) {
			c := newConnection(t)
			c.IdentityProvider.WantAuthnRequestsSigned = true
			e.resolver.set(c)
		}, target: samlsp.ErrInvalidConfig},
		{name: "app state too long", opts: samlsp.LoginOptions{AppState: strings.Repeat("a", 2049)}, target: samlsp.ErrInvalidLoginOptions},
		{name: "app state not UTF-8", opts: samlsp.LoginOptions{AppState: "\xff"}, target: samlsp.ErrInvalidLoginOptions},
		{name: "app state with NUL", opts: samlsp.LoginOptions{AppState: "a\x00"}, target: samlsp.ErrInvalidLoginOptions},
		{name: "too many contexts", opts: samlsp.LoginOptions{RequestedAuthnContext: strings.Split(strings.Repeat("urn:x,", 9)[:53], ",")}, target: samlsp.ErrInvalidLoginOptions},
		{name: "empty context", opts: samlsp.LoginOptions{RequestedAuthnContext: []string{""}}, target: samlsp.ErrInvalidLoginOptions},
		{name: "relative context", opts: samlsp.LoginOptions{RequestedAuthnContext: []string{"mfa"}}, target: samlsp.ErrInvalidLoginOptions},
		{name: "context too long", opts: samlsp.LoginOptions{RequestedAuthnContext: []string{longContext}}, target: samlsp.ErrInvalidLoginOptions},
		{name: "store failure", setup: func(e *env) {
			sp, err := samlsp.New(samlsp.Config{TransactionKeys: testTransactionKeys, Connections: e.resolver, Transactions: failingStore{e.store, boom}, ReplayCache: e.store, Now: e.clock.Now})
			require.NoError(t, err)
			e.sp = sp
		}, target: boom},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}

			conn := tc.conn
			if conn == "" {
				conn = connID
			}

			rec := httptest.NewRecorder()
			raw, err := e.sp.BeginLogin(context.Background(), rec, httptest.NewRequest(http.MethodGet, "/", nil), conn, tc.opts)
			require.ErrorIs(t, err, tc.target)
			assert.Empty(t, raw)
			assert.Empty(t, rec.Result().Cookies(), "no cookie on failure")
		})
	}
}

func TestBeginLogin_NilArguments(t *testing.T) {
	t.Parallel()

	e := newEnv(t)

	_, err := e.sp.BeginLogin(context.Background(), nil, httptest.NewRequest(http.MethodGet, "/", nil), connID, samlsp.LoginOptions{})
	require.ErrorIs(t, err, samlsp.ErrInvalidConfig)

	_, err = e.sp.BeginLogin(context.Background(), httptest.NewRecorder(), nil, connID, samlsp.LoginOptions{})
	require.ErrorIs(t, err, samlsp.ErrInvalidConfig)
}

func TestBeginLogin_MaximalOptionsFitTheStore(t *testing.T) {
	t.Parallel()

	e := newEnv(t)

	contexts := make([]string, 8)
	for i := range contexts {
		contexts[i] = "urn:" + strings.Repeat(string(rune('a'+i)), 1020)
	}

	res := begin(t, e, samlsp.LoginOptions{AppState: strings.Repeat("é", 1024), RequestedAuthnContext: contexts})
	_, err := e.store.LookupTransaction(context.Background(), txKey(connID, res.relayState))
	require.NoError(t, err)
}

// TestBeginLogin_PayloadIsASCII: the transaction payload is ASCII-only
// JSON (every other character \u-escaped), so every store column type and
// character set keeps it unchanged — a latin1, non-strict MySQL altered a
// raw UTF-8 AppState (audit STORE-I2) — and the AppState comes back exact.
func TestBeginLogin_PayloadIsASCII(t *testing.T) {
	t.Parallel()

	const appState = "/retour?ville=Z\u00fcrich&ok=\u2713&emoji=\U0001f600&ctl=\u007f&c1=\u0080"

	e := newEnv(t)
	res := begin(t, e, samlsp.LoginOptions{AppState: appState})

	rec, err := e.store.LookupTransaction(context.Background(), txKey(connID, res.relayState))
	require.NoError(t, err)

	for i := 0; i < len(rec.Payload); i++ {
		require.Less(t, rec.Payload[i], byte(0x80), "byte %d of the payload is not ASCII: %q", i, rec.Payload)
	}

	assert.Contains(t, rec.Payload, `\u00fc`)
	assert.Contains(t, rec.Payload, `\ud83d\ude00`, "a surrogate pair above U+FFFF")

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(rec.Payload), &payload))
	assert.Equal(t, appState, payload["app"])

	out, err := complete(e, res, respond(t, res.requestID, respOpts{}))
	require.NoError(t, err)
	assert.Equal(t, appState, out.AppState)
}

func TestBeginLogin_OptionsOverflowingThePayload(t *testing.T) {
	t.Parallel()

	// Each option within its own limit, but '<' is JSON-escaped to six
	// bytes: the transaction would exceed MaxTransactionPayloadSize. That is
	// an invalid option, not a store failure (code review F8).
	e := newEnv(t)

	contexts := make([]string, 8)
	for i := range contexts {
		contexts[i] = "urn:" + strings.Repeat("<", 1020)
	}

	rec := httptest.NewRecorder()
	_, err := e.sp.BeginLogin(context.Background(), rec, httptest.NewRequest(http.MethodGet, "/login", nil), connID,
		samlsp.LoginOptions{AppState: strings.Repeat("<", 2048), RequestedAuthnContext: contexts})
	require.ErrorIs(t, err, samlsp.ErrInvalidLoginOptions)
	assert.Empty(t, rec.Result().Cookies(), "nothing stored, no cookie")
}

// failingSigner is an RSA signer whose Sign fails (an unreachable KMS).
type failingSigner struct{ crypto.Signer }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("kms unreachable")
}

func TestBeginLogin_SigningFailure(t *testing.T) {
	t.Parallel()

	e := newEnv(t, func(c *samlsp.Config, _ *samlsp.Connection) {
		c.SigningKey = failingSigner{keys(t).sp.signer}
		c.SigningCertificate = keys(t).sp.cert
	})

	rec := httptest.NewRecorder()
	raw, err := e.sp.BeginLogin(context.Background(), rec, httptest.NewRequest(http.MethodGet, "/", nil), connID, samlsp.LoginOptions{})
	require.Error(t, err)
	assert.Empty(t, raw)
	assert.Empty(t, rec.Result().Cookies(), "no cookie when the request cannot be signed")
}
