// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The IdP of this test is simulated: a throwaway key generated at run time
// signs the responses (nothing secret is committed).
const (
	idpEntityID = "https://idp.example.test/metadata"
	idpSSOURL   = "https://idp.example.test/sso"
	nameID      = "a7f3c9e1-pairwise"
)

type testIdP struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newTestIdP(t *testing.T) testIdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test IdP"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return testIdP{key: key, cert: cert}
}

func (i testIdP) metadata() []byte {
	return fmt.Appendf(nil, `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, idpEntityID, base64.StdEncoding.EncodeToString(i.cert.Raw), idpSSOURL)
}

func samlTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func randomID(t *testing.T) string {
	t.Helper()

	b := make([]byte, 16)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return "_" + hex.EncodeToString(b)
}

// response returns a base64 SAMLResponse answering requestID, with a
// signed assertion for nameID ending the IdP session at sessionEnd.
func (i testIdP) response(t *testing.T, requestID, acsURL, audience string, now, sessionEnd time.Time) string {
	t.Helper()

	const (
		nsP = "urn:oasis:names:tc:SAML:2.0:protocol"
		nsA = "urn:oasis:names:tc:SAML:2.0:assertion"
	)

	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsA)
	a.CreateAttr("ID", randomID(t))
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", samlTime(now))
	a.CreateElement("saml:Issuer").SetText(idpEntityID)

	subject := a.CreateElement("saml:Subject")
	nid := subject.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
	nid.SetText(nameID)

	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("InResponseTo", requestID)
	scd.CreateAttr("NotOnOrAfter", samlTime(now.Add(5*time.Minute)))
	scd.CreateAttr("Recipient", acsURL)

	conditions := a.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", samlTime(now.Add(-time.Minute)))
	conditions.CreateAttr("NotOnOrAfter", samlTime(now.Add(5*time.Minute)))
	conditions.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(audience)

	authn := a.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", samlTime(now))
	authn.CreateAttr("SessionIndex", "_session-1")
	authn.CreateAttr("SessionNotOnOrAfter", samlTime(sessionEnd))
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	attr := a.CreateElement("saml:AttributeStatement").CreateElement("saml:Attribute")
	attr.CreateAttr("Name", mailAttribute)
	attr.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
	attr.CreateElement("saml:AttributeValue").SetText("alice@example.com")

	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsP)
	resp.CreateAttr("xmlns:saml", nsA)
	resp.CreateAttr("ID", randomID(t))
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", samlTime(now))
	resp.CreateAttr("Destination", acsURL)
	resp.CreateAttr("InResponseTo", requestID)
	resp.CreateElement("saml:Issuer").SetText(idpEntityID)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").
		CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	resp.AddChild(i.sign(t, a))

	doc := etree.NewDocument()
	doc.SetRoot(resp)

	out, err := doc.WriteToBytes()
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(out)
}

// sign signs el (enveloped, exclusive C14N, rsa-sha256) and places the
// signature right after its Issuer, as the SAML schema requires.
func (i testIdP) sign(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()

	ctx, err := dsig.NewSigningContext(i.key, [][]byte{i.cert.Raw})
	require.NoError(t, err)

	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	require.NoError(t, ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod))

	signed, err := ctx.SignEnveloped(el)
	require.NoError(t, err)

	// Reparse (goxmldsig appends the signature without a parent link),
	// then move the signature after Issuer.
	doc := etree.NewDocument()
	doc.SetRoot(signed)

	raw, err := doc.WriteToBytes()
	require.NoError(t, err)

	parsed := etree.NewDocument()
	require.NoError(t, parsed.ReadFromBytes(raw))

	root := parsed.Root()
	sig := root.ChildElements()[len(root.ChildElements())-1]
	root.RemoveChild(sig)
	root.InsertChildAt(1, sig)

	return root
}

// requestID inflates the AuthnRequest of an HTTP-Redirect URL and returns
// its ID.
func requestID(t *testing.T, location *url.URL) string {
	t.Helper()

	deflated, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLRequest"))
	require.NoError(t, err)

	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(raw))

	return doc.Root().SelectAttrValue("ID", "")
}

type harness struct {
	t      *testing.T
	idp    testIdP
	base   string
	client *http.Client
	offset atomic.Int64 // clock offset
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	h := &harness{t: t, idp: newTestIdP(t)}

	srv := httptest.NewUnstartedServer(nil)
	h.base = "http://" + srv.Listener.Addr().String()

	handler, err := newServer(appConfig{
		baseURL:      h.base,
		connectionID: "corp",
		idpMetadata:  h.idp.metadata(),
		now:          func() time.Time { return time.Now().Add(time.Duration(h.offset.Load())) },
	})
	require.NoError(t, err)

	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)

	h.client = h.newBrowser()

	return h
}

// newBrowser returns a client with its own cookie jar that does not follow
// redirects. Loopback origins count as secure, as in browsers.
func (h *harness) newBrowser() *http.Client {
	jar, err := cookiejar.New(nil)
	require.NoError(h.t, err)

	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (h *harness) get(client *http.Client, path string) (*http.Response, string) {
	h.t.Helper()

	resp, err := client.Get(h.base + path)
	require.NoError(h.t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)

	return resp, string(body)
}

// startLogin follows /login?return=… to the IdP redirect and returns the
// AuthnRequest ID and the RelayState.
func (h *harness) startLogin(client *http.Client, returnTo string) (string, string) {
	h.t.Helper()

	resp, _ := h.get(client, "/login?return="+url.QueryEscape(returnTo))
	require.Equal(h.t, http.StatusFound, resp.StatusCode)

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(h.t, err)
	require.Equal(h.t, idpSSOURL, location.Scheme+"://"+location.Host+location.Path)

	return requestID(h.t, location), location.Query().Get("RelayState")
}

// post submits an IdP response to the ACS.
func (h *harness) post(client *http.Client, samlResponse, relayState string) (*http.Response, string) {
	h.t.Helper()

	resp, err := client.PostForm(h.base+"/saml/corp/acs", url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}})
	require.NoError(h.t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)

	return resp, string(body)
}

// respond is the IdP answering request id for this SP.
func (h *harness) respond(id string, sessionEnd time.Time) string {
	return h.idp.response(h.t, id, h.base+"/saml/corp/acs", h.base+"/saml/corp", time.Now(), sessionEnd)
}

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func TestSAMLSPExample(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	// The SP metadata is published per connection.
	resp, body := h.get(h.client, "/saml/corp/metadata")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/samlmetadata+xml", resp.Header.Get("Content-Type"))
	assert.Contains(t, body, `entityID="`+h.base+`/saml/corp"`)
	assert.Contains(t, body, `Location="`+h.base+`/saml/corp/acs"`)

	resp, _ = h.get(h.client, "/saml/other/metadata")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Signed out: a login link.
	_, body = h.get(h.client, "/")
	assert.Contains(t, body, `href="/login"`)

	// Login sets the browser-binding cookie and redirects to the IdP.
	resp, _ = h.get(h.client, "/login?return=/account")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	var binding *http.Cookie

	for _, c := range resp.Cookies() {
		if c.Name == "__Host-samlsp" {
			binding = c
		}
	}

	require.NotNil(t, binding)
	assert.True(t, binding.Secure)
	assert.True(t, binding.HttpOnly)
	assert.Equal(t, http.SameSiteNoneMode, binding.SameSite)
	assert.Equal(t, "/", binding.Path)
	assert.Empty(t, binding.Domain)

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	id, relayState := requestID(t, location), location.Query().Get("RelayState")
	samlResponse := h.respond(id, time.Now().Add(time.Hour))

	// The ACS creates the session and goes to the (local) return path.
	resp, _ = h.post(h.client, samlResponse, relayState)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/account", resp.Header.Get("Location"))

	_, body = h.get(h.client, "/")
	assert.Contains(t, body, nameID)
	assert.Contains(t, body, "alice@example.com")

	// The same response cannot be used twice: a generic page, never an
	// HTTP error status (Bindings §3.5.6), and no detail.
	resp, body = h.post(h.client, samlResponse, relayState)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "Sign-in failed")
	assert.Empty(t, resp.Cookies())

	// Logout (CSRF-protected) ends the local session.
	_, body = h.get(h.client, "/")
	token := csrfRE.FindStringSubmatch(body)
	require.NotNil(t, token)

	resp, err = h.client.PostForm(h.base+"/logout", url.Values{"csrf_token": {token[1]}})
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	_, body = h.get(h.client, "/")
	assert.Contains(t, body, `href="/login"`)
}

func TestSAMLSPExampleRefusesOtherBrowsers(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	id, relayState := h.startLogin(h.client, "/")

	// The response delivered to another browser (no binding cookie) is
	// refused and creates no session.
	stranger := h.newBrowser()
	resp, body := h.post(stranger, h.respond(id, time.Now().Add(time.Hour)), relayState)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "Sign-in failed")
	assert.Empty(t, resp.Cookies())

	_, body = h.get(stranger, "/")
	assert.Contains(t, body, `href="/login"`)
}

func TestSAMLSPExampleNoOpenRedirect(t *testing.T) {
	t.Parallel()

	// Browsers strip TAB, LF and CR from URLs: "/\t/evil.example" is
	// "//evil.example", another origin (code review F1).
	for _, target := range []string{"https://evil.example/phish", "/\t/evil.example/phish", "/%2F/evil.example"} {
		h := newHarness(t)
		id, relayState := h.startLogin(h.client, target)

		resp, _ := h.post(h.client, h.respond(id, time.Now().Add(time.Hour)), relayState)
		require.Equal(t, http.StatusSeeOther, resp.StatusCode, target)
		assert.Equal(t, "/", resp.Header.Get("Location"), target)
	}
}

func TestSAMLSPExampleSessionEndsWithTheIdPSession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	id, relayState := h.startLogin(h.client, "/")

	resp, _ := h.post(h.client, h.respond(id, time.Now().Add(10*time.Minute)), relayState)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	_, body := h.get(h.client, "/")
	assert.Contains(t, body, "Signed in")

	// Past SessionNotOnOrAfter the local session is no longer honored.
	h.offset.Store(int64(11 * time.Minute))

	_, body = h.get(h.client, "/")
	assert.Contains(t, body, `href="/login"`)
}

func TestSafeReturn(t *testing.T) {
	t.Parallel()

	for target, want := range map[string]string{
		"/account":                   "/account",
		"/a/b?c=d&e=f":               "/a/b?c=d&e=f",
		"/":                          "/",
		"/caf%C3%A9":                 "/caf%C3%A9",
		"/~user/a-b_c.d!$'()*+,;=:@": "/~user/a-b_c.d!$'()*+,;=:@",

		"":                     "/",
		"account":              "/",
		"https://evil.example": "/",
		"javascript:alert(1)":  "/",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"\\/evil.example":      "/",
		"/x\r\nSet-Cookie: a":  "/",
		"/a#fragment":          "/",
		// WHATWG URL parsers strip TAB, LF and CR, which turns these into
		// "//evil.example" (code review F1); every other control, white
		// space and non-ASCII character is refused too.
		"/\t/evil.example/phish": "/",
		"/\n/evil.example":       "/",
		"/\r/evil.example":       "/",
		"\t//evil.example":       "/",
		"/\x0b/evil.example":     "/",
		"/\x00/evil.example":     "/",
		"/\x7f/evil.example":     "/",
		"/ /evil.example":        "/",
		" /account":              "/",
		"/\u00a0/evil.example":   "/",
		"/\u3000/evil.example":   "/",
		// Percent-decoding must not reveal another origin either.
		"/%2F/evil.example":             "/",
		"/%2f%2fevil.example":           "/",
		"/%5Cevil.example":              "/",
		"/%09/evil.example":             "/",
		"/%zz":                          "/",
		"/" + strings.Repeat("a", 1024): "/",
	} {
		assert.Equal(t, want, safeReturn(target), "%q", target)
	}
}

func TestAccountKey(t *testing.T) {
	t.Parallel()

	id := func(conn, issuer, nameID string) *samlsp.Identity {
		return &samlsp.Identity{
			ConnectionID: conn, Issuer: issuer, Audience: "https://sp.example.test/saml/" + conn,
			NameID: samlsp.NameID{Value: nameID, Format: samlsp.NameIDFormatPersistent},
		}
	}

	// ("a|b", "c") and ("a", "b|c") must not collide (code review F11).
	assert.NotEqual(t, accountKey(id("a|b", idpEntityID, "c")), accountKey(id("a", idpEntityID, "b|c")))

	// The issuer and the qualifiers are part of the key; absent qualifiers
	// stand for the issuer and the audience.
	base := id("corp", idpEntityID, "u")
	assert.Equal(t, accountKey(base), accountKey(id("corp", idpEntityID, "u")))
	assert.NotEqual(t, accountKey(base), accountKey(id("corp", "https://other-idp.example.test", "u")))

	qualified := id("corp", idpEntityID, "u")
	qualified.NameID.NameQualifier, qualified.NameID.SPNameQualifier = idpEntityID, qualified.Audience
	assert.Equal(t, accountKey(base), accountKey(qualified))

	qualified.NameID.SPNameQualifier = "https://other-sp.example.test"
	assert.NotEqual(t, accountKey(base), accountKey(qualified))
}

func TestNewServerRejectsBadMetadata(t *testing.T) {
	t.Parallel()

	_, err := newServer(appConfig{baseURL: "http://127.0.0.1:1", connectionID: "corp", idpMetadata: []byte("<nope/>")})
	require.Error(t, err)

	_, err = newServer(appConfig{baseURL: "ftp://example.com", connectionID: "corp", idpMetadata: newTestIdP(t).metadata()})
	require.Error(t, err)
}
