// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- SP metadata ----------------------------------------------------------

func parseXML(t *testing.T, b []byte) *etree.Element {
	t.Helper()

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(b))

	return doc.Root()
}

func TestMetadata_Content(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withSigningKey(t), func(c *samlsp.Config, conn *samlsp.Connection) {
		c.AdditionalSigningCertificates = []*x509.Certificate{keys(t).spNext.cert}
		c.MetadataCacheDuration = 12 * time.Hour
		conn.NameIDFormat = samlsp.NameIDFormatPersistent
	})

	body, err := e.sp.Metadata(context.Background(), connID)
	require.NoError(t, err)

	root := parseXML(t, body)
	assert.Equal(t, "EntityDescriptor", root.Tag)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:metadata", root.NamespaceURI())
	assert.Equal(t, spEntityID, root.SelectAttrValue("entityID", ""))
	assert.Equal(t, "PT43200S", root.SelectAttrValue("cacheDuration", ""))
	assert.Nil(t, root.SelectAttr("validUntil"), "no validUntil: an administrator's copy never expires")

	sso := root.FindElement("./SPSSODescriptor")
	require.NotNil(t, sso)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:protocol", sso.SelectAttrValue("protocolSupportEnumeration", ""))
	assert.Equal(t, "true", sso.SelectAttrValue("AuthnRequestsSigned", ""))
	assert.Nil(t, sso.SelectAttr("WantAssertionsSigned"), "WantAssertionsSigned is omitted (errata E93/E26)")
	assert.Empty(t, root.FindElements(".//SingleLogoutService"))

	kds := sso.FindElements("./KeyDescriptor")
	require.Len(t, kds, 2, "signing certificate and the rollover one")

	for i, want := range []*x509.Certificate{keys(t).sp.cert, keys(t).spNext.cert} {
		assert.Equal(t, "signing", kds[i].SelectAttrValue("use", ""), "explicit use: no encryption key is announced")
		cert := kds[i].FindElement("./KeyInfo/X509Data/X509Certificate")
		require.NotNil(t, cert)
		assert.Equal(t, "http://www.w3.org/2000/09/xmldsig#", cert.NamespaceURI())
		assert.Equal(t, base64.StdEncoding.EncodeToString(want.Raw), cert.Text())
	}

	nif := sso.FindElement("./NameIDFormat")
	require.NotNil(t, nif)
	assert.Equal(t, samlsp.NameIDFormatPersistent, nif.Text())

	acs := sso.FindElements("./AssertionConsumerService")
	require.Len(t, acs, 1)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs[0].SelectAttrValue("Binding", ""))
	assert.Equal(t, acsURL, acs[0].SelectAttrValue("Location", ""))
	assert.Equal(t, "0", acs[0].SelectAttrValue("index", ""))
	assert.Equal(t, "true", acs[0].SelectAttrValue("isDefault", ""))
}

func TestMetadata_UnsignedSPHasNoKey(t *testing.T) {
	t.Parallel()

	e := newEnv(t)

	body, err := e.sp.Metadata(context.Background(), connID)
	require.NoError(t, err)

	root := parseXML(t, body)
	sso := root.FindElement("./SPSSODescriptor")
	assert.Equal(t, "false", sso.SelectAttrValue("AuthnRequestsSigned", ""))
	assert.Empty(t, sso.FindElements("./KeyDescriptor"))
	assert.Empty(t, sso.FindElements("./NameIDFormat"))
	assert.Equal(t, "PT86400S", root.SelectAttrValue("cacheDuration", ""), "default cache duration")
}

func TestMetadata_PerConnection(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	other := newConnection(t)
	other.ID = "globex"
	other.SPEntityID = "https://sp.example.com/saml/globex"
	other.ACSURL = "https://sp.example.com/saml/globex/acs"
	e.resolver.set(other)

	body, err := e.sp.Metadata(context.Background(), "globex")
	require.NoError(t, err)

	root := parseXML(t, body)
	assert.Equal(t, "https://sp.example.com/saml/globex", root.SelectAttrValue("entityID", ""))
	assert.Equal(t, "https://sp.example.com/saml/globex/acs",
		root.FindElement(".//AssertionConsumerService").SelectAttrValue("Location", ""))
}

func TestServeMetadata(t *testing.T) {
	t.Parallel()

	e := newEnv(t)

	serve := func(method, conn string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		e.sp.ServeMetadata(rec, httptest.NewRequest(method, "/saml/"+conn+"/metadata", nil), conn)

		return rec
	}

	rec := serve(http.MethodGet, connID)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/samlmetadata+xml", rec.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=86400", rec.Header().Get("Cache-Control"))
	assert.Equal(t, spEntityID, parseXML(t, rec.Body.Bytes()).SelectAttrValue("entityID", ""))

	rec = serve(http.MethodHead, connID)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.Bytes())
	assert.NotEmpty(t, rec.Header().Get("Content-Length"))

	rec = serve(http.MethodPost, connID)
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, "GET, HEAD", rec.Header().Get("Allow"))

	rec = serve(http.MethodGet, "unknown")
	require.Equal(t, http.StatusNotFound, rec.Code)

	e.resolver.err = assert.AnError
	rec = serve(http.MethodGet, connID)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), assert.AnError.Error())
}

// ---- IdP metadata import ---------------------------------------------------

// idpMetadataSpec describes a test IdP metadata document.
type idpMetadataSpec struct {
	root, entityExtra, roleAttrs, roleExtra string
	entityID                                string
	keyDescriptors                          string
	sso                                     string
}

func certB64(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }

func keyDescriptor(use string, certs ...*x509.Certificate) string {
	attr := ""
	if use != "" {
		attr = ` use="` + use + `"`
	}

	var b strings.Builder
	for _, c := range certs {
		b.WriteString(`<ds:X509Certificate>` + certB64(c) + `</ds:X509Certificate>`)
	}

	return `<md:KeyDescriptor` + attr + `><ds:KeyInfo><ds:X509Data>` + b.String() +
		`</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
}

func (s idpMetadataSpec) render(t *testing.T) []byte {
	t.Helper()

	if s.entityID == "" {
		s.entityID = idpEntity
	}

	if s.keyDescriptors == "" {
		s.keyDescriptors = keyDescriptor("signing", keys(t).idpA.cert)
	}

	if s.sso == "" {
		s.sso = `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/post"/>` +
			`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>` +
			`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/second"/>`
	}

	entity := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` +
		s.entityID + `"` + s.entityExtra + `>` +
		`<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol"` +
		s.roleAttrs + `>` + s.keyDescriptors + s.roleExtra + s.sso + `</md:IDPSSODescriptor></md:EntityDescriptor>`

	if s.root != "" {
		return []byte(strings.Replace(s.root, "ENTITY", entity, 1))
	}

	return []byte(entity)
}

func parseMetadata(data []byte, opts samlsp.MetadataOptions) (*samlsp.IdentityProvider, error) {
	if opts.Now == nil {
		opts.Now = func() time.Time { return t0 }
	}

	return samlsp.ParseIdentityProviderMetadata(data, opts)
}

func TestParseIdentityProviderMetadata(t *testing.T) {
	t.Parallel()

	k := keys(t)

	idp, err := parseMetadata(idpMetadataSpec{
		keyDescriptors: keyDescriptor("signing", k.idpA.cert) + keyDescriptor("", k.idpB.cert) +
			keyDescriptor("encryption", k.attacker.cert) + keyDescriptor("signing", k.idpA.cert),
		roleAttrs:   ` WantAuthnRequestsSigned="true"`,
		entityExtra: ` validUntil="2026-10-20T00:00:00Z" cacheDuration="PT6H"`,
	}.render(t), samlsp.MetadataOptions{})
	require.NoError(t, err)

	assert.Equal(t, idpEntity, idp.EntityID)
	assert.Equal(t, "https://idp.example.com/sso", idp.SSOURL, "first HTTP-Redirect endpoint")
	require.Len(t, idp.SigningCertificates, 2, "signing + use-less keys, encryption ignored, duplicates removed")
	assert.True(t, idp.SigningCertificates[0].Equal(k.idpA.cert))
	assert.True(t, idp.SigningCertificates[1].Equal(k.idpB.cert))
	assert.True(t, idp.WantAuthnRequestsSigned)
	assert.True(t, idp.ValidUntil.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)))
	assert.Equal(t, 6*time.Hour, idp.CacheDuration)
	require.NoError(t, idp.Validate())
}

func TestParseIdentityProviderMetadata_WantAuthnRequestsSigned(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]bool{"true": true, "1": true, " false ": false, "0": false} {
		idp, err := parseMetadata(idpMetadataSpec{roleAttrs: ` WantAuthnRequestsSigned="` + value + `"`}.render(t), samlsp.MetadataOptions{})
		require.NoError(t, err, value)
		assert.Equal(t, want, idp.WantAuthnRequestsSigned, value)
	}

	idp, err := parseMetadata(idpMetadataSpec{}.render(t), samlsp.MetadataOptions{})
	require.NoError(t, err)
	assert.False(t, idp.WantAuthnRequestsSigned, "absent means false")
}

func TestParseIdentityProviderMetadata_ValidityMinimum(t *testing.T) {
	t.Parallel()

	root := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2026-10-30T00:00:00Z" cacheDuration="PT2H">ENTITY</md:EntitiesDescriptor>`

	idp, err := parseMetadata(idpMetadataSpec{
		root:        root,
		entityExtra: ` validUntil="2026-10-25T00:00:00Z" cacheDuration="PT4H"`,
		roleAttrs:   ` validUntil="2026-10-28T00:00:00Z" cacheDuration="PT1H"`,
	}.render(t), samlsp.MetadataOptions{})
	require.NoError(t, err)

	assert.True(t, idp.ValidUntil.Equal(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)), "smallest validUntil (E76)")
	assert.Equal(t, time.Hour, idp.CacheDuration, "smallest cacheDuration (E76)")
}

func TestParseIdentityProviderMetadata_EntitiesDescriptor(t *testing.T) {
	t.Parallel()

	k := keys(t)
	two := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">ENTITY` +
		`<md:EntityDescriptor entityID="https://other.example.com"/></md:EntitiesDescriptor>`

	// Several entities: the pin selects.
	idp, err := parseMetadata(idpMetadataSpec{root: two}.render(t), samlsp.MetadataOptions{EntityID: idpEntity})
	require.NoError(t, err)
	assert.Equal(t, idpEntity, idp.EntityID)
	assert.True(t, idp.SigningCertificates[0].Equal(k.idpA.cert))

	// Several entities without a pin: ambiguous.
	_, err = parseMetadata(idpMetadataSpec{root: two}.render(t), samlsp.MetadataOptions{})
	require.ErrorIs(t, err, samlsp.ErrInvalidMetadata)

	// A single entity needs no pin.
	one := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">ENTITY</md:EntitiesDescriptor>`
	_, err = parseMetadata(idpMetadataSpec{root: one}.render(t), samlsp.MetadataOptions{})
	require.NoError(t, err)
}

func TestParseIdentityProviderMetadata_Refusals(t *testing.T) {
	t.Parallel()

	k := keys(t)
	redirect := func(loc string) string {
		return `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + loc + `"/>`
	}

	cases := []struct {
		name string
		doc  []byte
		opts samlsp.MetadataOptions
	}{
		{"pin mismatch", idpMetadataSpec{}.render(t), samlsp.MetadataOptions{EntityID: "https://other.example.com"}},
		{"not metadata", []byte(`<r/>`), samlsp.MetadataOptions{}},
		{"DOCTYPE", append([]byte(`<!DOCTYPE x>`), idpMetadataSpec{}.render(t)...), samlsp.MetadataOptions{}},
		{"not XML", []byte(`not xml`), samlsp.MetadataOptions{}},
		{"too large", idpMetadataSpec{}.render(t), samlsp.MetadataOptions{MaxSize: 100}},
		{"negative max size", idpMetadataSpec{}.render(t), samlsp.MetadataOptions{MaxSize: -1}},
		{"nested aggregate", idpMetadataSpec{root: `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">` +
			`<md:EntitiesDescriptor>ENTITY</md:EntitiesDescriptor></md:EntitiesDescriptor>`}.render(t), samlsp.MetadataOptions{}},
		{"prefixed entityID only", []byte(strings.Replace(string(idpMetadataSpec{}.render(t)),
			`entityID="https://idp.example.com/acme"`, `xmlns:foo="urn:example:foo" foo:entityID="https://idp.example.com/acme"`, 1)), samlsp.MetadataOptions{}},
		{"nested aggregate next to the entity", idpMetadataSpec{root: `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">ENTITY` +
			`<md:EntitiesDescriptor><md:EntityDescriptor entityID="https://other.example.com"/></md:EntitiesDescriptor></md:EntitiesDescriptor>`}.render(t), samlsp.MetadataOptions{}},
		{"no redirect SSO", idpMetadataSpec{sso: `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/post"/>`}.render(t), samlsp.MetadataOptions{}},
		{"http SSO", idpMetadataSpec{sso: redirect("http://idp.example.com/sso")}.render(t), samlsp.MetadataOptions{}},
		{"SSO carrying SAMLRequest", idpMetadataSpec{sso: redirect("https://idp.example.com/sso?SAMLRequest=x")}.render(t), samlsp.MetadataOptions{}},
		{"no signing key", idpMetadataSpec{keyDescriptors: keyDescriptor("encryption", k.idpA.cert)}.render(t), samlsp.MetadataOptions{}},
		{"weak key", idpMetadataSpec{keyDescriptors: keyDescriptor("signing", k.weakRSA.cert)}.render(t), samlsp.MetadataOptions{}},
		{"bad certificate base64", idpMetadataSpec{keyDescriptors: `<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>!!!</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`}.render(t), samlsp.MetadataOptions{}},
		{"bad certificate DER", idpMetadataSpec{keyDescriptors: `<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`}.render(t), samlsp.MetadataOptions{}},
		{"no SAML 2.0 role", []byte(strings.Replace(string(idpMetadataSpec{}.render(t)),
			"urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:1.1:protocol", 1)), samlsp.MetadataOptions{}},
		{"two SAML 2.0 roles", []byte(strings.Replace(string(idpMetadataSpec{}.render(t)), "</md:EntityDescriptor>",
			`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`+keyDescriptor("signing", k.idpB.cert)+
				`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://evil.example.com/sso"/>`+
				`</md:IDPSSODescriptor></md:EntityDescriptor>`, 1)), samlsp.MetadataOptions{}},
		{"bad WantAuthnRequestsSigned", idpMetadataSpec{roleAttrs: ` WantAuthnRequestsSigned="yes"`}.render(t), samlsp.MetadataOptions{}},
		{"bad validUntil", idpMetadataSpec{entityExtra: ` validUntil="soon"`}.render(t), samlsp.MetadataOptions{}},
		{"bad cacheDuration", idpMetadataSpec{entityExtra: ` cacheDuration="1h"`}.render(t), samlsp.MetadataOptions{}},
		{"cacheDuration of 2^63 ns", idpMetadataSpec{entityExtra: ` cacheDuration="PT9223372036.854775808S"`}.render(t), samlsp.MetadataOptions{}},
		{"bad root cacheDuration", idpMetadataSpec{root: `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" cacheDuration="x">ENTITY</md:EntitiesDescriptor>`}.render(t), samlsp.MetadataOptions{}},
		{"bad role validUntil", idpMetadataSpec{roleAttrs: ` validUntil="x"`}.render(t), samlsp.MetadataOptions{}},
		{"relative entity ID", idpMetadataSpec{entityID: "idp"}.render(t), samlsp.MetadataOptions{}},
		{"bad validUntil of the selected entity", idpMetadataSpec{
			root:        `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">ENTITY</md:EntitiesDescriptor>`,
			entityExtra: ` validUntil="x"`,
		}.render(t), samlsp.MetadataOptions{}},
		{"certificate outside the dsig namespace", idpMetadataSpec{keyDescriptors: `<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><x:X509Certificate xmlns:x="urn:x">` +
			certB64(k.idpA.cert) + `</x:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`}.render(t), samlsp.MetadataOptions{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			idp, err := parseMetadata(tc.doc, tc.opts)
			require.ErrorIs(t, err, samlsp.ErrInvalidMetadata)
			assert.Nil(t, idp)
		})
	}
}

func TestParseIdentityProviderMetadata_Expired(t *testing.T) {
	t.Parallel()

	doc := idpMetadataSpec{entityExtra: ` validUntil="2026-10-12T10:00:00Z"`}.render(t)

	_, err := parseMetadata(doc, samlsp.MetadataOptions{})
	require.ErrorIs(t, err, samlsp.ErrMetadataExpired, "at validUntil the metadata is invalid (E94 §4.3.2)")

	_, err = parseMetadata(doc, samlsp.MetadataOptions{Now: func() time.Time { return t0.Add(-time.Second) }})
	require.NoError(t, err, "one second before validUntil")
}

func TestParseIdentityProviderMetadata_BOMAndDefaults(t *testing.T) {
	t.Parallel()

	doc := append([]byte("\xEF\xBB\xBF"), idpMetadataSpec{}.render(t)...)

	idp, err := samlsp.ParseIdentityProviderMetadata(doc, samlsp.MetadataOptions{})
	require.NoError(t, err, "a UTF-8 BOM is tolerated; default clock and size")
	assert.Equal(t, idpEntity, idp.EntityID)
	assert.True(t, idp.ValidUntil.IsZero())
	assert.Zero(t, idp.CacheDuration)
}
