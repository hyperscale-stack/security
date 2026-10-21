// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

// The keys an IdP metadata document makes trusted (audit 2026-10-21 F-13):
// one certificate per signing KeyDescriptor, read at
// KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate only (SAML V2.0
// Metadata Interoperability Profile §2.5.1; XML Signature 1.1 §4.5.4 gives
// the certificates of an X509Data no order, so a chain cannot be reduced to
// its end entity and is refused).

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chainKeys is an issuing CA and an end-entity certificate it signed.
type chainKeys struct {
	ca, leaf keyPair
	// reissued is a second certificate over idpA's key.
	reissued *x509.Certificate
}

var (
	chainOnce sync.Once
	chainVal  *chainKeys
)

// testChain returns the shared CA, leaf and re-issued certificates.
func testChain(t testing.TB) *chainKeys {
	t.Helper()

	k := keys(t)

	chainOnce.Do(func() {
		ca := newRSAPair(2048, "corporate root CA", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour))
		caTpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "corporate root CA"},
			NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(365 * 24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		ca.cert = mustCertificate(caTpl, caTpl, ca.signer.Public(), ca)

		leaf := newRSAPair(2048, "idp signing", t0.Add(-24*time.Hour), t0.Add(365*24*time.Hour))
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "idp signing"},
			NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(365 * 24 * time.Hour),
		}
		leaf.cert = mustCertificate(leafTpl, ca.cert, leaf.signer.Public(), ca)

		reTpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "idp-a re-issued"},
			NotBefore: t0.Add(-12 * time.Hour), NotAfter: t0.Add(730 * 24 * time.Hour),
		}

		chainVal = &chainKeys{ca: ca, leaf: leaf, reissued: mustCertificate(reTpl, reTpl, k.idpA.signer.Public(), k.idpA)}
	})

	return chainVal
}

func mustCertificate(tpl, parent *x509.Certificate, pub any, issuer keyPair) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, issuer.signer)
	if err != nil {
		panic(err)
	}

	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return c
}

// x509Data renders a ds:X509Data holding the certificates.
func x509Data(certs ...*x509.Certificate) string {
	out := `<ds:X509Data>`
	for _, c := range certs {
		out += `<ds:X509Certificate>` + certB64(c) + `</ds:X509Certificate>`
	}

	return out + `</ds:X509Data>`
}

// rawKeyDescriptor wraps inner (the KeyDescriptor's content) in a signing
// KeyDescriptor.
func rawKeyDescriptor(inner string) string {
	return `<md:KeyDescriptor use="signing">` + inner + `</md:KeyDescriptor>`
}

func TestParseIdentityProviderMetadata_KeyDescriptorRefusals(t *testing.T) {
	t.Parallel()

	k, c := keys(t), testChain(t)

	cases := map[string]string{
		// The F-13 shape: the issuing CA next to the signing certificate.
		"chain in one X509Data":              keyDescriptor("signing", c.leaf.cert, c.ca.cert),
		"CA first in one X509Data":           keyDescriptor("signing", c.ca.cert, c.leaf.cert),
		"chain in a KeyDescriptor of no use": keyDescriptor("", c.leaf.cert, c.ca.cert),
		"chain over two X509Data": rawKeyDescriptor(`<ds:KeyInfo>` + x509Data(c.leaf.cert) + x509Data(c.ca.cert) +
			`</ds:KeyInfo>`),
		// Certificate semantics: two certificates of one key are two
		// certificates (a KeyInfo certificate must equal a trusted one).
		"two certificates of one key": keyDescriptor("signing", k.idpA.cert, c.reissued),
		// SAML Metadata §2.4.1.1: one ds:KeyInfo per KeyDescriptor.
		"two KeyInfo": rawKeyDescriptor(`<ds:KeyInfo>` + x509Data(k.idpA.cert) + `</ds:KeyInfo>` +
			`<ds:KeyInfo>` + x509Data(k.idpB.cert) + `</ds:KeyInfo>`),
		"two identical KeyInfo": rawKeyDescriptor(`<ds:KeyInfo>` + x509Data(k.idpA.cert) + `</ds:KeyInfo>` +
			`<ds:KeyInfo>` + x509Data(k.idpA.cert) + `</ds:KeyInfo>`),
		// No partial import: one bad descriptor refuses the document.
		"a chain next to a valid descriptor": keyDescriptor("signing", k.idpB.cert) +
			keyDescriptor("signing", c.leaf.cert, c.ca.cert),
	}

	for name, kds := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			idp, err := parseMetadata(idpMetadataSpec{keyDescriptors: kds}.render(t), samlsp.MetadataOptions{})
			require.ErrorIs(t, err, samlsp.ErrInvalidMetadata)
			assert.Nil(t, idp)
		})
	}

	t.Run("the error tells to keep the signing certificate only", func(t *testing.T) {
		t.Parallel()

		_, err := parseMetadata(idpMetadataSpec{keyDescriptors: keyDescriptor("signing", c.leaf.cert, c.ca.cert)}.render(t),
			samlsp.MetadataOptions{})
		require.ErrorContains(t, err, "keep only the certificate the IdP signs with")
		require.ErrorContains(t, err, "never a CA or intermediate certificate")
	})
}

func TestParseIdentityProviderMetadata_KeyDescriptorShapes(t *testing.T) {
	t.Parallel()

	k, c := keys(t), testChain(t)

	cases := map[string]struct {
		kds  string
		want []*x509.Certificate
	}{
		"one certificate repeated in its X509Data": {keyDescriptor("signing", k.idpA.cert, k.idpA.cert), []*x509.Certificate{k.idpA.cert}},
		"one certificate in two X509Data": {
			rawKeyDescriptor(`<ds:KeyInfo>` + x509Data(k.idpA.cert) + x509Data(k.idpA.cert) + `</ds:KeyInfo>`),
			[]*x509.Certificate{k.idpA.cert},
		},
		// Only signing (or use-less) descriptors are read: an encryption
		// key, chain or not, is never trusted nor shape-checked.
		"a chain in an encryption descriptor is ignored": {
			keyDescriptor("encryption", c.leaf.cert, c.ca.cert) + keyDescriptor("signing", k.idpA.cert),
			[]*x509.Certificate{k.idpA.cert},
		},
		// Certificates elsewhere than KeyInfo/X509Data/X509Certificate are
		// not key representations: never trusted.
		"a certificate in EncryptionMethod content is ignored": {
			rawKeyDescriptor(`<ds:KeyInfo>` + x509Data(k.idpA.cert) + `</ds:KeyInfo>` +
				`<md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc">` + x509Data(k.attacker.cert) +
				`</md:EncryptionMethod>`),
			[]*x509.Certificate{k.idpA.cert},
		},
		"a certificate directly under KeyInfo is ignored": {
			rawKeyDescriptor(`<ds:KeyInfo><ds:X509Certificate>` + certB64(k.attacker.cert) + `</ds:X509Certificate>` +
				x509Data(k.idpA.cert) + `</ds:KeyInfo>`),
			[]*x509.Certificate{k.idpA.cert},
		},
		"a certificate nested deeper in X509Data is ignored": {
			rawKeyDescriptor(`<ds:KeyInfo><ds:X509Data><x:Wrap xmlns:x="urn:x"><ds:X509Certificate>` + certB64(k.attacker.cert) +
				`</ds:X509Certificate></x:Wrap><ds:X509Certificate>` + certB64(k.idpA.cert) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`),
			[]*x509.Certificate{k.idpA.cert},
		},
		"an X509Data outside the dsig namespace is ignored": {
			rawKeyDescriptor(`<ds:KeyInfo><x:X509Data xmlns:x="urn:x"><ds:X509Certificate>` + certB64(k.attacker.cert) +
				`</ds:X509Certificate></x:X509Data>` + x509Data(k.idpA.cert) + `</ds:KeyInfo>`),
			[]*x509.Certificate{k.idpA.cert},
		},
		// Namespaces, not prefixes, are matched.
		"a ds: prefix bound to another namespace is ignored": {
			rawKeyDescriptor(`<ds:KeyInfo xmlns:ds="urn:not-dsig"><ds:X509Data><ds:X509Certificate>`+certB64(k.attacker.cert)+
				`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`) + keyDescriptor("signing", k.idpA.cert),
			[]*x509.Certificate{k.idpA.cert},
		},
		"a KeyInfo outside the dsig namespace is ignored": {
			rawKeyDescriptor(`<x:KeyInfo xmlns:x="urn:x">`+x509Data(k.attacker.cert)+`</x:KeyInfo>`) +
				keyDescriptor("signing", k.idpA.cert),
			[]*x509.Certificate{k.idpA.cert},
		},
		"KeyInfo in the default namespace": {
			rawKeyDescriptor(`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + certB64(k.idpA.cert) +
				`</X509Certificate></X509Data></KeyInfo>`),
			[]*x509.Certificate{k.idpA.cert},
		},
		"KeyInfo under another prefix": {
			rawKeyDescriptor(`<dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><dsig:X509Data><dsig:X509Certificate>` +
				certB64(k.idpA.cert) + `</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo>`),
			[]*x509.Certificate{k.idpA.cert},
		},
		// Metadata Interoperability Profile §2.6.1 deviation (I-21): a key
		// published only as ds:KeyValue is not imported.
		"a KeyValue-only descriptor is not imported": {
			rawKeyDescriptor(`<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AQAB</ds:Modulus><ds:Exponent>AQAB</ds:Exponent>`+
				`</ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>`) + keyDescriptor("signing", k.idpA.cert),
			[]*x509.Certificate{k.idpA.cert},
		},
		// A rollover: one key per descriptor.
		"two keys in two descriptors": {
			keyDescriptor("signing", k.idpA.cert) + keyDescriptor("signing", k.idpB.cert),
			[]*x509.Certificate{k.idpA.cert, k.idpB.cert},
		},
		// Documented, not refused (Metadata Interoperability Profile §2.6.1,
		// and self-signed IdP certificates often carry CA:TRUE): a CA
		// certificate published in a descriptor of its own is a trusted
		// signing key. Operators must not "fix" a refused chain this way.
		"a CA certificate in its own descriptor is a trusted key": {
			keyDescriptor("signing", c.leaf.cert) + keyDescriptor("signing", c.ca.cert),
			[]*x509.Certificate{c.leaf.cert, c.ca.cert},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			idp, err := parseMetadata(idpMetadataSpec{keyDescriptors: tc.kds}.render(t), samlsp.MetadataOptions{})
			require.NoError(t, err)
			require.Len(t, idp.SigningCertificates, len(tc.want))

			for i, want := range tc.want {
				assert.True(t, idp.SigningCertificates[i].Equal(want), "certificate %d", i)
			}
		})
	}

	t.Run("a lone ignored certificate leaves no signing key", func(t *testing.T) {
		t.Parallel()

		_, err := parseMetadata(idpMetadataSpec{keyDescriptors: rawKeyDescriptor(`<ds:KeyInfo xmlns:ds="urn:not-dsig"><ds:X509Data>` +
			`<ds:X509Certificate>` + certB64(k.idpA.cert) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`)}.render(t),
			samlsp.MetadataOptions{})
		require.ErrorIs(t, err, samlsp.ErrInvalidMetadata)
		require.ErrorContains(t, err, "no signing certificate")
	})
}

// TestCompleteLogin_MetadataChainNeverTrustsTheCA: the audit's probe, end
// to end. Metadata carrying the chain is refused; with the signing
// certificate alone, a response signed with the CA's key is refused.
func TestCompleteLogin_MetadataChainNeverTrustsTheCA(t *testing.T) {
	t.Parallel()

	c := testChain(t)

	_, err := parseMetadata(idpMetadataSpec{keyDescriptors: keyDescriptor("signing", c.leaf.cert, c.ca.cert)}.render(t),
		samlsp.MetadataOptions{})
	require.ErrorIs(t, err, samlsp.ErrInvalidMetadata)

	idp, err := parseMetadata(idpMetadataSpec{keyDescriptors: keyDescriptor("signing", c.leaf.cert)}.render(t), samlsp.MetadataOptions{})
	require.NoError(t, err)
	require.Len(t, idp.SigningCertificates, 1)

	withIdP := func(_ *samlsp.Config, conn *samlsp.Connection) { conn.IdentityProvider = *idp }

	rejectConsumed(t, respOpts{assertionSig: sigOpts{signer: c.ca}}, samlsp.ErrInvalidSignature, withIdP)

	res, err := flow(t, newEnv(t, withIdP), respOpts{assertionSig: sigOpts{signer: c.leaf}})
	require.NoError(t, err)
	assert.NotEmpty(t, res.Identity.NameID.Value)
}
