// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/require"
)

// publishedSigningCertificates returns the signing certificates of the SP
// metadata of conn, as crewjam reads them.
func publishedSigningCertificates(t *testing.T, idp *identityProvider, sp *serviceProvider, conn string) []*x509.Certificate {
	t.Helper()

	ed := idp.registerSP(t, sp.metadata(t, conn))

	var certs []*x509.Certificate

	for _, kd := range ed.SPSSODescriptors[0].KeyDescriptors {
		require.Equal(t, "signing", kd.Use, "no encryption key is ever published")

		for _, c := range kd.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(c.Data)
			require.NoError(t, err)

			cert, err := x509.ParseCertificate(der)
			require.NoError(t, err)

			certs = append(certs, cert)
		}
	}

	return certs
}

// verifiesWithAny checks the redirect signature of u against a published
// certificate set (errata E68: any listed key may sign).
func verifiesWithAny(u *url.URL, certs []*x509.Certificate) error {
	for _, c := range certs {
		if verifyRedirectSignature(u, c) == nil {
			return nil
		}
	}

	return errors.New("no published certificate verifies the signature")
}

// TestSPSigningKeyRollover rolls the SP's AuthnRequest signing key: the
// next key is announced in the metadata, then signs while the old one is
// still published, then the old one is retired. crewjam verifies no
// AuthnRequest signature, so the IdP side of the check is the
// independent verifier of Bindings §3.4.4.1 run against the certificates
// crewjam read from the published metadata.
func TestSPSigningKeyRollover(t *testing.T) {
	t.Parallel()

	current, next := newKey(t, "sp-current"), newKey(t, "sp-next")
	idp := newIdentityProvider(t, newKey(t, "idp"), rsaSHA256)
	sp := newServiceProvider(t, spOptions{key: &current, next: []*x509.Certificate{next.cert}})
	sp.addConnection(t, "acme", idp.metadata(t), nil)

	b := newBrowser(t, sp.srv)

	// 1. Announce: both keys published, the current one signs.
	published := publishedSigningCertificates(t, idp, sp, "acme")
	require.Len(t, published, 2)

	retired, form := b.mustSignIn(t, sp, "acme")
	require.NoError(t, verifyRedirectSignature(retired, current.cert))
	require.Error(t, verifyRedirectSignature(retired, next.cert))
	require.NoError(t, verifiesWithAny(retired, published))
	require.Equal(t, http.StatusOK, b.mustPost(t, form))

	// 2. Switch: the next key signs, the old one stays published.
	sp.configure(t, spOptions{key: &next, next: []*x509.Certificate{current.cert}})
	published = publishedSigningCertificates(t, idp, sp, "acme")
	require.Len(t, published, 2)

	switched, form := b.mustSignIn(t, sp, "acme")
	require.NoError(t, verifyRedirectSignature(switched, next.cert))
	require.NoError(t, verifiesWithAny(switched, published))
	require.Equal(t, http.StatusOK, b.mustPost(t, form))

	// 3. Retire: only the new key is published; requests signed by the
	// retired key no longer verify against what the IdP imported.
	sp.configure(t, spOptions{key: &next})
	published = publishedSigningCertificates(t, idp, sp, "acme")
	require.Len(t, published, 1)
	require.Error(t, verifiesWithAny(retired, published))

	after, form := b.mustSignIn(t, sp, "acme")
	require.NoError(t, verifiesWithAny(after, published))
	require.Equal(t, http.StatusOK, b.mustPost(t, form))
}

// redirectOf returns the redirect a GET to u answers, without following it
// (cookies are still stored).
func (b *browser) redirectOf(t *testing.T, u string) *url.URL {
	t.Helper()

	client := *b.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Get(u)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	return loc
}

// postFormOf returns the HTTP-POST binding form of a page.
func postFormOf(body []byte) (postForm, error) {
	action := formAction.FindSubmatch(body)
	if action == nil {
		return postForm{}, fmt.Errorf("no POST form: %.200s", body)
	}

	form := postForm{action: html.UnescapeString(string(action[1]))}

	for _, m := range formInput.FindAllSubmatch(body, -1) {
		if v := html.UnescapeString(string(m[2])); string(m[1]) == "SAMLResponse" {
			form.samlResponse = v
		} else {
			form.relayState = v
		}
	}

	return form, nil
}

// answerForgedRequest makes idp answer an unsigned AuthnRequest that the
// attacker wrote herself: her own request ID and RelayState, and the SP
// entity ID and ACS of conn (crewjam answers any registered SP). It
// returns the HTTP-POST form the IdP served.
func answerForgedRequest(t *testing.T, b *browser, idp *identityProvider, conn samlsp.Connection, requestID, relayState string) postForm {
	t.Helper()

	request := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`+
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID=%q Version="2.0" IssueInstant=%q Destination=%q`+
		` AssertionConsumerServiceURL=%q ProtocolBinding=%q><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		requestID, time.Now().UTC().Format("2006-01-02T15:04:05Z"), idp.srv.URL+"/sso", conn.ACSURL,
		saml.HTTPPostBinding, conn.SPEntityID)

	var deflated bytes.Buffer

	fw, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = fw.Write([]byte(request))
	require.NoError(t, err)
	require.NoError(t, fw.Close())

	sso := idp.srv.URL + "/sso?" + url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(deflated.Bytes())},
		"RelayState":  {relayState},
	}.Encode()

	resp, err := b.client.Get(sso)
	require.NoError(t, err)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	form, err := postFormOf(body)
	require.NoError(t, err, "the IdP answers the forged request")
	require.Equal(t, conn.ACSURL, form.action)

	return form
}

// TestCrossTenantSameIdP plays the multi-tenant substitution of plan review
// F4 against crewjam: two connections trust the same IdP (same entity ID,
// same key), the IdP only knows the victim tenant's SP. The attacker starts
// a login at her squatting connection, then asks the IdP, with an unsigned
// AuthnRequest, for a response to the victim's SP answering her own request
// ID. InResponseTo then matches her transaction, and the per-connection SP
// identity (decision D1) is the only thing standing in the way.
func TestCrossTenantSameIdP(t *testing.T) {
	t.Parallel()

	idp := newIdentityProvider(t, newKey(t, "idp"), rsaSHA256)
	sp := newServiceProvider(t, spOptions{})
	victim := sp.addConnection(t, "victim", idp.metadata(t), nil)
	squatter := sp.addConnection(t, "squatter", idp.metadata(t), nil)
	idp.registerSP(t, sp.metadata(t, "victim"))

	mallory := newBrowser(t, sp.srv)

	// The IdP never registered the squatter's SP: it serves no response.
	_, _, err := mallory.signIn(sp, "squatter")
	require.Error(t, err)

	// Mallory's own transaction at the squatter; her AuthnRequest names
	// her request ID with the victim's SP and ACS.
	redirect := mallory.redirectOf(t, sp.srv.URL+"/login/squatter")
	form := answerForgedRequest(t, mallory, idp, victim, authnRequest(t, redirect).ID, redirect.Query().Get("RelayState"))

	// At the squatter's ACS, with her binding: the signed Destination names
	// the victim's ACS.
	form.action = squatter.ACSURL
	require.Equal(t, http.StatusForbidden, mallory.mustPost(t, form))
	require.ErrorIs(t, sp.last(t).err, samlsp.ErrDestinationMismatch)

	// At the victim's ACS: the transaction belongs to the squatter.
	form.action = victim.ACSURL
	require.Equal(t, http.StatusForbidden, mallory.mustPost(t, form))
	require.ErrorIs(t, sp.last(t).err, samlsp.ErrTransactionNotFound)
}

// TestTwoIdentityProvidersTwoConnections federates two IdPs, each with its
// own entity ID and key, behind two connections of one SP. Each tenant
// signs in through its own IdP. The administrator of IdP-B (another
// tenant) cannot sign anyone in at connection A: neither with a genuine
// response of IdP-B for her own tenant, nor with one IdP-B issued for
// connection A's SP and A's own request. In both cases the first guard is
// the signature, verified against connection A's IdP keys only, before
// any Destination, InResponseTo or Issuer comparison.
func TestTwoIdentityProvidersTwoConnections(t *testing.T) {
	t.Parallel()

	idpA := newIdentityProvider(t, newKey(t, "idp-a"), rsaSHA256)
	idpB := newIdentityProvider(t, newKey(t, "idp-b"), rsaSHA256)
	sp := newServiceProvider(t, spOptions{})
	acme := sp.addConnection(t, "acme", idpA.metadata(t), nil)
	sp.addConnection(t, "globex", idpB.metadata(t), nil)
	idpA.registerSP(t, sp.metadata(t, "acme"))
	idpB.registerSP(t, sp.metadata(t, "globex"))

	for _, tenant := range []struct {
		conn string
		idp  *identityProvider
	}{{"acme", idpA}, {"globex", idpB}} {
		b := newBrowser(t, sp.srv)
		_, form := b.mustSignIn(t, sp, tenant.conn)
		require.Equal(t, http.StatusOK, b.mustPost(t, form))

		id := sp.last(t).result.Identity
		require.Equal(t, tenant.conn, id.ConnectionID)
		require.Equal(t, tenant.idp.entityID(), id.Issuer)
	}

	// Mallory holds a transaction at acme and IdP-B's genuine response for
	// her globex login, posted with acme's RelayState and binding.
	mallory := newBrowser(t, sp.srv)
	redirect := mallory.redirectOf(t, sp.srv.URL+"/login/acme")
	_, genuine := mallory.mustSignIn(t, sp, "globex")

	genuine.action, genuine.relayState = acme.ACSURL, redirect.Query().Get("RelayState")
	require.Equal(t, http.StatusForbidden, mallory.mustPost(t, genuine))
	require.ErrorIs(t, sp.last(t).err, samlsp.ErrInvalidSignature)
	require.Contains(t, sp.last(t).err.Error(), "(signature verification failed)")

	// IdP-B answers acme's own request for acme's SP (an IdP administrator
	// can register any SP metadata): Destination, Audience and InResponseTo
	// are right, but acme does not trust IdP-B.
	idpB.registerSP(t, sp.metadata(t, "acme"))

	redirect = mallory.redirectOf(t, sp.srv.URL+"/login/acme")
	forged := answerForgedRequest(t, mallory, idpB, acme, authnRequest(t, redirect).ID, redirect.Query().Get("RelayState"))
	require.Equal(t, http.StatusForbidden, mallory.mustPost(t, forged))
	require.ErrorIs(t, sp.last(t).err, samlsp.ErrInvalidSignature)
	require.Contains(t, sp.last(t).err.Error(), "(signature verification failed)")
}
