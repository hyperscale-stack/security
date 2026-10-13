// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/hyperscale-stack/security/outbound"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// federation is one crewjam IdP and one SP connection ("acme") that
// imported each other's metadata.
type federation struct {
	idpKey testKey
	idp    *identityProvider
	sp     *serviceProvider
	conn   samlsp.Connection
}

func federate(t *testing.T, signatureMethod string, o spOptions, tune func(*samlsp.Connection)) *federation {
	t.Helper()

	f := &federation{idpKey: newKey(t, "idp")}
	f.idp = newIdentityProvider(t, f.idpKey, signatureMethod)
	f.sp = newServiceProvider(t, o)
	f.conn = f.sp.addConnection(t, "acme", f.idp.metadata(t), tune)
	f.idp.registerSP(t, f.sp.metadata(t, "acme"))

	return f
}

// login runs one complete login in browser b and returns the ACS outcome.
func (f *federation) login(t *testing.T, b *browser) (int, outcome) {
	t.Helper()

	_, form := b.mustSignIn(t, f.sp, "acme")
	status := b.mustPost(t, form)

	return status, f.sp.last(t)
}

// signatureCount counts the XML-DSig signatures of the form's response.
func signatureCount(t *testing.T, form postForm) int {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(form.samlResponse)
	require.NoError(t, err)

	return strings.Count(string(raw), "<ds:SignatureValue>")
}

func TestSPInitiatedSSO(t *testing.T) {
	t.Parallel()

	spKey := newKey(t, "sp")
	f := federate(t, rsaSHA256, spOptions{key: &spKey}, func(c *samlsp.Connection) {
		c.NameIDFormat = samlsp.NameIDFormatPersistent
	})
	b := newBrowser(t, f.sp.srv)

	redirect, form := b.mustSignIn(t, f.sp, "acme")

	// The SP sent a signed AuthnRequest to the IdP SSO URL (HTTP-Redirect).
	assert.Equal(t, f.idp.srv.URL+"/sso", redirect.Scheme+"://"+redirect.Host+redirect.Path)
	require.NoError(t, verifyRedirectSignature(redirect, spKey.cert))
	require.Error(t, verifyRedirectSignature(redirect, f.idpKey.cert))
	assert.Len(t, redirect.Query().Get("RelayState"), 43, "an opaque handle, never application data")

	req := authnRequest(t, redirect)
	assert.Regexp(t, `^_[0-9a-f]{64}$`, req.ID)
	assert.Equal(t, "2.0", req.Version)
	assert.Equal(t, f.idp.srv.URL+"/sso", req.Destination)
	assert.Equal(t, f.conn.ACSURL, req.AssertionConsumerServiceURL)
	assert.Equal(t, saml.HTTPPostBinding, req.ProtocolBinding)
	require.NotNil(t, req.Issuer)
	assert.Equal(t, f.conn.SPEntityID, req.Issuer.Value)
	require.NotNil(t, req.NameIDPolicy)
	assert.Equal(t, samlsp.NameIDFormatPersistent, *req.NameIDPolicy.Format)
	assert.True(t, *req.NameIDPolicy.AllowCreate)

	// crewjam answered at the ACS with the RelayState, signing both the
	// Response and the Assertion.
	assert.Equal(t, f.conn.ACSURL, form.action)
	assert.Equal(t, redirect.Query().Get("RelayState"), form.relayState)
	assert.Equal(t, 2, signatureCount(t, form))

	require.Equal(t, http.StatusOK, b.mustPost(t, form))

	out := f.sp.last(t)
	require.NoError(t, out.err)

	id := out.result.Identity
	assert.Equal(t, "acme", id.ConnectionID)
	assert.Equal(t, f.idp.entityID(), id.Issuer)
	assert.Equal(t, f.conn.SPEntityID, id.Audience)
	assert.Equal(t, samlsp.NameID{
		Value: "alice-pairwise-id", Format: samlsp.NameIDFormatPersistent,
		NameQualifier: f.idp.entityID(), SPNameQualifier: f.conn.SPEntityID,
	}, id.NameID)
	assert.Equal(t, "index-1", id.SessionIndex)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", id.AuthnContextClassRef)
	assert.WithinDuration(t, time.Now(), id.AuthnInstant, time.Minute)
	assert.Equal(t, []string{"alice"}, id.AttributeValues("urn:oid:0.9.2342.19200300.100.1.1"))
	assert.Equal(t, []string{"alice@example.com"}, id.AttributeValues("urn:oid:0.9.2342.19200300.100.1.3"))
	assert.Equal(t, []string{"admins", "devs"}, id.AttributeValues("urn:oid:1.3.6.1.4.1.5923.1.1.1.1"))
	assert.NotEmpty(t, id.AssertionID)
	assert.Equal(t, "/home", out.result.AppState)
}

func TestMetadataExchange(t *testing.T) {
	t.Parallel()

	spKey := newKey(t, "sp")
	f := federate(t, rsaSHA256, spOptions{key: &spKey}, func(c *samlsp.Connection) {
		c.NameIDFormat = samlsp.NameIDFormatPersistent
	})

	// crewjam's reading of the SP metadata.
	ed := f.idp.registerSP(t, f.sp.metadata(t, "acme"))
	assert.Equal(t, f.conn.SPEntityID, ed.EntityID)
	assert.Equal(t, samlsp.DefaultMetadataCacheDuration, ed.CacheDuration)
	require.Len(t, ed.SPSSODescriptors, 1)

	sso := ed.SPSSODescriptors[0]
	require.NotNil(t, sso.AuthnRequestsSigned)
	assert.True(t, *sso.AuthnRequestsSigned)
	assert.Nil(t, sso.WantAssertionsSigned, "signed Response or signed Assertion (errata E93, E26)")
	require.Len(t, sso.KeyDescriptors, 1, "no encryption key: encrypted assertions are refused")
	assert.Equal(t, "signing", sso.KeyDescriptors[0].Use)
	assert.Equal(t, base64.StdEncoding.EncodeToString(spKey.cert.Raw),
		sso.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data)
	require.Len(t, sso.NameIDFormats, 1)
	assert.Equal(t, samlsp.NameIDFormatPersistent, string(sso.NameIDFormats[0]))
	require.Len(t, sso.AssertionConsumerServices, 1)

	acs := sso.AssertionConsumerServices[0]
	assert.Equal(t, saml.HTTPPostBinding, acs.Binding)
	assert.Equal(t, f.conn.ACSURL, acs.Location)
	require.NotNil(t, acs.IsDefault)
	assert.True(t, *acs.IsDefault)

	// The SP's reading of crewjam's IdP metadata: its signing and
	// encryption descriptors carry the same certificate, kept once.
	idp := f.conn.IdentityProvider
	assert.Equal(t, f.idp.entityID(), idp.EntityID)
	assert.Equal(t, f.idp.srv.URL+"/sso", idp.SSOURL, "the HTTP-Redirect endpoint")
	require.Len(t, idp.SigningCertificates, 1)
	assert.True(t, idp.SigningCertificates[0].Equal(f.idpKey.cert))
	assert.False(t, idp.WantAuthnRequestsSigned)
	assert.WithinDuration(t, time.Now().Add(saml.DefaultValidDuration), idp.ValidUntil, time.Minute)
	assert.Equal(t, saml.DefaultValidDuration, idp.CacheDuration)
}

func TestUnsignedAuthnRequests(t *testing.T) {
	t.Parallel()

	f := federate(t, rsaSHA256, spOptions{}, nil)

	ed := f.idp.registerSP(t, f.sp.metadata(t, "acme"))
	require.NotNil(t, ed.SPSSODescriptors[0].AuthnRequestsSigned)
	assert.False(t, *ed.SPSSODescriptors[0].AuthnRequestsSigned)
	assert.Empty(t, ed.SPSSODescriptors[0].KeyDescriptors)

	b := newBrowser(t, f.sp.srv)
	redirect, form := b.mustSignIn(t, f.sp, "acme")
	assert.Empty(t, redirect.Query().Get("Signature"))
	assert.Empty(t, redirect.Query().Get("SigAlg"))

	require.Equal(t, http.StatusOK, b.mustPost(t, form))
	require.NoError(t, f.sp.last(t).err)
}

func TestSHA1Policy(t *testing.T) {
	t.Parallel()

	// crewjam signs with rsa-sha1 and SHA-1 digests by default.
	f := federate(t, "", spOptions{}, nil)
	b := newBrowser(t, f.sp.srv)

	status, out := f.login(t, b)
	assert.Equal(t, http.StatusForbidden, status)
	require.ErrorIs(t, out.err, samlsp.ErrUnsupportedAlgorithm)

	// The per-connection opt-in accepts it.
	f.sp.addConnection(t, "acme", f.idp.metadata(t), func(c *samlsp.Connection) { c.InsecureAllowSHA1 = true })

	status, out = f.login(t, b)
	assert.Equal(t, http.StatusOK, status)
	require.NoError(t, out.err)
}

func TestIdPKeyRollover(t *testing.T) {
	t.Parallel()

	f := federate(t, rsaSHA256, spOptions{}, nil)
	b := newBrowser(t, f.sp.srv)
	keyA, keyB, rogue := f.idpKey, newKey(t, "idp-next"), newKey(t, "rogue")

	accepted := func(step string) {
		t.Helper()

		status, out := f.login(t, b)
		require.NoError(t, out.err, step)
		require.Equal(t, http.StatusOK, status, step)
	}
	refused := func(step string) {
		t.Helper()

		status, out := f.login(t, b)
		require.ErrorIs(t, out.err, samlsp.ErrInvalidSignature, step)
		require.Equal(t, http.StatusForbidden, status, step)
	}

	accepted("signed with the only announced key")

	// The IdP announces its next key; the SP imports the metadata.
	f.sp.addConnection(t, "acme", f.idp.metadata(t, keyB.cert), nil)
	accepted("old key still signing")

	f.idp.useKey(keyB)
	accepted("new key signing, both announced")

	// The old key is retired from the metadata.
	f.sp.addConnection(t, "acme", f.idp.metadata(t), nil)
	accepted("new key alone")

	f.idp.useKey(keyA)
	refused("retired key")

	f.idp.useKey(rogue)
	refused("never announced key")
}

func TestReplayAndBrowserBinding(t *testing.T) {
	t.Parallel()

	f := federate(t, rsaSHA256, spOptions{}, nil)
	alice := newBrowser(t, f.sp.srv)

	// A consumed response cannot be posted again.
	_, form := alice.mustSignIn(t, f.sp, "acme")
	require.Equal(t, http.StatusOK, alice.mustPost(t, form))
	require.Equal(t, http.StatusForbidden, alice.mustPost(t, form))
	require.ErrorIs(t, f.sp.last(t).err, samlsp.ErrTransactionConsumed)

	// Another browser cannot complete alice's login: without a binding
	// cookie, or with its own.
	_, form = alice.mustSignIn(t, f.sp, "acme")

	stranger := newBrowser(t, f.sp.srv)
	require.Equal(t, http.StatusForbidden, stranger.mustPost(t, form))
	require.ErrorIs(t, f.sp.last(t).err, samlsp.ErrMissingBrowserBinding)

	mallory := newBrowser(t, f.sp.srv)
	mallory.mustSignIn(t, f.sp, "acme") // gets a binding cookie
	require.Equal(t, http.StatusForbidden, mallory.mustPost(t, form))
	require.ErrorIs(t, f.sp.last(t).err, samlsp.ErrBrowserBindingMismatch)

	// Those attempts consumed nothing: alice completes her login.
	require.Equal(t, http.StatusOK, alice.mustPost(t, form))
	require.NoError(t, f.sp.last(t).err)
}

// TestResponseOrigins: a connection with ResponseOrigins refuses crewjam's
// response posted from another site, or with neither Origin nor Referer,
// before the transaction is touched; the same login then completes from
// the IdP's origin (audit SAML-02).
func TestResponseOrigins(t *testing.T) {
	t.Parallel()

	f := federate(t, rsaSHA256, spOptions{}, nil)
	idpOrigin := f.idp.srv.URL // https://127.0.0.1:port, a serialized origin

	f.sp.mu.Lock()
	c := f.sp.conns["acme"]
	c.ResponseOrigins = []string{idpOrigin}
	f.sp.conns["acme"] = c
	f.sp.mu.Unlock()

	alice := newBrowser(t, f.sp.srv)
	_, form := alice.mustSignIn(t, f.sp, "acme")

	status, err := alice.postWith(form, http.Header{"Origin": {"https://attacker.example"}})
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, status)
	require.ErrorIs(t, f.sp.last(t).err, samlsp.ErrOriginMismatch)

	require.Equal(t, http.StatusForbidden, alice.mustPost(t, form), "neither Origin nor Referer")
	require.ErrorIs(t, f.sp.last(t).err, samlsp.ErrOriginMismatch)

	status, err = alice.postWith(form, http.Header{"Origin": {idpOrigin}})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.NoError(t, f.sp.last(t).err)
}

func TestConcurrentLoginsAcrossInstances(t *testing.T) {
	t.Parallel()

	// Three SP instances behind a round-robin balancer share one store:
	// a login started on one instance completes on another.
	f := federate(t, rsaSHA256, spOptions{instances: 3}, nil)

	const users = 12

	browsers := make([]*browser, users)
	for i := range browsers {
		browsers[i] = newBrowser(t, f.sp.srv)
	}

	var wg sync.WaitGroup

	errs := make(chan error, users)

	for _, b := range browsers {
		wg.Go(func() {
			_, form, err := b.signIn(f.sp, "acme")
			if err == nil {
				var status int

				if status, err = b.post(form); err == nil && status != http.StatusOK {
					err = fmt.Errorf("ACS answered %d", status)
				}
			}

			errs <- err
		})
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	// One response posted concurrently to every instance logs in once.
	b := browsers[0]
	_, form := b.mustSignIn(t, f.sp, "acme")

	const posts = 9

	statuses := make(chan int, posts)

	for range posts {
		wg.Go(func() {
			status, err := b.post(form)
			if err != nil {
				status = -1
			}

			statuses <- status
		})
	}

	wg.Wait()
	close(statuses)

	count := map[int]int{}
	for s := range statuses {
		count[s]++
	}

	assert.Equal(t, map[int]int{http.StatusOK: 1, http.StatusForbidden: posts - 1}, count)
}

func TestMetadataSourceAgainstTheIdP(t *testing.T) {
	t.Parallel()

	// The SP fetches crewjam's metadata from its URL, through the outbound
	// client (loopback exempted, the test CA trusted), and logs in with it.
	idpKey := newKey(t, "idp")
	ip := newIdentityProvider(t, idpKey, rsaSHA256)
	sp := newServiceProvider(t, spOptions{})

	pool := x509.NewCertPool()
	pool.AddCert(ip.srv.Certificate())

	src, err := samlsp.NewMetadataSource(samlsp.MetadataSourceConfig{
		URL:      ip.srv.URL + "/metadata",
		EntityID: ip.entityID(),
		Outbound: outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool},
	})
	require.NoError(t, err)

	idp, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ip.srv.URL+"/sso", idp.SSOURL)
	require.Len(t, idp.SigningCertificates, 1)
	assert.True(t, idp.SigningCertificates[0].Equal(idpKey.cert))
	assert.Equal(t, saml.DefaultValidDuration, idp.CacheDuration)

	sp.setConnection("acme", idp)
	ip.registerSP(t, sp.metadata(t, "acme"))

	b := newBrowser(t, sp.srv)
	_, form := b.mustSignIn(t, sp, "acme")
	require.Equal(t, http.StatusOK, b.mustPost(t, form))
	require.NoError(t, sp.last(t).err)

	// Without the loopback exemption, the same URL is refused.
	strict, err := samlsp.NewMetadataSource(samlsp.MetadataSourceConfig{URL: ip.srv.URL + "/metadata", EntityID: ip.entityID()})
	require.NoError(t, err)

	_, err = strict.IdentityProvider(context.Background())
	require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
}
