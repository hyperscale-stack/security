// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package samlinterop_test drives the saml/sp Service Provider against an
// independent SAML implementation, crewjam/saml's IdentityProvider, in
// process over TLS: SP-initiated SSO with metadata exchanged both ways,
// signed AuthnRequests, IdP key rollover, the SHA-1 policy, replay, the
// browser binding and concurrent SP instances sharing one store.
//
// This private, test-only module keeps crewjam/saml out of every
// production build. crewjam signs with goxmldsig, the library the SP
// verifies with, so these tests do not prove XML-DSig interoperability
// with another signer: issue #88 adds Keycloak and browser runs.
package samlinterop_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/require"
)

// testKey is a throwaway RSA key and its self-signed certificate, generated
// at run time: no key material is committed.
type testKey struct {
	signer *rsa.PrivateKey
	cert   *x509.Certificate
}

var serial atomic.Int64

func newKey(t testing.TB, cn string) testKey {
	t.Helper()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return testKey{signer: k, cert: cert}
}

// identityProvider is crewjam's IdentityProvider served over TLS. Every
// request is authenticated as the same user (alice).
type identityProvider struct {
	srv *httptest.Server

	cfgMu sync.Mutex // guards idp: held for each request and by useKey
	idp   *saml.IdentityProvider

	spMu sync.Mutex
	sps  map[string]*saml.EntityDescriptor
}

// newIdentityProvider starts an IdP signing with key and signatureMethod
// ("" keeps crewjam's default, rsa-sha1).
func newIdentityProvider(t testing.TB, key testKey, signatureMethod string) *identityProvider {
	t.Helper()

	i := &identityProvider{sps: map[string]*saml.EntityDescriptor{}}

	mux := http.NewServeMux()
	i.srv = httptest.NewTLSServer(mux)
	t.Cleanup(i.srv.Close)

	base, err := url.Parse(i.srv.URL)
	require.NoError(t, err)

	i.idp = &saml.IdentityProvider{
		Key:                     key.signer,
		Certificate:             key.cert,
		Logger:                  logger.DefaultLogger,
		MetadataURL:             *base.JoinPath("/metadata"),
		SSOURL:                  *base.JoinPath("/sso"),
		ServiceProviderProvider: i,
		SessionProvider:         i,
		SignatureMethod:         signatureMethod,
	}

	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		i.cfgMu.Lock()
		defer i.cfgMu.Unlock()

		i.idp.ServeSSO(w, r)
	})
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		i.cfgMu.Lock()
		defer i.cfgMu.Unlock()

		i.idp.ServeMetadata(w, r)
	})

	return i
}

// entityID is the IdP entity ID (crewjam uses its metadata URL).
func (i *identityProvider) entityID() string { return i.srv.URL + "/metadata" }

// useKey makes the IdP sign with key (a rollover step).
func (i *identityProvider) useKey(key testKey) {
	i.cfgMu.Lock()
	defer i.cfgMu.Unlock()

	i.idp.Key, i.idp.Certificate = key.signer, key.cert
}

// metadata renders the IdP metadata with crewjam, announcing the extra
// signing certificates after the current one.
func (i *identityProvider) metadata(t testing.TB, extra ...*x509.Certificate) []byte {
	t.Helper()

	i.cfgMu.Lock()
	md := i.idp.Metadata()
	i.cfgMu.Unlock()

	for _, c := range extra {
		kd := saml.KeyDescriptor{Use: "signing"}
		kd.KeyInfo.X509Data.X509Certificates = []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(c.Raw)}}
		md.IDPSSODescriptors[0].KeyDescriptors = append(md.IDPSSODescriptors[0].KeyDescriptors, kd)
	}

	out, err := xml.Marshal(md)
	require.NoError(t, err)

	return out
}

// registerSP trusts a Service Provider from its metadata, as crewjam
// parses it.
func (i *identityProvider) registerSP(t testing.TB, metadata []byte) *saml.EntityDescriptor {
	t.Helper()

	var ed saml.EntityDescriptor
	require.NoError(t, xml.Unmarshal(metadata, &ed), "crewjam parses the SP metadata")

	i.spMu.Lock()
	defer i.spMu.Unlock()

	i.sps[ed.EntityID] = &ed

	return &ed
}

// GetServiceProvider implements saml.ServiceProviderProvider.
func (i *identityProvider) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	i.spMu.Lock()
	defer i.spMu.Unlock()

	if ed, ok := i.sps[id]; ok {
		return ed, nil
	}

	return nil, os.ErrNotExist
}

// GetSession implements saml.SessionProvider.
func (i *identityProvider) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	now := saml.TimeNow()

	return &saml.Session{
		ID: "session-1", CreateTime: now, ExpireTime: now.Add(time.Hour), Index: "index-1",
		NameID: "alice-pairwise-id", NameIDFormat: samlsp.NameIDFormatPersistent,
		UserName: "alice", UserEmail: "alice@example.com", Groups: []string{"admins", "devs"},
	}
}

// serviceProvider serves one or more samlsp instances (round robin, as
// behind a load balancer) sharing one store: GET /login/{conn},
// GET /saml/{conn}/metadata and POST /saml/{conn}/acs.
type serviceProvider struct {
	srv       *httptest.Server
	instances []*samlsp.ServiceProvider
	next      atomic.Uint64

	mu       sync.Mutex
	conns    map[string]samlsp.Connection
	outcomes []outcome
}

// outcome is what the ACS handler observed for one request.
type outcome struct {
	result *samlsp.LoginResult
	err    error
}

type spOptions struct {
	key       *testKey // SP signing key; nil: unsigned AuthnRequests
	instances int      // 0 means 1
}

func newServiceProvider(t testing.TB, o spOptions) *serviceProvider {
	t.Helper()

	s := &serviceProvider{conns: map[string]samlsp.Connection{}}
	store := memory.New()

	cfg := samlsp.Config{
		Connections:  samlsp.ConnectionResolverFunc(s.resolve),
		Transactions: store,
		ReplayCache:  store,
	}

	if o.key != nil {
		cfg.SigningKey, cfg.SigningCertificate = o.key.signer, o.key.cert
	}

	for n := max(o.instances, 1); n > 0; n-- {
		sp, err := samlsp.New(cfg)
		require.NoError(t, err)

		s.instances = append(s.instances, sp)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login/{conn}", s.login)
	mux.HandleFunc("GET /saml/{conn}/metadata", func(w http.ResponseWriter, r *http.Request) {
		s.pick().ServeMetadata(w, r, r.PathValue("conn"))
	})
	mux.HandleFunc("POST /saml/{conn}/acs", s.acs)

	s.srv = httptest.NewTLSServer(mux)
	t.Cleanup(s.srv.Close)

	return s
}

// pick returns the next instance.
func (s *serviceProvider) pick() *samlsp.ServiceProvider {
	return s.instances[(s.next.Add(1)-1)%uint64(len(s.instances))]
}

func (s *serviceProvider) resolve(_ context.Context, id string) (*samlsp.Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.conns[id]
	if !ok {
		return nil, samlsp.ErrUnknownConnection
	}

	return &c, nil
}

// addConnection (re)imports the IdP metadata under connection id; the SP
// entity ID and ACS URL derive from the server URL and the connection.
func (s *serviceProvider) addConnection(t testing.TB, id string, idpMetadata []byte, tune func(*samlsp.Connection)) samlsp.Connection {
	t.Helper()

	idp, err := samlsp.ParseIdentityProviderMetadata(idpMetadata, samlsp.MetadataOptions{})
	require.NoError(t, err, "import the IdP metadata")

	c := samlsp.Connection{
		ID:               id,
		SPEntityID:       s.srv.URL + "/saml/" + id,
		ACSURL:           s.srv.URL + "/saml/" + id + "/acs",
		IdentityProvider: *idp,
	}

	if tune != nil {
		tune(&c)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.conns[id] = c

	return c
}

// setConnection trusts idp under connection id, as addConnection does.
func (s *serviceProvider) setConnection(id string, idp *samlsp.IdentityProvider) samlsp.Connection {
	c := samlsp.Connection{
		ID:               id,
		SPEntityID:       s.srv.URL + "/saml/" + id,
		ACSURL:           s.srv.URL + "/saml/" + id + "/acs",
		IdentityProvider: *idp,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.conns[id] = c

	return c
}

// metadata fetches a connection's SP metadata over HTTP.
func (s *serviceProvider) metadata(t testing.TB, id string) []byte {
	t.Helper()

	resp, err := s.srv.Client().Get(s.srv.URL + "/saml/" + id + "/metadata")
	require.NoError(t, err)

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/samlmetadata+xml", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return body
}

func (s *serviceProvider) login(w http.ResponseWriter, r *http.Request) {
	target, err := s.pick().BeginLogin(r.Context(), w, r, r.PathValue("conn"), samlsp.LoginOptions{AppState: "/home"})
	if err != nil {
		http.Error(w, "cannot start the login", http.StatusInternalServerError)

		return
	}

	http.Redirect(w, r, target, http.StatusFound)
}

func (s *serviceProvider) acs(w http.ResponseWriter, r *http.Request) {
	res, err := s.pick().CompleteLogin(r.Context(), r, r.PathValue("conn"))

	s.mu.Lock()
	s.outcomes = append(s.outcomes, outcome{result: res, err: err})
	s.mu.Unlock()

	if err != nil {
		// A real ACS answers 200 with a generic page (Bindings §3.5.6); the
		// harness answers 403 so that tests can count refusals.
		http.Error(w, "sign-in refused", http.StatusForbidden)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res.Identity)
}

// last returns the latest ACS outcome.
func (s *serviceProvider) last(t testing.TB) outcome {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	require.NotEmpty(t, s.outcomes, "the ACS was never reached")

	return s.outcomes[len(s.outcomes)-1]
}

// browser is an HTTP client with its own cookie jar.
type browser struct{ client *http.Client }

// newBrowser returns a browser trusting the httptest certificate (shared
// by every httptest TLS server).
func newBrowser(t testing.TB, srv *httptest.Server) *browser {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	client := *srv.Client() // a copy: Client returns the server's own client
	client.Jar = jar

	return &browser{client: &client}
}

// postForm is the auto-submitted form of the HTTP-POST binding.
type postForm struct {
	action, samlResponse, relayState string
}

var (
	formAction = regexp.MustCompile(`<form method="post" action="([^"]+)"`)
	formInput  = regexp.MustCompile(`<input type="hidden" name="(SAMLResponse|RelayState)" value="([^"]*)"`)
)

// signIn starts an SP-initiated login and follows it to the IdP's POST
// form; it returns the IdP URL the SP redirected to and the form.
func (b *browser) signIn(sp *serviceProvider, conn string) (*url.URL, postForm, error) {
	var redirect *url.URL

	client := *b.client
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if redirect == nil {
			redirect = req.URL
		}

		return nil
	}

	resp, err := client.Get(sp.srv.URL + "/login/" + conn)
	if err != nil {
		return nil, postForm{}, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, postForm{}, err
	}

	action := formAction.FindSubmatch(body)
	if resp.StatusCode != http.StatusOK || action == nil || redirect == nil {
		return nil, postForm{}, fmt.Errorf("no POST form from the IdP (status %d): %.200s", resp.StatusCode, body)
	}

	form := postForm{action: html.UnescapeString(string(action[1]))}

	for _, m := range formInput.FindAllSubmatch(body, -1) {
		if v := html.UnescapeString(string(m[2])); string(m[1]) == "SAMLResponse" {
			form.samlResponse = v
		} else {
			form.relayState = v
		}
	}

	return redirect, form, nil
}

// mustSignIn is signIn for the test goroutine.
func (b *browser) mustSignIn(t testing.TB, sp *serviceProvider, conn string) (*url.URL, postForm) {
	t.Helper()

	redirect, form, err := b.signIn(sp, conn)
	require.NoError(t, err)

	return redirect, form
}

// post submits the form with the browser's cookies and returns the status.
func (b *browser) post(form postForm) (int, error) {
	resp, err := b.client.PostForm(form.action, url.Values{"SAMLResponse": {form.samlResponse}, "RelayState": {form.relayState}})
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

// mustPost is post for the test goroutine.
func (b *browser) mustPost(t testing.TB, form postForm) int {
	t.Helper()

	status, err := b.post(form)
	require.NoError(t, err)

	return status
}

// verifyRedirectSignature checks the HTTP-Redirect binding signature of an
// AuthnRequest URL (Bindings §3.4.4.1: rsa-sha256 over
// "SAMLRequest=…&RelayState=…&SigAlg=…" with the values exactly as
// URL-encoded in the query), independently of gosaml2.
func verifyRedirectSignature(u *url.URL, cert *x509.Certificate) error {
	raw := map[string]string{}

	for _, kv := range strings.Split(u.RawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		raw[k] = v
	}

	if sigAlg, err := url.QueryUnescape(raw["SigAlg"]); err != nil || sigAlg != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		return fmt.Errorf("unexpected SigAlg %q", raw["SigAlg"])
	}

	signed := "SAMLRequest=" + raw["SAMLRequest"] + "&RelayState=" + raw["RelayState"] + "&SigAlg=" + raw["SigAlg"]

	encoded, err := url.QueryUnescape(raw["Signature"])
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("not an RSA certificate")
	}

	digest := sha256.Sum256([]byte(signed))

	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// authnRequest inflates and parses (with crewjam) the AuthnRequest of a
// redirect URL.
func authnRequest(t testing.TB, u *url.URL) saml.AuthnRequest {
	t.Helper()

	deflated, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	require.NoError(t, err)

	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	require.NoError(t, err)

	var req saml.AuthnRequest
	require.NoError(t, xml.Unmarshal(raw, &req))

	return req
}
