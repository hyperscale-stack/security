// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

// The helper process of the opt-in browser suite in e2e/saml (Tales).
// e2e/saml/run.sh compiles this package's tests and runs
// TestE2EHelperProcess alone, with SAMLSP_E2E_SERVE naming the file where
// the helper reports that it is ready. The helper:
//   - starts the real examples/saml-sp binary (SAMLSP_E2E_EXAMPLE) on its
//     default 127.0.0.1:8084, trusting the helper's IdP;
//   - serves, on one TLS port and one runtime certificate, the sites the
//     scenarios browse: sp.test and acs.sp.test (a recording reverse proxy
//     in front of the example), evil.sp.test (cookie tossing, a forced
//     login from the same site), idp.test (a stateful crewjam IdP) and
//     attacker.test (cross-site pages);
//   - answers a plain-HTTP control API on loopback, which the scenarios use
//     to reset the helper, switch the IdP behaviour and read the
//     server-side evidence: the cookies each request carried, its
//     Sec-Fetch-Site, the Set-Cookie headers and the example's own log of
//     refused logins.
//
// Chrome reaches the sites through --host-resolver-rules and trusts the
// runtime certificate through --ignore-certificate-errors-spki-list: no
// trust store is touched and no key is written to disk.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/require"
)

const (
	e2ePort        = "18443"                 // every site, one TLS listener
	e2eControlAddr = "127.0.0.1:18480"       // the control API (plain HTTP)
	e2eExampleURL  = "http://127.0.0.1:8084" // the example's fixed address
	e2eSessionName = "idp_session"           // the IdP's own session cookie
)

// e2eHosts are the site names, all mapped to 127.0.0.1 by Chrome. Each
// .test name is its own site except evil.sp.test and acs.sp.test, which are
// same-site with sp.test on purpose.
var e2eHosts = []string{"sp.test", "acs.sp.test", "evil.sp.test", "idp.test", "attacker.test"}

// e2eSite returns the origin of a site.
func e2eSite(host string) string { return "https://" + host + ":" + e2ePort }

// e2eForm is an HTTP-POST binding form.
type e2eForm struct{ URL, SAMLResponse, RelayState string }

// e2eExchange is one request to the SP sites and its response.
type e2eExchange struct {
	host, method, path, secFetchSite string
	cookies                          []string
	status                           int
	setCookies                       []string
}

// e2eHelper holds the IdP and the recorded evidence.
type e2eHelper struct {
	idp       *saml.IdentityProvider
	passwords map[string]string // per-run random IdP passwords

	mu              sync.Mutex
	sp              *saml.EntityDescriptor // the example's SP metadata
	mode            string                 // IdP behaviour, see deliver
	exchanges       []e2eExchange
	hits            map[string]int // host and host+path
	rejections      []string       // the example's "login rejected" log lines
	failures        []string       // the example's "login error" log lines
	credentialPosts int
	held            map[string]e2eForm
	sessions        map[string]string // IdP session → user
	binding         string            // latest browser-binding value set by the SP
}

// TestE2EHelperProcess serves the e2e/saml sites until interrupted. It runs
// only when SAMLSP_E2E_SERVE is set (e2e/saml/run.sh).
func TestE2EHelperProcess(t *testing.T) {
	ready := os.Getenv("SAMLSP_E2E_SERVE")
	if ready == "" {
		t.Skip("helper process of e2e/saml/run.sh (set SAMLSP_E2E_SERVE)")
	}

	example := os.Getenv("SAMLSP_E2E_EXAMPLE")
	require.NotEmpty(t, example, "SAMLSP_E2E_EXAMPLE names the built examples/saml-sp binary")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tlsConfig, spki := newE2ECertificate(t)
	h := newE2EHelper(t)

	dir := t.TempDir()
	metadata := filepath.Join(dir, "idp-metadata.xml")
	raw, err := xml.MarshalIndent(h.idp.Metadata(), "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(metadata, raw, 0o600))

	sites := &http.Server{
		Addr: "127.0.0.1:" + e2ePort, Handler: h.sites(), TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0),
	}
	control := &http.Server{Addr: e2eControlAddr, Handler: h.control(), ReadHeaderTimeout: 10 * time.Second}

	for _, srv := range []*http.Server{sites, control} {
		ln, err := net.Listen("tcp", srv.Addr)
		require.NoError(t, err, "port %s", srv.Addr)

		go func() {
			if srv.TLSConfig != nil {
				_ = srv.ServeTLS(ln, "", "")
			} else {
				_ = srv.Serve(ln)
			}
		}()

		t.Cleanup(func() { _ = srv.Close() })
	}

	exited := h.startExample(t, example, metadata, os.Getenv("SAMLSP_E2E_EXAMPLE_LOG"))
	h.registerSP(t)

	require.NoError(t, os.WriteFile(ready, fmt.Appendf(nil, "SAMLSP_E2E_SPKI='%s'\n", spki), 0o600))
	t.Logf("sites on port %s, control on http://%s", e2ePort, e2eControlAddr)

	select {
	case <-ctx.Done():
	case <-exited:
		t.Error("the example exited")
	}
}

// newE2ECertificate returns a TLS configuration whose runtime certificate
// names every site, and the SPKI hashes (CA and leaf) Chrome must accept.
func newE2ECertificate(t *testing.T) (*tls.Config, string) {
	t.Helper()

	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "samlsp e2e CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sp.test"}, DNSNames: e2eHosts,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	hash := func(c *x509.Certificate) string {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)

		return base64.StdEncoding.EncodeToString(sum[:])
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey, Leaf: leaf}},
	}, hash(ca) + "," + hash(leaf)
}

// newE2EHelper builds the IdP with per-run passwords for alice and mallory.
func newE2EHelper(t *testing.T) *e2eHelper {
	t.Helper()

	h := &e2eHelper{
		passwords: map[string]string{"alice": rand.Text(), "mallory": rand.Text()},
		hits:      map[string]int{}, held: map[string]e2eForm{}, sessions: map[string]string{},
	}

	key := newKey(t, "e2e-idp")
	base, err := url.Parse(e2eSite("idp.test"))
	require.NoError(t, err)

	h.idp = &saml.IdentityProvider{
		Key: key.signer, Certificate: key.cert, Logger: logger.DefaultLogger,
		MetadataURL: *base.JoinPath("/metadata"), SSOURL: *base.JoinPath("/sso"),
		ServiceProviderProvider: h, SessionProvider: h, SignatureMethod: rsaSHA256,
	}

	return h
}

// startExample runs the example behind the proxy and returns a channel
// closed when it exits. Its log is scanned for refused logins and copied to
// logPath when set.
func (h *e2eHelper) startExample(t *testing.T, path, metadata, logPath string) <-chan struct{} {
	t.Helper()

	cmd := exec.Command(path) //nolint:gosec // the example binary built by run.sh
	cmd.Env = append(os.Environ(), "SAMLSP_IDP_METADATA="+metadata, "SAMLSP_BASE_URL="+e2eSite("sp.test"))

	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	var copyTo io.Writer = io.Discard

	if logPath != "" {
		f, err := os.Create(logPath) //nolint:gosec // run.sh's work directory
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })

		copyTo = f
	}

	exited := make(chan struct{})

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = fmt.Fprintln(copyTo, line)
			h.noteExampleLog(line)
		}

		_ = cmd.Wait()

		close(exited)
	}()

	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)

		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	})

	deadline := time.Now().Add(15 * time.Second)

	for {
		select {
		case <-exited:
			require.FailNow(t, "the example exited at startup (is :8084 free?)")
		default:
		}

		resp, err := http.Get(e2eExampleURL + "/saml/corp/metadata")
		if err == nil {
			_ = resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return exited
			}
		}

		require.True(t, time.Now().Before(deadline), "the example did not start")
		time.Sleep(50 * time.Millisecond)
	}
}

// noteExampleLog records the example's refusals.
func (h *e2eHelper) noteExampleLog(line string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, msg, ok := strings.Cut(line, "saml-sp: login rejected: "); ok {
		h.rejections = append(h.rejections, msg)
	}

	if _, msg, ok := strings.Cut(line, "saml-sp: login error: "); ok {
		h.failures = append(h.failures, msg)
	}
}

// registerSP imports the example's SP metadata into the IdP.
func (h *e2eHelper) registerSP(t *testing.T) {
	t.Helper()

	resp, err := http.Get(e2eExampleURL + "/saml/corp/metadata")
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)

	var ed saml.EntityDescriptor
	require.NoError(t, xml.Unmarshal(body, &ed))
	require.Equal(t, e2eSite("sp.test")+"/saml/corp", ed.EntityID)

	h.mu.Lock()
	h.sp = &ed
	h.mu.Unlock()
}

// GetServiceProvider implements saml.ServiceProviderProvider.
func (h *e2eHelper) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.sp == nil || h.sp.EntityID != id {
		return nil, os.ErrNotExist
	}

	return h.sp, nil
}

// e2eSession is the IdP session of user: a persistent, pairwise NameID.
func e2eSession(user string) *saml.Session {
	now := saml.TimeNow()

	return &saml.Session{
		ID: "session-" + user, CreateTime: now, ExpireTime: now.Add(time.Hour), Index: "index-" + user,
		NameID: user + "-pairwise-id", NameIDFormat: samlsp.NameIDFormatPersistent,
		UserName: user, UserEmail: user + "@example.test",
	}
}

var e2eLoginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html><head><title>IdP sign-in</title></head><body>
<h1>Identity provider</h1>{{if .Failed}}<p data-testid="idp.failed">Wrong credentials</p>{{end}}
<form data-testid="idp.login" method="post" action="/sso">
<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}">
<input type="hidden" name="RelayState" value="{{.RelayState}}">
<label>User <input data-testid="idp.user" name="user"></label>
<label>Password <input data-testid="idp.password" name="password" type="password"></label>
<button data-testid="idp.submit" type="submit">Sign in</button>
</form></body></html>`))

// GetSession implements saml.SessionProvider: the IdP session cookie, or a
// credential form posted back to /sso with the request. In the as-mallory
// mode, the IdP is the attacker's: it answers as mallory, unprompted.
func (h *e2eHelper) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.mode == "as-mallory" {
		return e2eSession("mallory")
	}

	if c, err := r.Cookie(e2eSessionName); err == nil {
		if user, ok := h.sessions[c.Value]; ok {
			return e2eSession(user)
		}
	}

	failed := false

	if r.Method == http.MethodPost && r.PostFormValue("user") != "" {
		h.credentialPosts++

		user := r.PostFormValue("user")
		if want, ok := h.passwords[user]; ok && subtle.ConstantTimeCompare([]byte(r.PostFormValue("password")), []byte(want)) == 1 {
			id := rand.Text()
			h.sessions[id] = user

			http.SetCookie(w, &http.Cookie{
				Name: e2eSessionName, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})

			return e2eSession(user)
		}

		failed = true
	}

	_ = e2eLoginPage.Execute(w, map[string]any{
		"Failed": failed, "SAMLRequest": base64.StdEncoding.EncodeToString(req.RequestBuffer), "RelayState": req.RelayState,
	})

	return nil
}

var e2eAutoPost = template.Must(template.New("post").Parse(`<!doctype html>
<html><head><title>Signing in</title></head><body>
<form id="saml" method="post" action="{{.URL}}">
<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}">
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}">{{end}}
</form><script>document.getElementById("saml").submit()</script></body></html>`))

var e2ePage = template.Must(template.New("page").Parse(`<!doctype html>
<html><head><title>{{.Title}}</title></head><body><p data-testid="{{.ID}}">{{.Title}}</p>{{.Extra}}</body></html>`))

// page renders a marker page.
func page(w http.ResponseWriter, status int, id, title string, extra template.HTML) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = e2ePage.Execute(w, map[string]any{"ID": id, "Title": title, "Extra": extra})
}

// sites routes the TLS requests by host.
func (h *e2eHelper) sites() http.Handler {
	target, _ := url.Parse(e2eExampleURL)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
		},
		// A Lax and a Strict cookie minted at the ACS show which of them
		// the still cross-site redirect after the ACS carries.
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request.Method == http.MethodPost && strings.HasSuffix(resp.Request.URL.Path, "/acs") {
				resp.Header.Add("Set-Cookie", "__Host-acs-lax=1; Path=/; Secure; HttpOnly; SameSite=Lax")
				resp.Header.Add("Set-Cookie", "__Host-acs-strict=1; Path=/; Secure; HttpOnly; SameSite=Strict")
			}

			return nil
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}

		h.mu.Lock()
		h.hits[host]++
		h.hits[host+r.URL.Path]++
		h.mu.Unlock()

		switch host {
		case "sp.test", "acs.sp.test":
			h.serveSP(w, r, host, proxy)
		case "evil.sp.test":
			h.serveEvilSibling(w, r)
		case "idp.test":
			h.serveIdP(w, r)
		case "attacker.test":
			h.serveAttacker(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// statusWriter remembers the response status.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// serveSP proxies to the example and records the exchange; it also serves
// the control cookies, a pixel, and a login entry point for browsers
// without Fetch Metadata.
func (h *e2eHelper) serveSP(w http.ResponseWriter, r *http.Request, host string, proxy http.Handler) {
	rec := &statusWriter{ResponseWriter: w, status: http.StatusOK}

	defer func() { h.record(r, host, rec.status, rec.Header().Values("Set-Cookie")) }()

	switch r.URL.Path {
	case "/_e2e/controls":
		// One control cookie per SameSite value, set first-party.
		for _, mode := range []string{"Lax", "Strict", "None"} {
			rec.Header().Add("Set-Cookie", "__Host-ctl-"+strings.ToLower(mode)+"=1; Path=/; Secure; HttpOnly; SameSite="+mode)
		}

		page(rec, http.StatusOK, "sp.controls", "control cookies set", "")

		return
	case "/_e2e/pixel":
		rec.Header().Set("Content-Type", "image/gif")
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.Write([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"))

		return
	}

	// A browser that predates Fetch Metadata sends no Sec-Fetch-* header:
	// this entry point forwards to the example's login without them.
	if r.URL.Path == "/_e2e/legacy-login" {
		r.URL.Path = "/login"

		for _, name := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User"} {
			r.Header.Del(name)
		}
	}

	proxy.ServeHTTP(rec, r)
}

// record keeps one SP exchange and the latest binding value.
func (h *e2eHelper) record(r *http.Request, host string, status int, setCookies []string) {
	names := make([]string, 0, len(r.Cookies()))
	for _, c := range r.Cookies() {
		names = append(names, c.Name)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.exchanges = append(h.exchanges, e2eExchange{
		host: host, method: r.Method, path: r.URL.Path, secFetchSite: r.Header.Get("Sec-Fetch-Site"),
		cookies: names, status: status, setCookies: setCookies,
	})

	for _, raw := range setCookies {
		if c, err := http.ParseSetCookie(raw); err == nil && c.Name == samlsp.DefaultCookieName {
			h.binding = c.Value
		}
	}
}

// serveEvilSibling plants cookies for sp.test from its sibling: each
// carries the latest binding value the SP set (mallory's, in BR4).
func (h *e2eHelper) serveEvilSibling(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/toss":
	case "/force-login":
		// Forced login initiation from the same site, another origin.
		forceLogin(w, "/login")

		return
	default:
		http.NotFound(w, r)

		return
	}

	h.mu.Lock()
	v := h.binding
	h.mu.Unlock()

	for _, c := range []string{
		"__Host-samlsp=" + v + "; Domain=sp.test; Path=/; Secure; SameSite=None",  // __Host- with Domain
		"=__Host-samlsp=" + v + "; Domain=sp.test; Path=/; Secure; SameSite=None", // nameless, __Host- value
		"__HOST-samlsp=" + v + "; Domain=sp.test; Path=/; Secure; SameSite=None",  // case variant of the prefix
		"__Host-samlsp=" + v + "; Path=/; Secure; SameSite=None",                  // valid, host-only on evil.sp.test
		"samlsp=" + v + "; Domain=sp.test; Path=/; Secure; SameSite=None",         // control: no prefix
	} {
		w.Header().Add("Set-Cookie", c)
	}

	page(w, http.StatusOK, "evil.tossed", "cookies tossed", "")
}

// serveIdP serves the IdP: SSO, held responses and IdP-initiated logins.
func (h *e2eHelper) serveIdP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/sso":
		h.sso(w, r)
	case "/_e2e/release":
		h.mu.Lock()
		form, ok := h.held[r.URL.Query().Get("slot")]
		h.mu.Unlock()

		if !ok {
			page(w, http.StatusNotFound, "idp.nothing", "nothing held", "")

			return
		}

		_ = e2eAutoPost.Execute(w, form)
	case "/_e2e/unsolicited":
		h.mu.Lock()
		spID := ""
		if h.sp != nil {
			spID = h.sp.EntityID
		}
		h.mu.Unlock()

		h.idp.ServeIDPInitiated(w, r, spID, "")
	default:
		http.NotFound(w, r)
	}
}

// sso is crewjam's ServeSSO with the delivery of the response under test
// control.
func (h *e2eHelper) sso(w http.ResponseWriter, r *http.Request) {
	req, err := saml.NewIdpAuthnRequest(h.idp, r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	if err := req.Validate(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	session := h.GetSession(w, r, req)
	if session == nil {
		return
	}

	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		http.Error(w, "cannot make the assertion", http.StatusInternalServerError)

		return
	}

	form, err := req.PostBinding()
	if err != nil {
		http.Error(w, "cannot make the response", http.StatusInternalServerError)

		return
	}

	h.deliver(w, e2eForm{URL: form.URL, SAMLResponse: form.SAMLResponse, RelayState: form.RelayState})
}

// deliver posts a response form to the SP according to the IdP mode:
//   - "" or "as-mallory": unchanged;
//   - hold: kept in slot "held", not delivered (mallory's own valid form);
//   - hold-first: kept in slot "first", not delivered;
//   - tamper: delivered with another handle of the same shape, the
//     original kept in slot "original";
//   - swap: delivered with the RelayState of slot "first", the original
//     kept in slot "second";
//   - drop: delivered without RelayState;
//   - url: delivered with a URL as RelayState.
func (h *e2eHelper) deliver(w http.ResponseWriter, form e2eForm) {
	h.mu.Lock()

	switch h.mode {
	case "hold", "hold-first":
		h.held[map[string]string{"hold": "held", "hold-first": "first"}[h.mode]] = form
		h.mu.Unlock()

		page(w, http.StatusOK, "idp.held", "response held", "")

		return
	case "tamper":
		h.held["original"] = form

		flipped := byte('A')
		if form.RelayState != "" && form.RelayState[0] == 'A' {
			flipped = 'B'
		}

		form.RelayState = string(flipped) + form.RelayState[min(1, len(form.RelayState)):]
	case "swap":
		h.held["second"] = form
		form.RelayState = h.held["first"].RelayState
	case "drop":
		form.RelayState = ""
	case "url":
		form.RelayState = e2eSite("attacker.test") + "/landing"
	}

	h.mu.Unlock()

	_ = e2eAutoPost.Execute(w, form)
}

// serveAttacker serves the attacker's cross-site pages.
func (h *e2eHelper) serveAttacker(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/csrf":
		// Login CSRF: auto-post mallory's own valid form into the
		// visitor's browser.
		h.mu.Lock()
		form, ok := h.held[r.URL.Query().Get("slot")]
		h.mu.Unlock()

		if !ok {
			page(w, http.StatusNotFound, "attacker.nothing", "nothing held", "")

			return
		}

		_ = e2eAutoPost.Execute(w, form)
	case "/force-login":
		// Forced login initiation: navigate the visitor to the SP's login.
		forceLogin(w, "/login")
	case "/force-legacy-login":
		// The same, as seen from a browser without Fetch Metadata.
		forceLogin(w, "/_e2e/legacy-login")
	case "/pixel":
		// A cross-site subresource: carries only third-party cookies.
		page(w, http.StatusOK, "attacker.pixel", "pixel page", template.HTML(
			`<img alt="" src="`+e2eSite("sp.test")+`/_e2e/pixel">`)) //nolint:gosec // constant markup
	default:
		page(w, http.StatusOK, "attacker.landing", "attacker landing", "")
	}
}

// forceLogin answers a page navigating the visitor to path on sp.test, the
// SP's login entry point, without any user gesture.
func forceLogin(w http.ResponseWriter, path string) {
	page(w, http.StatusOK, "force", "redirecting", template.HTML( //nolint:gosec // constant markup
		`<script>location.replace("`+e2eSite("sp.test")+path+`?return=/")</script>`))
}

// control serves the control API.
func (h *e2eHelper) control() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Mode string `json:"mode"`
		}

		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "bad JSON", http.StatusBadRequest)

			return
		}

		h.mu.Lock()
		h.mode = in.Mode
		h.exchanges, h.rejections, h.failures = nil, nil, nil
		h.credentialPosts, h.binding = 0, ""
		h.hits, h.held, h.sessions = map[string]int{}, map[string]e2eForm{}, map[string]string{}
		h.mu.Unlock()

		writeJSON(w, map[string]any{
			"alice_password": h.passwords["alice"], "mallory_password": h.passwords["mallory"],
			"mode": in.Mode,
		})
	})

	mux.HandleFunc("POST /config", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Mode *string `json:"mode"`
		}

		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
			http.Error(w, "bad JSON", http.StatusBadRequest)

			return
		}

		h.mu.Lock()
		if in.Mode != nil {
			h.mode = *in.Mode
		}

		out := map[string]any{"mode": h.mode}
		h.mu.Unlock()

		writeJSON(w, out)
	})

	mux.HandleFunc("GET /state", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, h.snapshot())
	})

	return mux
}

// writeJSON answers v as JSON.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// snapshot is the evidence the scenarios assert: for each kind of SP
// exchange, the latest one, with the names of the cookies the browser
// sent (absent cookies are absent keys) and the cookies the response set.
func (h *e2eHelper) snapshot() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()

	last := func(match func(e e2eExchange) bool) int {
		for i := len(h.exchanges) - 1; i >= 0; i-- {
			if match(h.exchanges[i]) {
				return i
			}
		}

		return -1
	}

	view := func(i int) any {
		if i < 0 {
			return nil
		}

		e := h.exchanges[i]
		cookies := map[string]bool{}

		for _, name := range e.cookies {
			cookies[name] = true
		}

		set := map[string]any{}

		for _, raw := range e.setCookies {
			if c, err := http.ParseSetCookie(raw); err == nil {
				set[c.Name] = map[string]any{
					"path": c.Path, "domain": c.Domain, "secure": c.Secure, "http_only": c.HttpOnly,
					"same_site": sameSiteName(c.SameSite), "max_age": c.MaxAge,
					"cleared": c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())),
				}
			}
		}

		return map[string]any{
			"host": e.host, "method": e.method, "path": e.path, "status": e.status,
			"sec_fetch_site": e.secFetchSite, "cookies": cookies, "set_cookies": set,
		}
	}

	isACS := func(e e2eExchange) bool { return e.method == http.MethodPost && strings.HasSuffix(e.path, "/acs") }
	acs := last(isACS)

	// The request that followed the latest ACS: its 303 target.
	afterACS := -1

	if acs >= 0 {
		for i := acs + 1; i < len(h.exchanges); i++ {
			if h.exchanges[i].method == http.MethodGet && !strings.HasPrefix(h.exchanges[i].path, "/_e2e/") {
				afterACS = i

				break
			}
		}
	}

	signedIn, acsCount := 0, 0

	for _, e := range h.exchanges {
		if isACS(e) {
			acsCount++

			if e.status == http.StatusSeeOther {
				signedIn++
			}
		}
	}

	lastRejection := ""
	if len(h.rejections) > 0 {
		lastRejection = h.rejections[len(h.rejections)-1]
	}

	hits := map[string]int{}
	for k, v := range h.hits {
		hits[k] = v
	}

	return map[string]any{
		"mode":      h.mode,
		"login":     view(last(func(e e2eExchange) bool { return e.method == http.MethodGet && e.path == "/login" })),
		"acs":       view(acs),
		"after_acs": view(afterACS),
		"logout":    view(last(func(e e2eExchange) bool { return e.method == http.MethodPost && e.path == "/logout" })),
		"pixel":     view(last(func(e e2eExchange) bool { return e.path == "/_e2e/pixel" })),
		"acs_count": acsCount, "signed_in": signedIn,
		"rejections": append([]string{}, h.rejections...), "rejection_count": len(h.rejections), "last_rejection": lastRejection,
		"failures":         append([]string{}, h.failures...),
		"credential_posts": h.credentialPosts,
		"hits":             hits, "attacker_landing": hits["attacker.test/landing"],
	}
}

// sameSiteName renders a parsed SameSite attribute.
func sameSiteName(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}
