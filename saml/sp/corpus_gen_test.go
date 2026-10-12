// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

// Regeneration of testdata/corpus. Run it alone, so that nothing else
// draws from the deterministic randomness:
//
//	go test -run '^TestCorpusGenerate$' -count=1 . -args -corpus.update
//
// With the same Go toolchain and the same goxmldsig/etree versions the
// output is byte-identical (git diff --exit-code proves it). The generator
// checks every declared outcome against the real Service Provider before
// writing anything; -corpus.report prints the outcomes instead.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/require"
)

var (
	updateCorpus = flag.Bool("corpus.update", false, "regenerate testdata/corpus (TestCorpusGenerate)")
	reportCorpus = flag.Bool("corpus.report", false, "print the outcome of every corpus spec (TestCorpusGenerate)")
)

// corpusSeed seeds testing/cryptotest: keys, request IDs, RelayState
// handles, binding cookies and ECDSA signatures are deterministic.
const corpusSeed uint64 = 0x53414d4c0088 // "SAML", issue #88

// corpusGen builds the corpus.
type corpusGen struct {
	t     *testing.T
	keys  map[string]keyPair
	certs map[string]*x509.Certificate
	conns map[string]corpusConnection
	txs   map[string]corpusTx
}

// Connections of the corpus. initech squats acme's IdP: same entity ID,
// same trusted key, its own SP entity ID and ACS (decision D1).
func corpusConnections() map[string]corpusConnection {
	return map[string]corpusConnection{
		"acme": {
			SPEntityID: spEntityID, ACSURL: acsURL, IdPEntityID: idpEntity, SSOURL: ssoURL, Trust: []string{"idp-a"},
		},
		"globex": {
			SPEntityID: "https://sp.example.com/saml/globex", ACSURL: "https://sp.example.com/saml/globex/acs",
			IdPEntityID: "https://idp.example.com/globex", SSOURL: "https://idp.example.com/sso?tenant=globex",
			Trust: []string{"idp-b"},
		},
		"initech": {
			SPEntityID: "https://sp.example.com/saml/initech", ACSURL: "https://sp.example.com/saml/initech/acs",
			IdPEntityID: idpEntity, SSOURL: ssoURL, Trust: []string{"idp-a"},
		},
	}
}

// Corpus key validity: around t0, never rotting since every replay pins
// the SP clock (and goxmldsig evaluates certificates at that clock).
var (
	corpusNotBefore = t0.Add(-24 * time.Hour)
	corpusNotAfter  = t0.AddDate(10, 0, 0)
)

// newCorpusGen generates the keys (in a fixed order: the randomness is a
// stream) and the transactions.
func newCorpusGen(t *testing.T) *corpusGen {
	t.Helper()

	g := &corpusGen{t: t, keys: map[string]keyPair{}, certs: map[string]*x509.Certificate{}, conns: corpusConnections()}

	g.rsaKey("idp-a", 1, corpusNotBefore, corpusNotAfter)
	g.rsaKey("idp-b", 2, corpusNotBefore, corpusNotAfter)
	g.rsaKey("attacker", 3, corpusNotBefore, corpusNotAfter)
	g.rsaKey("expired", 4, t0.Add(-48*time.Hour), t0.Add(-24*time.Hour))
	g.rsaKey("expired-2", 5, t0.Add(-72*time.Hour), t0.Add(-25*time.Hour))
	g.ecKey("idp-ec", 6)

	// Four valid keys announced at once, oldest first (rollover retry cap).
	for i := 1; i <= 4; i++ {
		g.rsaKey(fmt.Sprintf("roll-%d", i), int64(6+i), t0.Add(-time.Duration(5-i)*24*time.Hour), corpusNotAfter)
	}

	// Certificate faking: idp-a's subject and serial number, the attacker's
	// key, self-signed.
	attacker := g.keys["attacker"]
	faked := g.certificate(attacker.signer, g.keys["idp-a"].cert.Subject.CommonName, 1, corpusNotBefore, corpusNotAfter)
	g.keys["faked-idp-a"] = keyPair{signer: attacker.signer, cert: faked}
	g.certs["faked-idp-a"] = faked

	g.txs = map[string]corpusTx{}
	acme := g.begin("acme", "acme", samlsp.LoginOptions{AppState: "/after"}, "", "")
	g.begin("acme-2", "acme", samlsp.LoginOptions{AppState: "/second"}, acme.Cookie, "")
	g.begin("acme-forceauthn", "acme", samlsp.LoginOptions{ForceAuthn: true}, "", "")
	g.begin("acme-authncontext", "acme", samlsp.LoginOptions{
		RequestedAuthnContext: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:X509"},
	}, "", "")
	g.begin("acme-persistent", "acme", samlsp.LoginOptions{}, "", samlsp.NameIDFormatPersistent)
	g.begin("globex", "globex", samlsp.LoginOptions{}, "", "")
	g.begin("initech", "initech", samlsp.LoginOptions{}, "", "")

	return g
}

func (g *corpusGen) rsaKey(name string, serial int64, notBefore, notAfter time.Time) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(g.t, err)

	g.keys[name] = keyPair{signer: k, cert: g.certificate(k, name, serial, notBefore, notAfter)}
	g.certs[name] = g.keys[name].cert
}

func (g *corpusGen) ecKey(name string, serial int64) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(g.t, err)

	g.keys[name] = keyPair{signer: k, cert: g.certificate(k, name, serial, corpusNotBefore, corpusNotAfter)}
	g.certs[name] = g.keys[name].cert
}

// certificate self-signs a corpus test certificate.
func (g *corpusGen) certificate(k crypto.Signer, name string, serial int64, notBefore, notAfter time.Time) *x509.Certificate {
	cn := name
	if !strings.HasPrefix(name, "samlsp corpus ") {
		cn = "samlsp corpus " + name + " - TEST KEY, DO NOT TRUST"
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	require.NoError(g.t, err)

	c, err := x509.ParseCertificate(der)
	require.NoError(g.t, err)

	return c
}

// recordingStore captures the record BeginLogin saves.
type recordingStore struct {
	*memory.Store

	saved samlsp.TransactionRecord
}

func (r *recordingStore) SaveTransaction(ctx context.Context, rec *samlsp.TransactionRecord) error {
	r.saved = *rec

	return r.Store.SaveTransaction(ctx, rec)
}

// begin runs a real BeginLogin at t0 and records the transaction.
func (g *corpusGen) begin(name, connID string, opts samlsp.LoginOptions, cookie, nameIDFormat string) corpusTx {
	g.t.Helper()

	c := g.conns[connID]
	conn := &samlsp.Connection{
		ID: connID, SPEntityID: c.SPEntityID, ACSURL: c.ACSURL, NameIDFormat: nameIDFormat,
		IdentityProvider: samlsp.IdentityProvider{
			EntityID: c.IdPEntityID, SSOURL: c.SSOURL, SigningCertificates: []*x509.Certificate{g.certs[c.Trust[0]]},
		},
	}

	store := &recordingStore{Store: memory.New()}

	sp, err := samlsp.New(samlsp.Config{
		Connections:  newResolver(conn),
		Transactions: store,
		ReplayCache:  store,
		Now:          func() time.Time { return t0 },
	})
	require.NoError(g.t, err)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: cookie})
	}

	rec := httptest.NewRecorder()

	raw, err := sp.BeginLogin(context.Background(), rec, req, connID, opts)
	require.NoError(g.t, err)

	u, err := url.Parse(raw)
	require.NoError(g.t, err)

	request := decodeAuthnRequest(g.t, u)

	tx := corpusTx{
		Connection: connID,
		RequestID:  request.SelectAttrValue("ID", ""),
		RelayState: u.Query().Get("RelayState"),
		Record:     store.saved,
	}

	for _, ck := range rec.Result().Cookies() {
		if ck.Name == samlsp.DefaultCookieName {
			tx.Cookie = ck.Value
		}
	}

	require.NotEmpty(g.t, tx.Cookie)
	g.txs[name] = tx

	return tx
}

// opts fills the corpus defaults of a respOpts: every signature made by
// an explicit corpus key (never the package's random keys).
func (g *corpusGen) opts(o respOpts) respOpts {
	if o.assertionSig.signer.signer == nil {
		o.assertionSig.signer = g.keys["idp-a"]
	}

	if o.responseSig.signer.signer == nil {
		o.responseSig.signer = g.keys["idp-a"]
	}

	return o
}

// xml builds the response answering the transaction tx with o.
func (g *corpusGen) xml(tx string, o respOpts) []byte {
	g.t.Helper()

	return []byte(respondXML(g.t, g.txs[tx].RequestID, g.opts(o)))
}

// resignAssertion returns a hook that edits the assertion signature's
// SignedInfo and signs it again with idp-a: the result is a valid
// signature of a shape goxmldsig's signer cannot produce, so only the
// pre-check can refuse it.
func (g *corpusGen) resignAssertion(edit func(sig *etree.Element), hash crypto.Hash) func(_, a *etree.Element) {
	return func(_, a *etree.Element) {
		sig := child(a, "Signature")
		edit(sig)
		resign(g.t, sig, g.keys["idp-a"], hash)
	}
}

// resignResponse is resignAssertion for the Response signature (the
// Response must be signed, with respOpts.signResponse).
func (g *corpusGen) resignResponse(edit func(sig *etree.Element), hash crypto.Hash) func(r *etree.Element) {
	return func(r *etree.Element) {
		sig := child(r, "Signature")
		edit(sig)
		resign(g.t, sig, g.keys["idp-a"], hash)
	}
}

// forged returns an unsigned assertion naming the attacker.
func forged(id string) *etree.Element {
	a := buildAssertion(respParams{requestID: "_evil-request", issued: t0})
	a.CreateAttr("ID", id)
	path(a, "Subject", "NameID").SetText("mallory@attacker.example")

	return a
}

// corpusSpec declares one entry: how its bytes are built and what it must
// yield.
type corpusSpec struct {
	id     string // category/name
	attack string
	refs   []string
	tx     string // default acme
	knobs  corpusKnobs
	build  func() []byte
	expect corpusExpect
	file   string // optional file name override (reuse another entry's bytes)
}

// rejected declares a refusal: the sentinel and the static detail of the
// rule that must refuse ("" for a sentinel without detail).
func rejected(sentinel, detail string) corpusExpect {
	return corpusExpect{Outcome: outcomeRejected, Sentinel: sentinel, Detail: detail}
}

// accepted declares an accepted response with its exact identity.
func accepted(id samlsp.Identity) corpusExpect {
	return corpusExpect{Outcome: outcomeAccepted, Identity: &id}
}

// statusOf declares an IdP error status.
func statusOf(code, subCode, message, printed string) corpusExpect {
	return corpusExpect{
		Outcome: outcomeStatus, Sentinel: "ErrResponseStatus",
		Status: &corpusStatus{Code: code, SubCode: subCode, Message: message, Printed: printed},
	}
}

// baselineIdentity is the identity of #87's reference assertion for acme.
func baselineIdentity() samlsp.Identity {
	return samlsp.Identity{
		ConnectionID: "acme",
		Issuer:       idpEntity,
		Audience:     spEntityID,
		NameID: samlsp.NameID{
			Value: nameIDValue, Format: samlsp.NameIDFormatPersistent, NameQualifier: idpEntity, SPNameQualifier: spEntityID,
		},
		Attributes: []samlsp.Attribute{
			{Name: "mail", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", Values: []string{"alice@example.com"}},
			{Name: "groups", Values: []string{"admins", "devs"}},
			{Name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.10", FriendlyName: "eduPersonTargetedID", Values: []string{"targeted-7"}},
		},
		SessionIndex:         "_session-42",
		AuthnInstant:         t0,
		SessionNotOnOrAfter:  t0.Add(8 * time.Hour),
		AuthnContextClassRef: pptClass,
		AssertionID:          assertionID,
	}
}

// TestCorpusGenerate regenerates testdata/corpus (-corpus.update) or
// reports the outcome of every spec (-corpus.report).
func TestCorpusGenerate(t *testing.T) {
	if !*updateCorpus && !*reportCorpus {
		t.Skip("run with -args -corpus.update (or -corpus.report) to regenerate testdata/corpus")
	}

	require.Nil(t, keysVal, "run alone: -run '^TestCorpusGenerate$' -count=1")

	cryptotest.SetGlobalRandom(t, corpusSeed)

	g := newCorpusGen(t)
	specs := corpusSpecs(g)
	m := g.manifest()

	var problems []string

	files := map[string][]byte{}

	for _, s := range specs {
		entry, data := g.entry(s)
		m.Fixtures = append(m.Fixtures, entry)

		for _, preparsed := range []bool{false, true} {
			o := runCorpusEntry(t, m, g.certs, entry, data, preparsed)

			if *reportCorpus {
				t.Logf("%-55s preparsed=%-5v %s", entry.ID, preparsed, describeOutcome(o))
			}

			if problem := checkOutcome(entry, o, preparsed); problem != "" {
				problems = append(problems, fmt.Sprintf("%s (pre-parsed %v): %s", entry.ID, preparsed, problem))
			}
		}

		if prev, dup := files[entry.File]; dup && !bytes.Equal(prev, data) {
			problems = append(problems, entry.ID+": shares "+entry.File+" with different bytes")
		} else if !dup {
			files[entry.File] = data
		}
	}

	require.Nil(t, keysVal, "a corpus builder used the package's random keys (fixtures_test.go keys())")
	require.Empty(t, problems, "declared outcomes differ from the Service Provider:\n%s", strings.Join(problems, "\n"))

	if *updateCorpus {
		g.write(m, files)
	}
}

// describeOutcome renders an outcome for -corpus.report.
func describeOutcome(o entryOutcome) string {
	if o.err == nil {
		return fmt.Sprintf("ACCEPTED nameid=%q consumes=%d marks=%d", o.result.Identity.NameID.Value, o.consumes, o.marks)
	}

	return fmt.Sprintf("%q consumes=%d marks=%d consumed=%v", o.err.Error(), o.consumes, o.marks, o.consumed)
}

// manifest returns the manifest header (without entries).
func (g *corpusGen) manifest() *corpusManifest {
	keys := map[string]string{}
	for name, c := range g.certs {
		keys[name] = base64.StdEncoding.EncodeToString(c.Raw)
	}

	return &corpusManifest{
		Version:   1,
		Instant:   t0,
		Generator: "go test -run '^TestCorpusGenerate$' -count=1 ./saml/sp -args -corpus.update",
		GeneratedWith: map[string]string{
			"go": runtime.Version(), "goxmldsig": "v1.6.1", "gosaml2": "v0.12.0", "etree": "v1.8.1",
		},
		Keys:         keys,
		Connections:  g.conns,
		Transactions: g.txs,
	}
}

// entry builds the manifest entry and the bytes of a spec.
func (g *corpusGen) entry(s corpusSpec) (corpusEntry, []byte) {
	g.t.Helper()

	data := s.build()
	sum := sha256.Sum256(data)

	// Every fixture is stored gzipped: the corpus stays small, and the
	// pinned hash covers the XML itself (stable across compressors).
	file := s.file
	if file == "" {
		ext := ".xml.gz"
		if s.knobs.Encoding == "asis" {
			ext = ".txt.gz"
		}

		file = s.id + ext
	}

	tx := s.tx
	if tx == "" {
		tx = "acme"
	}

	category, _, _ := strings.Cut(s.id, "/")

	return corpusEntry{
		ID: s.id, Category: category, Attack: s.attack, Refs: s.refs, File: file,
		SHA256: hex.EncodeToString(sum[:]), Transaction: tx, Knobs: s.knobs, Expect: s.expect,
	}, data
}

// write replaces testdata/corpus with the generated files and manifest.
func (g *corpusGen) write(m *corpusManifest, files map[string][]byte) {
	g.t.Helper()

	require.NoError(g.t, os.RemoveAll(corpusDir))

	for name, data := range files {
		target := filepath.Join(corpusDir, filepath.FromSlash(name))
		require.NoError(g.t, os.MkdirAll(filepath.Dir(target), 0o750))

		if strings.HasSuffix(name, ".gz") {
			var buf bytes.Buffer

			zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			require.NoError(g.t, err)
			zw.ModTime = time.Time{} // reproducible archives
			_, err = zw.Write(data)
			require.NoError(g.t, err)
			require.NoError(g.t, zw.Close())

			data = buf.Bytes()
		}

		require.NoError(g.t, os.WriteFile(target, data, 0o600))
	}

	out, err := json.MarshalIndent(m, "", "  ")
	require.NoError(g.t, err)
	require.NoError(g.t, os.WriteFile(filepath.Join(corpusDir, "manifest.json"), append(out, '\n'), 0o600))
}
