// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

// The adversarial corpus: pinned, signed SAML responses under
// testdata/corpus, each labelled with the attack it carries and the exact
// outcome it must produce. TestCorpus replays every entry against the
// public API; corpus_gen_test.go regenerates the files deterministically.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/require"
)

// corpusDir holds the pinned corpus, relative to the package directory.
const corpusDir = "testdata/corpus"

// corpusManifest is testdata/corpus/manifest.json.
type corpusManifest struct {
	Version       int                         `json:"version"`
	Instant       time.Time                   `json:"instant"`
	Generator     string                      `json:"generator"`
	GeneratedWith map[string]string           `json:"generatedWith"`
	Keys          map[string]string           `json:"keys"` // base64 DER certificates
	Connections   map[string]corpusConnection `json:"connections"`
	Transactions  map[string]corpusTx         `json:"transactions"`
	Fixtures      []corpusEntry               `json:"fixtures"`
}

// corpusConnection is one configured connection of the corpus.
type corpusConnection struct {
	SPEntityID   string   `json:"spEntityID"`
	ACSURL       string   `json:"acsURL"`
	IdPEntityID  string   `json:"idpEntityID"`
	SSOURL       string   `json:"ssoURL"`
	Trust        []string `json:"trust"`
	NameIDFormat string   `json:"nameIDFormat,omitempty"`
}

// corpusTx is a transaction captured from a real BeginLogin.
type corpusTx struct {
	Connection string                   `json:"connection"`
	RequestID  string                   `json:"requestID"`
	RelayState string                   `json:"relayState"`
	Cookie     string                   `json:"cookie"`
	Record     samlsp.TransactionRecord `json:"record"`
}

// corpusEntry is one pinned response and what it must yield.
type corpusEntry struct {
	ID          string       `json:"id"`
	Category    string       `json:"category"`
	Attack      string       `json:"attack"`
	Refs        []string     `json:"refs,omitempty"`
	File        string       `json:"file"`
	SHA256      string       `json:"sha256"` // of the XML (decompressed for .gz)
	Transaction string       `json:"transaction"`
	Knobs       corpusKnobs  `json:"knobs"`
	Expect      corpusExpect `json:"expect"`
}

// corpusKnobs set the request and the configuration around the response.
type corpusKnobs struct {
	// PostTo is the connection whose ACS receives the POST (default: the
	// transaction's connection).
	PostTo string `json:"postTo,omitempty"`
	// Path is "acs" (default) or "other": a request received elsewhere.
	Path string `json:"path,omitempty"`
	// Trust overrides the trusted keys of the posted connection.
	Trust []string `json:"trust,omitempty"`
	// AllowSHA1 sets Connection.InsecureAllowSHA1.
	AllowSHA1 bool `json:"allowSHA1,omitempty"`
	// At offsets the SP clock from the corpus instant (Go duration).
	At string `json:"at,omitempty"`
	// Encoding of the SAMLResponse value: std (default), wrapped76,
	// spaces, garbage, deflate, gzip, or asis (the file is the value).
	Encoding string `json:"encoding,omitempty"`
	// Cookie is tx (default), none, other or malformed.
	Cookie string `json:"cookie,omitempty"`
	// RelayState is tx (default), none, other or url.
	RelayState string `json:"relayState,omitempty"`
	// PreMarked records the assertion in the replay cache beforehand.
	PreMarked *corpusReplayKey `json:"preMarked,omitempty"`
	// MaxResponseSize sets Config.MaxResponseSize.
	MaxResponseSize int64 `json:"maxResponseSize,omitempty"`
	// MetadataExpired makes the posted connection's IdP metadata expire at
	// the corpus instant (Metadata §4.3.2, errata E94).
	MetadataExpired bool `json:"metadataExpired,omitempty"`
}

// corpusReplayKey names a replay-cache entry.
type corpusReplayKey struct {
	Issuer      string `json:"issuer"`
	AssertionID string `json:"assertionID"`
}

// corpusExpect is the declared outcome: accepted with an exact identity,
// rejected by the rule whose static detail is pinned (the runner compares
// the whole error string: sentinel text plus detail, plan review F1), or
// an IdP error status.
type corpusExpect struct {
	Outcome  string `json:"outcome"` // accepted | rejected | status
	Sentinel string `json:"sentinel,omitempty"`
	// Detail is the static detail of the refusing rule ("" for a sentinel
	// without detail); PreparsedDetail overrides it when the application
	// parsed the form first.
	Detail          string           `json:"detail,omitempty"`
	PreparsedDetail string           `json:"preparsedDetail,omitempty"`
	Consumed        bool             `json:"consumed,omitempty"`
	Identity        *samlsp.Identity `json:"identity,omitempty"`
	Status          *corpusStatus    `json:"status,omitempty"`
}

// corpusStatus is the expected *StatusError: its sanitized fields and the
// short names its Error() prints.
type corpusStatus struct {
	Code    string `json:"code"`
	SubCode string `json:"subCode,omitempty"`
	Message string `json:"message,omitempty"`
	Printed string `json:"printed"`
}

// message is the exact error string of a rejection.
func (e corpusExpect) message(preparsed bool) string {
	if e.Outcome == outcomeStatus {
		return samlsp.ErrResponseStatus.Error() + " (" + e.Status.Printed + ")"
	}

	detail := e.Detail
	if preparsed && e.PreparsedDetail != "" {
		detail = e.PreparsedDetail
	}

	return rejectionMessage(e.Sentinel, detail)
}

// connectionSentinels are rejections met when the connection changed
// between the two legs of a login: no response alone produces them.
var connectionSentinels = map[string]error{
	"ErrUnknownConnection": samlsp.ErrUnknownConnection,
	"ErrInvalidConnection": samlsp.ErrInvalidConnection,
	"ErrMetadataExpired":   samlsp.ErrMetadataExpired,
}

// rejectionMessage is the exact error string of a rejection.
func rejectionMessage(sentinel, detail string) string {
	err, ok := corpusSentinels[sentinel]
	if !ok {
		err = connectionSentinels[sentinel]
	}

	msg := err.Error()
	if detail != "" {
		msg += " (" + detail + ")"
	}

	return msg
}

// Outcomes.
const (
	outcomeAccepted = "accepted"
	outcomeRejected = "rejected"
	outcomeStatus   = "status"
)

// attackerMarkers are carried by every forged value of the corpus: no
// accepted identity may contain one (plan review F2).
var attackerMarkers = []string{"attacker.example", "_evil", "mallory"}

// corpusSentinels maps the exported rejection sentinels by name.
var corpusSentinels = map[string]error{
	"ErrRejected":                      samlsp.ErrRejected,
	"ErrTransactionNotFound":           samlsp.ErrTransactionNotFound,
	"ErrTransactionConsumed":           samlsp.ErrTransactionConsumed,
	"ErrBrowserBindingMismatch":        samlsp.ErrBrowserBindingMismatch,
	"ErrAssertionReplayed":             samlsp.ErrAssertionReplayed,
	"ErrMalformedRequest":              samlsp.ErrMalformedRequest,
	"ErrResponseTooLarge":              samlsp.ErrResponseTooLarge,
	"ErrUnsolicitedResponse":           samlsp.ErrUnsolicitedResponse,
	"ErrMissingBrowserBinding":         samlsp.ErrMissingBrowserBinding,
	"ErrTransactionExpired":            samlsp.ErrTransactionExpired,
	"ErrTransactionMismatch":           samlsp.ErrTransactionMismatch,
	"ErrMalformedResponse":             samlsp.ErrMalformedResponse,
	"ErrEncryptedAssertionUnsupported": samlsp.ErrEncryptedAssertionUnsupported,
	"ErrUnsupportedAlgorithm":          samlsp.ErrUnsupportedAlgorithm,
	"ErrInvalidSignature":              samlsp.ErrInvalidSignature,
	"ErrResponseStatus":                samlsp.ErrResponseStatus,
	"ErrIssuerMismatch":                samlsp.ErrIssuerMismatch,
	"ErrDestinationMismatch":           samlsp.ErrDestinationMismatch,
	"ErrRecipientMismatch":             samlsp.ErrRecipientMismatch,
	"ErrAudienceMismatch":              samlsp.ErrAudienceMismatch,
	"ErrInResponseToMismatch":          samlsp.ErrInResponseToMismatch,
	"ErrAssertionExpired":              samlsp.ErrAssertionExpired,
	"ErrAssertionNotYetValid":          samlsp.ErrAssertionNotYetValid,
	"ErrInvalidAssertion":              samlsp.ErrInvalidAssertion,
	"ErrNameIDFormatMismatch":          samlsp.ErrNameIDFormatMismatch,
	"ErrAuthnContextMismatch":          samlsp.ErrAuthnContextMismatch,
	"ErrStaleAuthentication":           samlsp.ErrStaleAuthentication,
}

// corpusCategories are the categories of the corpus and the acceptance
// criterion (issue #88) each one serves.
var corpusCategories = map[string]string{
	"baseline":     "AC1/AC3: accepted shapes, including inert attacks",
	"correlation":  "AC2: issuer, audience, destination, recipient, InResponseTo, cross-tenant",
	"time":         "AC2: expired and not-yet-valid",
	"status":       "AC2: unsuccessful status",
	"shape":        "AC2: missing or repeated required fields",
	"keys":         "AC2: untrusted keys",
	"xsw":          "AC3: signature wrapping",
	"ids":          "AC3: duplicate XML IDs",
	"substitution": "AC3: unsigned assertion substitution",
	"algorithms":   "AC3: unsupported algorithms",
	"signature":    "AC3: XML-DSig profile (signature structure)",
	"differential": "AC3: parser differentials",
	"xml":          "AC3: malformed XML",
	"encryption":   "AC3: encrypted content refused",
	"limits":       "AC3: size and decompression limits",
	"replay":       "AC4: replay, binding and unsolicited responses",
}

// loadCorpus reads and checks the manifest.
func loadCorpus(t testing.TB) *corpusManifest {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(corpusDir, "manifest.json"))
	require.NoError(t, err, "regenerate with: go test -run '^TestCorpusGenerate$' -count=1 . -args -corpus.update")

	var m corpusManifest

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&m))
	require.Equal(t, 1, m.Version)

	return &m
}

// readCorpusFile returns the XML (or raw value) of an entry, checking its
// pinned SHA-256: a mismatch means the bytes were altered (editor, EOL
// conversion) and every signature would fail for the wrong reason.
func readCorpusFile(t testing.TB, f corpusEntry) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(corpusDir, filepath.FromSlash(f.File)))
	require.NoError(t, err)

	if strings.HasSuffix(f.File, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		require.NoError(t, err)

		data, err = io.ReadAll(zr)
		require.NoError(t, err)
	}

	sum := sha256.Sum256(data)
	require.Equal(t, f.SHA256, hex.EncodeToString(sum[:]), "%s: the pinned bytes changed", f.File)

	return data
}

// corpusCertificates parses the manifest keys.
func corpusCertificates(t testing.TB, m *corpusManifest) map[string]*x509.Certificate {
	t.Helper()

	out := make(map[string]*x509.Certificate, len(m.Keys))

	for name, b64 := range m.Keys {
		der, err := base64.StdEncoding.DecodeString(b64)
		require.NoError(t, err)

		c, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		out[name] = c
	}

	return out
}

// countingStore counts the side effects of CompleteLogin on its store.
type countingStore struct {
	*memory.Store

	mu       sync.Mutex
	consumes int
	marks    int
}

func (s *countingStore) ConsumeTransaction(ctx context.Context, id, bindingHash string) error {
	s.mu.Lock()
	s.consumes++
	s.mu.Unlock()

	return s.Store.ConsumeTransaction(ctx, id, bindingHash)
}

func (s *countingStore) MarkAssertionUsed(ctx context.Context, key string, expiresAt time.Time) error {
	s.mu.Lock()
	s.marks++
	s.mu.Unlock()

	return s.Store.MarkAssertionUsed(ctx, key, expiresAt)
}

// entryOutcome is what one corpus run observed.
type entryOutcome struct {
	result   *samlsp.LoginResult
	err      error
	consumes int
	marks    int
	consumed bool // the transaction ended consumed
}

// Fixed values of the "other" knobs.
const (
	otherHandle  = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	attackerURL  = "https://attacker.example/landing"
	otherACSPath = "/elsewhere"
)

// runCorpusEntry replays one entry through CompleteLogin, the form either
// read from the body or pre-parsed by the application (plan review F3).
func runCorpusEntry(t testing.TB, m *corpusManifest, certs map[string]*x509.Certificate, f corpusEntry, data []byte,
	preparsed bool,
) entryOutcome {
	t.Helper()

	tx, ok := m.Transactions[f.Transaction]
	require.True(t, ok, "unknown transaction %q", f.Transaction)

	postTo := cmpOr(f.Knobs.PostTo, tx.Connection)
	conns := corpusResolver(t, m, certs, postTo, f.Knobs)

	store := &countingStore{Store: memory.New()}
	ctx := context.Background()
	require.NoError(t, store.SaveTransaction(ctx, &tx.Record))

	if pk := f.Knobs.PreMarked; pk != nil {
		require.NoError(t, store.Store.MarkAssertionUsed(ctx, replayKeyHex(pk.Issuer, pk.AssertionID), m.Instant.Add(time.Hour)))
	}

	now := m.Instant
	if f.Knobs.At != "" {
		d, err := time.ParseDuration(f.Knobs.At)
		require.NoError(t, err)

		now = now.Add(d)
	}

	sp, err := samlsp.New(samlsp.Config{
		Connections:     conns,
		Transactions:    store,
		ReplayCache:     store,
		Now:             func() time.Time { return now },
		MaxResponseSize: f.Knobs.MaxResponseSize,
	})
	require.NoError(t, err)

	req := corpusRequest(t, m, f, tx, postTo, data)
	if preparsed {
		require.NoError(t, req.ParseForm())
	}

	res, cerr := sp.CompleteLogin(ctx, req, postTo)

	_, lerr := store.LookupTransaction(ctx, tx.Record.ID)

	return entryOutcome{
		result: res, err: cerr, consumes: store.consumes, marks: store.marks,
		consumed: errors.Is(lerr, samlsp.ErrTransactionConsumed),
	}
}

// corpusResolver resolves the manifest's connections, with the knobs
// applied to the posted one.
func corpusResolver(t testing.TB, m *corpusManifest, certs map[string]*x509.Certificate, postTo string,
	k corpusKnobs,
) samlsp.ConnectionResolver {
	t.Helper()

	conns := make(map[string]*samlsp.Connection, len(m.Connections))

	for id, c := range m.Connections {
		trust := c.Trust
		if id == postTo && len(k.Trust) > 0 {
			trust = k.Trust
		}

		conn := &samlsp.Connection{
			ID: id, SPEntityID: c.SPEntityID, ACSURL: c.ACSURL, NameIDFormat: c.NameIDFormat,
			InsecureAllowSHA1: id == postTo && k.AllowSHA1,
			IdentityProvider:  samlsp.IdentityProvider{EntityID: c.IdPEntityID, SSOURL: c.SSOURL},
		}

		if id == postTo && k.MetadataExpired {
			conn.IdentityProvider.ValidUntil = m.Instant
		}

		for _, name := range trust {
			cert, ok := certs[name]
			require.True(t, ok, "unknown key %q", name)

			conn.IdentityProvider.SigningCertificates = append(conn.IdentityProvider.SigningCertificates, cert)
		}

		require.NoError(t, conn.Validate(), "connection %s", id)

		conns[id] = conn
	}

	return samlsp.ConnectionResolverFunc(func(_ context.Context, id string) (*samlsp.Connection, error) {
		c, ok := conns[id]
		if !ok {
			return nil, samlsp.ErrUnknownConnection
		}

		cp := *c

		return &cp, nil
	})
}

// corpusRequest builds the HTTP-POST binding request of an entry.
func corpusRequest(t testing.TB, m *corpusManifest, f corpusEntry, tx corpusTx, postTo string, data []byte) *http.Request {
	t.Helper()

	acs, err := url.Parse(m.Connections[postTo].ACSURL)
	require.NoError(t, err)

	if f.Knobs.Path == "other" {
		acs.Path = otherACSPath
	}

	form := url.Values{"SAMLResponse": {encodeCorpusValue(t, f.Knobs.Encoding, data)}}

	switch f.Knobs.RelayState {
	case "", "tx":
		form.Set("RelayState", tx.RelayState)
	case "other":
		form.Set("RelayState", otherHandle)
	case "url":
		form.Set("RelayState", attackerURL)
	case "none":
	default:
		t.Fatalf("unknown RelayState knob %q", f.Knobs.RelayState)
	}

	req := httptest.NewRequest(http.MethodPost, acs.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	switch f.Knobs.Cookie {
	case "", "tx":
		req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: tx.Cookie})
	case "other":
		req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: otherHandle})
	case "malformed":
		req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: "not-a-handle"})
	case "none":
	default:
		t.Fatalf("unknown Cookie knob %q", f.Knobs.Cookie)
	}

	return req
}

// encodeCorpusValue encodes the SAMLResponse form value.
func encodeCorpusValue(t testing.TB, encoding string, data []byte) string {
	t.Helper()

	switch encoding {
	case "", "std":
		return base64.StdEncoding.EncodeToString(data)
	case "asis":
		return string(data)
	case "wrapped76":
		b64 := base64.StdEncoding.EncodeToString(data)

		var b strings.Builder

		for i := 0; i < len(b64); i += 76 {
			b.WriteString(b64[i:min(i+76, len(b64))])
			b.WriteString("\r\n")
		}

		return b.String()
	case "spaces":
		return strings.Replace(base64.StdEncoding.EncodeToString(data), "A", " A", 3)
	case "garbage":
		return "!!!" + base64.StdEncoding.EncodeToString(data)
	case "deflate":
		var buf bytes.Buffer

		fw, err := flate.NewWriter(&buf, flate.BestCompression)
		require.NoError(t, err)
		_, err = fw.Write(data)
		require.NoError(t, err)
		require.NoError(t, fw.Close())

		return base64.StdEncoding.EncodeToString(buf.Bytes())
	case "gzip":
		var buf bytes.Buffer

		zw := gzip.NewWriter(&buf)
		_, err := zw.Write(data)
		require.NoError(t, err)
		require.NoError(t, zw.Close())

		return base64.StdEncoding.EncodeToString(buf.Bytes())
	default:
		t.Fatalf("unknown encoding %q", encoding)

		return ""
	}
}

// checkOutcome compares an outcome with the declared expectation; it
// returns a description of every difference ("" when they match).
func checkOutcome(f corpusEntry, o entryOutcome, preparsed bool) string {
	var problems []string

	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if o.err != nil {
		for _, marker := range attackerMarkers {
			if strings.Contains(o.err.Error(), marker) {
				fail("the error string echoes attacker content %q: %q", marker, o.err.Error())
			}
		}
	}

	switch f.Expect.Outcome {
	case outcomeAccepted:
		checkAccepted(f, o, fail)
	case outcomeRejected:
		checkRejected(f, o, preparsed, fail)
	case outcomeStatus:
		checkStatus(f, o, fail)
	default:
		fail("unknown declared outcome %q", f.Expect.Outcome)
	}

	return strings.Join(problems, "; ")
}

func checkAccepted(f corpusEntry, o entryOutcome, fail func(string, ...any)) {
	if o.err != nil {
		fail("accepted declared, got %q", o.err.Error())

		return
	}

	if o.consumes != 1 || o.marks != 1 || !o.consumed {
		fail("accepted: want one consume and one replay mark, got %d/%d (consumed %v)", o.consumes, o.marks, o.consumed)
	}

	if leak := markerIn(o.result.Identity); leak != "" {
		fail("an accepted identity carries attacker data: %s", leak)
	}

	if f.Expect.Identity != nil && !identityEqual(*f.Expect.Identity, o.result.Identity) {
		got, _ := json.Marshal(o.result.Identity)
		want, _ := json.Marshal(f.Expect.Identity)
		fail("identity differs:\n got  %s\n want %s", got, want)
	}
}

func checkRejected(f corpusEntry, o entryOutcome, preparsed bool, fail func(string, ...any)) {
	if o.err == nil {
		got, _ := json.Marshal(o.result.Identity)
		fail("rejection declared, the response was ACCEPTED: %s", got)

		return
	}

	sentinel, ok := corpusSentinels[f.Expect.Sentinel]
	if !ok {
		sentinel, ok = connectionSentinels[f.Expect.Sentinel]
	}

	if !ok {
		fail("unknown sentinel %q", f.Expect.Sentinel)

		return
	}

	if !errors.Is(o.err, sentinel) || !errors.Is(o.err, samlsp.ErrRejected) || !errors.Is(o.err, security.ErrInvalidCredentials) {
		fail("want %s (and ErrRejected), got %q", f.Expect.Sentinel, o.err.Error())
	}

	if want := f.Expect.message(preparsed); o.err.Error() != want {
		fail("message: got %q, want %q", o.err.Error(), want)
	}

	switch {
	case f.Expect.Consumed && (o.consumes != 1 || !o.consumed):
		fail("a consumed transaction was declared: %d consumes (consumed %v)", o.consumes, o.consumed)
	case !f.Expect.Consumed && (o.consumes != 0 || o.marks != 0 || o.consumed):
		fail("a rejection must consume nothing: %d consumes, %d marks (consumed %v)", o.consumes, o.marks, o.consumed)
	}
}

func checkStatus(f corpusEntry, o entryOutcome, fail func(string, ...any)) {
	var se *samlsp.StatusError
	if !errors.As(o.err, &se) {
		fail("want a *StatusError, got %v", o.err)

		return
	}

	if want := f.Expect.Status; want == nil || se.Code != want.Code || se.SubCode != want.SubCode || se.Message != want.Message {
		fail("status: got %+v, want %+v", *se, want)
	}

	if want := f.Expect.message(false); o.err.Error() != want {
		fail("message: got %q, want %q", o.err.Error(), want)
	}

	if o.consumes != 0 || o.marks != 0 || o.consumed {
		fail("an error status must consume nothing")
	}
}

// markerIn reports an attacker marker inside an identity.
func markerIn(id samlsp.Identity) string {
	raw, err := json.Marshal(id)
	if err != nil {
		return err.Error()
	}

	for _, marker := range attackerMarkers {
		if bytes.Contains(raw, []byte(marker)) {
			return marker
		}
	}

	return ""
}

// identityEqual compares identities, times by instant.
func identityEqual(a, b samlsp.Identity) bool {
	if !a.AuthnInstant.Equal(b.AuthnInstant) || !a.SessionNotOnOrAfter.Equal(b.SessionNotOnOrAfter) {
		return false
	}

	a.AuthnInstant, b.AuthnInstant = time.Time{}, time.Time{}
	a.SessionNotOnOrAfter, b.SessionNotOnOrAfter = time.Time{}, time.Time{}

	return reflect.DeepEqual(a, b)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}

	return b
}

// TestCorpus replays every pinned entry, with the form read from the body
// and pre-parsed by the application: both must give the declared outcome.
func TestCorpus(t *testing.T) {
	t.Parallel()

	m := loadCorpus(t)
	certs := corpusCertificates(t, m)

	for _, f := range m.Fixtures {
		t.Run(f.ID, func(t *testing.T) {
			t.Parallel()

			data := readCorpusFile(t, f)

			for _, preparsed := range []bool{false, true} {
				if problem := checkOutcome(f, runCorpusEntry(t, m, certs, f, data, preparsed), preparsed); problem != "" {
					t.Errorf("%s (pre-parsed form: %v) [%s]: %s", f.ID, preparsed, f.Attack, problem)
				}
			}
		})
	}
}

// TestCorpusIntegrity checks the manifest against the directory: no file
// left out, unique IDs, known categories, sentinels and transactions, and
// every attack labelled and referenced.
func TestCorpusIntegrity(t *testing.T) {
	t.Parallel()

	m := loadCorpus(t)

	listed := map[string]bool{}
	ids := map[string]bool{}
	byCategory := map[string]int{}

	for _, f := range m.Fixtures {
		require.False(t, ids[f.ID], "duplicate id %s", f.ID)
		ids[f.ID] = true
		listed[f.File] = true
		byCategory[f.Category]++

		require.Contains(t, corpusCategories, f.Category, f.ID)
		require.True(t, strings.HasPrefix(f.ID, f.Category+"/"), "%s must live under its category", f.ID)
		require.NotEmpty(t, f.Attack, f.ID)
		require.Contains(t, m.Transactions, f.Transaction, f.ID)
		require.Contains(t, []string{outcomeAccepted, outcomeRejected, outcomeStatus}, f.Expect.Outcome, f.ID)

		if f.Category != "baseline" {
			require.NotEmpty(t, f.Refs, "%s: an attack names its references", f.ID)
		}

		if f.Expect.Outcome != outcomeAccepted {
			_, known := corpusSentinels[f.Expect.Sentinel]
			_, connection := connectionSentinels[f.Expect.Sentinel]
			require.True(t, known || connection, "%s: unknown sentinel %s", f.ID, f.Expect.Sentinel)
		}

		if f.Expect.Outcome == outcomeStatus {
			require.NotNil(t, f.Expect.Status, f.ID)
		}
	}

	for category := range corpusCategories {
		require.Positive(t, byCategory[category], "category %s has no entry", category)
	}

	err := filepath.WalkDir(corpusDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "manifest.json" {
			return err
		}

		rel, err := filepath.Rel(corpusDir, path)
		if err != nil {
			return err
		}

		if !listed[filepath.ToSlash(rel)] {
			return fmt.Errorf("%s is not in the manifest", rel)
		}

		return nil
	})
	require.NoError(t, err)
}

// TestCorpusCoversEveryRejection checks that every response-reachable
// rejection sentinel appears in the corpus.
func TestCorpusCoversEveryRejection(t *testing.T) {
	t.Parallel()

	m := loadCorpus(t)
	seen := map[string]bool{}

	for _, f := range m.Fixtures {
		seen[f.Expect.Sentinel] = true
	}

	// Sentinels a response alone cannot produce: they need another request
	// shape or a changed configuration and have their own unit tests.
	notFromResponses := []string{
		"ErrRejected", "ErrMalformedRequest", "ErrTransactionConsumed", "ErrTransactionMismatch",
	}

	for name := range corpusSentinels {
		if slices.Contains(notFromResponses, name) {
			continue
		}

		require.True(t, seen[name], "no corpus entry yields %s", name)
	}
}

// TestTestdataHoldsNoPrivateKey guards the pinned fixtures: only
// certificates and signed messages are committed, never key material
// (plan review F12).
func TestTestdataHoldsNoPrivateKey(t *testing.T) {
	t.Parallel()

	err := filepath.WalkDir("testdata", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		if strings.HasSuffix(path, ".gz") {
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return err
			}

			if data, err = io.ReadAll(zr); err != nil {
				return err
			}
		}

		for _, marker := range []string{"PRIVATE KEY", "private.key"} {
			if bytes.Contains(data, []byte(marker)) {
				return fmt.Errorf("%s contains %q", path, marker)
			}
		}

		return nil
	})
	require.NoError(t, err)
}
