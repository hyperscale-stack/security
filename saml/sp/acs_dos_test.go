// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

// Resource-exhaustion tests (plan review F1/F2). The measuring tests do not
// call t.Parallel: Go pauses parallel tests while sequential ones run, so the
// allocation figures (process-wide runtime.MemStats) only count the call
// under test.

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

// cost measures the time and the bytes allocated by fn.
func cost(fn func()) (time.Duration, uint64) {
	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	start := time.Now()
	fn()
	elapsed := time.Since(start)

	runtime.ReadMemStats(&after)

	return elapsed, after.TotalAlloc - before.TotalAlloc
}

// Budgets of a refused or worst-case response. The allocation budgets are
// deterministic and always enforced; the wall-clock ones are generous and
// skipped under the race detector, which slows the verification tenfold
// (code review F10). The measured figures are logged.
const (
	refusalBudgetBytes   = 32 << 20
	refusalBudgetTime    = 2 * time.Second
	worstCaseBudgetBytes = 96 << 20
	worstCaseBudgetTime  = 5 * time.Second
)

// requireFaster enforces a wall-clock budget, except under the race
// detector.
func requireFaster(t *testing.T, elapsed, budget time.Duration, what string) {
	t.Helper()

	if !raceEnabled {
		require.Less(t, elapsed, budget, what)
	}
}

// withMaxSize sets MaxResponseSize to the ceiling.
func withMaxSize(c *samlsp.Config, _ *samlsp.Connection) {
	c.MaxResponseSize = samlsp.MaxMaxResponseSize
}

// declarations renders n namespace declarations.
func declarations(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, ` xmlns:p%d="urn:x:%d"`, i, i)
	}

	return b.String()
}

func TestCompleteLogin_AmplificationInputsRefusedEarly(t *testing.T) {
	k := keys(t)

	e := newEnv(t, withMaxSize)
	lr := begin(t, e, samlsp.LoginOptions{})

	attackerSigned := func(values int) respOpts {
		return respOpts{assertionSig: sigOpts{signer: k.attacker}, beforeAssertion: func(a *etree.Element) {
			attr := path(a, "AttributeStatement", "Attribute")
			for i := 0; i < values; i++ {
				attr.CreateElement("saml:AttributeValue").SetText(fmt.Sprintf("g%d", i))
			}
		}}
	}

	withRootDecls := func(n, values int) string {
		o := attackerSigned(values)
		o.raw = func(s string) string {
			return strings.Replace(s, "<samlp:Response ", "<samlp:Response"+declarations(n)+" ", 1)
		}

		return respond(t, lr.requestID, o)
	}

	manyAttrs := func() string {
		var b strings.Builder
		for i := 0; i < 2000; i++ {
			fmt.Fprintf(&b, ` xmlns:p%d="urn:x:%d" p%d:a="v"`, i, i, i)
		}

		o := respOpts{raw: func(s string) string {
			return strings.Replace(s, "<samlp:Status>", "<samlp:Status"+b.String()+">", 1)
		}}

		return respond(t, lr.requestID, o)
	}

	emptyElements := func() string {
		return respond(t, lr.requestID, respOpts{raw: func(s string) string {
			return strings.Replace(s, "</samlp:Response>", strings.Repeat("<a/>", 16000)+"</samlp:Response>", 1)
		}})
	}

	cases := []struct {
		name string
		body string
	}{
		{"16 000 declarations on the Response, untrusted signer", withRootDecls(16000, 100)},
		{"30 000 declarations", withRootDecls(30000, 100)},
		{"16 000 declarations and 900 values", withRootDecls(16000, 900)},
		{"16 000 empty elements (round-trip validator)", emptyElements()},
		{"2 000 prefixed attributes on one element (round-trip validator)", manyAttrs()},
		{"900 attribute values (goxmldsig traversal budget)", respond(t, lr.requestID, attackerSigned(900))},
	}

	for _, tc := range cases {
		var err error

		elapsed, alloc := cost(func() { _, err = complete(e, lr, tc.body) })

		t.Logf("%-62s %8d KiB body: refused in %v, %d KiB allocated", tc.name,
			base64.StdEncoding.DecodedLen(len(tc.body))>>10, elapsed.Round(time.Microsecond), alloc>>10)
		requireRejected(t, e, lr, err, samlsp.ErrResponseTooLarge)
		require.Less(t, alloc, uint64(refusalBudgetBytes), tc.name)
		requireFaster(t, elapsed, refusalBudgetTime, tc.name)
	}
}

// worstCaseResponse builds the costliest response the limits admit: the
// Response and the Assertion filled up to 16 attributes with namespace
// declarations (25 prefixes in scope on every attribute value), nearly the
// element cap filled with attribute values carrying 16 attributes each of
// valueLen bytes, signed with signer.
func worstCaseResponse(t testing.TB, requestID string, sig sigOpts, valueLen int) string {
	t.Helper()

	o := respOpts{assertionSig: sig, beforeAssertion: func(a *etree.Element) {
		for i := 0; i < 12; i++ {
			a.CreateAttr(fmt.Sprintf("xmlns:q%d", i), fmt.Sprintf("urn:q:%d", i))
		}

		attr := path(a, "AttributeStatement", "Attribute")

		for i := 0; ; i++ {
			av := attr.CreateElement("saml:AttributeValue")
			for j := 0; j < 16; j++ {
				av.CreateAttr(fmt.Sprintf("a%d", j), strings.Repeat("v", valueLen))
			}

			av.SetText(fmt.Sprintf("g%d", i))

			if countElements(a) >= samlsp.MaxResponseElements-40 {
				break
			}
		}
	}, raw: func(s string) string {
		return strings.Replace(s, "<samlp:Response ", "<samlp:Response"+declarations(9)+" ", 1)
	}}

	return respond(t, requestID, o)
}

// countElements counts el and its descendants.
func countElements(el *etree.Element) int {
	n := 1
	for _, c := range el.ChildElements() {
		n += countElements(c)
	}

	return n
}

func TestCompleteLogin_WorstCaseWithinLimitsIsBounded(t *testing.T) {
	k := keys(t)

	sizes := []struct {
		name     string
		opts     []envOption
		valueLen int
	}{
		{"default 256 KiB body limit", nil, 16},
		{"1 MiB body ceiling", []envOption{withMaxSize}, 80},
	}

	for _, size := range sizes {
		e := newEnv(t, size.opts...)
		lr := begin(t, e, samlsp.LoginOptions{})
		body := worstCaseResponse(t, lr.requestID, sigOpts{signer: k.attacker}, size.valueLen)

		var err error

		elapsed, alloc := cost(func() { _, err = complete(e, lr, body) })

		t.Logf("worst case, %s (%d KiB, untrusted signer): %v, %d KiB allocated", size.name,
			base64.StdEncoding.DecodedLen(len(body))>>10, elapsed.Round(time.Microsecond), alloc>>10)
		requireRejected(t, e, lr, err, samlsp.ErrInvalidSignature)
		require.Less(t, alloc, uint64(worstCaseBudgetBytes))
		requireFaster(t, elapsed, worstCaseBudgetTime, size.name)

		// The same shape signed by the trusted key is a valid login.
		body = worstCaseResponse(t, lr.requestID, sigOpts{signer: k.idpA}, size.valueLen)
		elapsed, alloc = cost(func() { _, err = complete(e, lr, body) })

		t.Logf("worst case, %s (trusted signer, accepted): %v, %d KiB allocated", size.name,
			elapsed.Round(time.Microsecond), alloc>>10)
		require.NoError(t, err)
		require.Less(t, alloc, uint64(worstCaseBudgetBytes))
	}
}

func TestCompleteLogin_RolloverRetryIsBounded(t *testing.T) {
	k := keys(t)

	// Eight trusted certificates valid now, and a worst-case response
	// without KeyInfo signed by an untrusted key: each certificate tried
	// re-runs gosaml2, so at most three are (code review F4).
	eight := []keyPair{k.idpA, k.idpB}
	for i := 0; i < 6; i++ {
		eight = append(eight, newRSAPair(2048, fmt.Sprintf("rollover-%d", i), t0.Add(-time.Hour), t0.Add(24*time.Hour)))
	}

	measure := func(trusted ...keyPair) uint64 {
		e := newEnv(t, withMaxSize, trustKeys(trusted...))
		lr := begin(t, e, samlsp.LoginOptions{})
		body := worstCaseResponse(t, lr.requestID, sigOpts{signer: k.attacker, noKeyInfo: true}, 80)

		var err error

		_, alloc := cost(func() { _, err = complete(e, lr, body) })
		requireRejected(t, e, lr, err, samlsp.ErrInvalidSignature)

		return alloc
	}

	one, all := measure(k.idpA), measure(eight...)
	t.Logf("worst case without KeyInfo: 1 trusted certificate %d KiB, 8 trusted certificates %d KiB", one>>10, all>>10)
	require.Less(t, all, 4*one, "at most three certificates are tried")
}

// atCap builds a valid response of exactly MaxResponseElements elements.
func atCap(t testing.TB, requestID string, o respOpts) string {
	t.Helper()

	base := respondXML(t, requestID, o)
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(base))

	missing := samlsp.MaxResponseElements - countElements(doc.Root())
	o.beforeAssertion = func(a *etree.Element) {
		attr := path(a, "AttributeStatement", "Attribute")
		for i := 0; i < missing; i++ {
			attr.CreateElement("saml:AttributeValue").SetText("g")
		}
	}

	out := respondXML(t, requestID, o)
	final := etree.NewDocument()
	require.NoError(t, final.ReadFromString(out))
	require.Equal(t, samlsp.MaxResponseElements, countElements(final.Root()))

	return encodeString(out)
}

func TestCompleteLogin_ElementCapFitsTheVerifierBudget(t *testing.T) {
	t.Parallel()

	modes := map[string]respOpts{
		"assertion signed": {},
		"response signed":  {unsignedAssert: true, signResponse: true},
		"both signed":      {signResponse: true},
	}

	for name, o := range modes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			lr := begin(t, e, samlsp.LoginOptions{})

			res, err := complete(e, lr, atCap(t, lr.requestID, o))
			require.NoError(t, err, "a response at the element cap always fits goxmldsig's traversal budget")
			require.NotEmpty(t, res.Identity.AttributeValues("groups"))
		})
	}
}

// TestGosaml2TraversalBudgetIsPinned bisects the largest response gosaml2 +
// goxmldsig verify (bypassing this package's limits). The element cap is
// derived from it: if a dependency upgrade moves the limit, this test fails
// and the cap must be re-evaluated (plan review F2).
func TestGosaml2TraversalBudgetIsPinned(t *testing.T) {
	t.Parallel()

	k := keys(t)

	verify := func(values int) bool {
		xml := respondXML(t, "_req", respOpts{beforeAssertion: func(a *etree.Element) {
			attr := path(a, "AttributeStatement", "Attribute")
			for i := 0; i < values; i++ {
				attr.CreateElement("saml:AttributeValue").SetText("g")
			}
		}})

		sp := &saml2.SAMLServiceProvider{
			IdentityProviderIssuer:      idpEntity,
			AssertionConsumerServiceURL: acsURL,
			ServiceProviderIssuer:       spEntityID,
			AudienceURI:                 spEntityID,
			IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{k.idpA.cert}},
			Clock:                       dsig.NewFakeClockAt(t0),
			MaximumDecompressedBodySize: 1,
			MaximumXMLTokens:            1 << 20,
		}

		_, err := sp.ValidateEncodedResponse(encodeString(xml))

		return err == nil
	}

	lo, hi := 0, 2000
	require.True(t, verify(lo))

	for lo < hi {
		mid := (lo + hi + 1) / 2
		if verify(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(respondXML(t, "_req", respOpts{beforeAssertion: func(a *etree.Element) {
		attr := path(a, "AttributeStatement", "Attribute")
		for i := 0; i < lo; i++ {
			attr.CreateElement("saml:AttributeValue").SetText("g")
		}
	}})))

	limit := countElements(doc.Root())
	t.Logf("gosaml2/goxmldsig verify at most %d elements (assertion signed); MaxResponseElements = %d", limit, samlsp.MaxResponseElements)

	require.GreaterOrEqual(t, limit, samlsp.MaxResponseElements, "the cap must fit the verifier budget")
	require.LessOrEqual(t, limit, samlsp.MaxResponseElements+80, "the verifier budget moved: re-evaluate MaxResponseElements")
}

func BenchmarkCompleteLogin_Typical(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		e := newEnv(b) // fresh replay cache: the fixtures reuse one assertion ID
		lr := begin(b, e, samlsp.LoginOptions{})
		body := respond(b, lr.requestID, respOpts{})

		b.StartTimer()

		if _, err := complete(e, lr, body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompleteLogin_WorstCaseUntrusted(b *testing.B) {
	k := keys(b)
	e := newEnv(b, withMaxSize)
	lr := begin(b, e, samlsp.LoginOptions{})
	body := worstCaseResponse(b, lr.requestID, sigOpts{signer: k.attacker}, 80)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := complete(e, lr, body); err == nil {
			b.Fatal("expected a rejection")
		}
	}
}

func BenchmarkCompleteLogin_RefusedAmplification(b *testing.B) {
	e := newEnv(b, withMaxSize)
	lr := begin(b, e, samlsp.LoginOptions{})
	body := respond(b, lr.requestID, respOpts{raw: func(s string) string {
		return strings.Replace(s, "<samlp:Response ", "<samlp:Response"+declarations(30000)+" ", 1)
	}})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := complete(e, lr, body); err == nil {
			b.Fatal("expected a rejection")
		}
	}
}
