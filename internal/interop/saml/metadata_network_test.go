// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

// IdP metadata retrieval behind a Service Provider (issue #88, plan §5.5 as
// trimmed by its review, F10). #87's unit tests cover the fetcher and the
// MetadataSource alone; these wire a source into a connection, the way the
// guide documents it, and log in through crewjam over TLS with the source's
// clock under test control:
//   - a key rollover is followed from the first login after the refresh
//     completes, and only then;
//   - a due refresh runs in the background: a hung metadata endpoint never
//     delays a login while a usable document is cached;
//   - the number of fetches depends on time only: neither logins nor
//     forged responses with unknown keys make the SP fetch;
//   - a document of another entity is refused and the last good one kept;
//   - every refusal of the outbound policy fails the login closed.
//
// A refresh completes in the background, so the tests never sleep: they
// wait for the document the source serves, or for the source to record a
// failed attempt (see failHeld).

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/outbound"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/require"
)

// metadataServer publishes the metadata document the test chooses, over
// TLS, and counts the requests. While held, a request waits for the test
// to answer it.
type metadataServer struct {
	srv    *httptest.Server
	doc    atomic.Pointer[[]byte]
	status atomic.Int32 // answered instead of the document when not 0
	held   atomic.Pointer[chan int]
	hits   atomic.Int64
}

func newMetadataServer(t *testing.T, doc []byte) *metadataServer {
	t.Helper()

	m := &metadataServer{}
	m.publish(doc)

	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits.Add(1)

		code := int(m.status.Load())

		if held := m.held.Load(); held != nil {
			select {
			case code = <-*held:
			case <-r.Context().Done():
				return
			}
		}

		if code != 0 {
			http.Error(w, "upstream trouble", code)

			return
		}

		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(*m.doc.Load())
	}))
	t.Cleanup(m.srv.Close)

	return m
}

// publish replaces the document.
func (m *metadataServer) publish(doc []byte) { m.doc.Store(&doc) }

// hold makes the next request wait until answer.
func (m *metadataServer) hold() {
	ch := make(chan int)
	m.held.Store(&ch)
}

// answer releases the held request with status (0: the document) and
// stops holding.
func (m *metadataServer) answer(t *testing.T, status int) {
	t.Helper()

	held := m.held.Swap(nil)
	require.NotNil(t, held, "no request held")

	select {
	case *held <- status:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "no metadata request is waiting")
	}
}

// testClock is a settable clock counting its reads.
type testClock struct {
	now   atomic.Int64
	reads atomic.Int64
}

func newTestClock() *testClock {
	c := &testClock{}
	c.now.Store(time.Now().UnixNano())

	return c
}

func (c *testClock) Now() time.Time {
	c.reads.Add(1)

	return time.Unix(0, c.now.Load())
}

func (c *testClock) advance(d time.Duration) { c.now.Add(int64(d)) }

// Refresh policy of the sources under test. The outbound timeout outlasts
// any held request of a test.
const (
	sourceRefresh = time.Hour
	sourceRetry   = time.Minute
	sourceStale   = 6 * time.Hour
	sourceTimeout = time.Minute
)

// newSource returns a MetadataSource of m, pinned to entityID, trusting the
// httptest certificate and exempting loopback, on clock.
func newSource(t *testing.T, m *metadataServer, entityID string, clock *testClock) *samlsp.MetadataSource {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(m.srv.Certificate())

	src, err := samlsp.NewMetadataSource(samlsp.MetadataSourceConfig{
		URL: m.srv.URL + "/metadata", EntityID: entityID,
		Outbound:   outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool, Timeout: sourceTimeout},
		MaxRefresh: sourceRefresh, RetryInterval: sourceRetry, MaxStale: sourceStale, Now: clock.Now,
	})
	require.NoError(t, err)

	return src
}

// sourcedFederation is one SP connection, acme, whose IdP comes from a
// metadata source.
type sourcedFederation struct {
	idp   *identityProvider
	md    *metadataServer
	clock *testClock
	src   *samlsp.MetadataSource
	sp    *serviceProvider
	acme  samlsp.Connection
}

func newSourcedFederation(t *testing.T, idpKey testKey) *sourcedFederation {
	t.Helper()

	f := &sourcedFederation{idp: newIdentityProvider(t, idpKey, rsaSHA256), clock: newTestClock()}
	f.md = newMetadataServer(t, f.idp.metadata(t))
	f.src = newSource(t, f.md, f.idp.entityID(), f.clock)
	f.sp = newServiceProvider(t, spOptions{})
	f.acme = f.sp.addSourcedConnection("acme", f.src)
	f.idp.registerSP(t, f.sp.metadata(t, "acme"))

	return f
}

// login runs a whole SP-initiated login and returns the ACS outcome.
func (f *sourcedFederation) login(t *testing.T) error {
	t.Helper()

	b := newBrowser(t, f.sp.srv)
	_, form := b.mustSignIn(t, f.sp, "acme")
	b.mustPost(t, form)

	return f.sp.last(t).err
}

// served waits until the source serves a document satisfying ok: a due
// refresh completes in the background, and its first caller only starts
// it.
func (f *sourcedFederation) served(t *testing.T, ok func(*samlsp.IdentityProvider) bool) {
	t.Helper()

	require.Eventually(t, func() bool {
		idp, err := f.src.IdentityProvider(context.Background())

		return err == nil && ok(idp)
	}, 10*time.Second, 5*time.Millisecond)
}

// failHeld answers the held refresh with status (0: the document, which
// the source must refuse) and waits until the source has recorded the
// failed attempt. The test makes no call meanwhile, so the next read of the
// source's clock is the fetch recording its outcome: it reads it once, then,
// under the source's lock, which any later call takes after it.
func (f *sourcedFederation) failHeld(t *testing.T, status int) {
	t.Helper()

	reads := f.clock.reads.Load()
	f.md.answer(t, status)

	require.Eventually(t, func() bool { return f.clock.reads.Load() > reads }, 10*time.Second, time.Millisecond)
}

// waitHits waits until the metadata server has received n requests; a
// background refresh reaches it at its own pace.
func (f *sourcedFederation) waitHits(t *testing.T, n int64) {
	t.Helper()

	require.Eventually(t, func() bool { return f.md.hits.Load() == n }, 10*time.Second, 5*time.Millisecond)
}

// trusts reports whether a document trusts exactly certs.
func trusts(certs ...*x509.Certificate) func(*samlsp.IdentityProvider) bool {
	return func(idp *samlsp.IdentityProvider) bool {
		return len(idp.SigningCertificates) == len(certs) && !slices.ContainsFunc(certs, func(c *x509.Certificate) bool {
			return !slices.ContainsFunc(idp.SigningCertificates, c.Equal)
		})
	}
}

// TestMetadataSourceFollowsKeyRollover rolls the IdP key through the
// published metadata: an announced key is trusted from the first login
// after the refresh completes, and a retired key is refused from the first
// login after the next refresh completes.
func TestMetadataSourceFollowsKeyRollover(t *testing.T) {
	t.Parallel()

	current, next := newKey(t, "idp-current"), newKey(t, "idp-next")
	f := newSourcedFederation(t, current)
	require.NoError(t, f.login(t))

	fetches := f.md.hits.Load()

	// Announce: the IdP publishes both keys; the SP's copy is still fresh.
	f.md.publish(f.idp.metadata(t, next.cert))
	f.idp.useKey(next)
	require.ErrorIs(t, f.login(t), samlsp.ErrInvalidSignature, "announced, not fetched yet")
	f.idp.useKey(current)
	require.NoError(t, f.login(t))
	require.Equal(t, fetches, f.md.hits.Load(), "no refresh due")

	// The refresh is due: the cached document serves while it runs, then
	// both keys sign.
	f.clock.advance(sourceRefresh + time.Second)
	require.NoError(t, f.login(t))
	f.served(t, trusts(current.cert, next.cert))
	require.Equal(t, fetches+1, f.md.hits.Load())

	f.idp.useKey(next)
	require.NoError(t, f.login(t))

	// Retire: only the next key is published; the retired one is trusted
	// until the refresh completes, refused after it.
	f.md.publish(f.idp.metadata(t))
	f.idp.useKey(current)
	require.NoError(t, f.login(t), "retired, not fetched yet")

	f.clock.advance(sourceRefresh + time.Second)
	f.served(t, trusts(next.cert))
	require.ErrorIs(t, f.login(t), samlsp.ErrInvalidSignature)
	require.Equal(t, fetches+2, f.md.hits.Load())

	f.idp.useKey(next)
	require.NoError(t, f.login(t))
}

// TestMetadataFetchesDependOnTimeOnly checks that no traffic makes the SP
// fetch: neither logins, nor forged responses signed by unknown keys (a
// refresh on an unknown key would let an attacker drive the fetches), nor
// requests while a refresh hangs or fails. A hung refresh never delays a
// login, failed attempts are spaced by RetryInterval, and without a
// successful refresh for MaxStale the logins fail closed.
func TestMetadataFetchesDependOnTimeOnly(t *testing.T) {
	t.Parallel()

	f := newSourcedFederation(t, newKey(t, "idp"))
	require.NoError(t, f.login(t))
	require.EqualValues(t, 1, f.md.hits.Load())

	// Responses of a rogue IdP, signed by an unknown key, for acme's own
	// transaction.
	rogue := newIdentityProvider(t, newKey(t, "rogue"), rsaSHA256)
	rogue.registerSP(t, f.sp.metadata(t, "acme"))

	mallory := newBrowser(t, f.sp.srv)
	redirect := mallory.redirectOf(t, f.sp.srv.URL+"/login/acme")
	forged := answerForgedRequest(t, mallory, rogue, f.acme, authnRequest(t, redirect).ID, redirect.Query().Get("RelayState"))

	for range 100 {
		require.Equal(t, http.StatusForbidden, mallory.mustPost(t, forged))
		require.ErrorIs(t, f.sp.last(t).err, samlsp.ErrInvalidSignature)
	}

	require.EqualValues(t, 1, f.md.hits.Load(), "unknown keys trigger no fetch")

	// The refresh is due and the endpoint hangs: the logins are served
	// from the cache without waiting, and they start one attempt between
	// them.
	f.md.hold()
	f.clock.advance(sourceRefresh + time.Second)

	for range 20 {
		start := time.Now()
		require.NoError(t, f.login(t), "served from the cache")
		require.Less(t, time.Since(start), 5*time.Second, "a login never waits for a refresh")
	}

	f.waitHits(t, 2)

	// The attempt fails: the cached document keeps serving, and the next
	// attempt comes RetryInterval later, not before.
	f.failHeld(t, http.StatusServiceUnavailable)
	f.md.status.Store(http.StatusServiceUnavailable)
	f.clock.advance(sourceRetry - time.Second)

	for range 20 {
		require.NoError(t, f.login(t), "stale on error")
	}

	require.EqualValues(t, 2, f.md.hits.Load(), "no attempt within RetryInterval")

	f.md.hold()
	f.clock.advance(time.Second)
	require.NoError(t, f.login(t))
	f.waitHits(t, 3)
	f.failHeld(t, http.StatusServiceUnavailable)

	// Past MaxStale without a successful refresh, nothing usable is left:
	// BeginLogin waits for the attempt, which fails, and fails closed.
	f.clock.advance(sourceStale)

	_, err := f.sp.pick().BeginLogin(context.Background(), httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil), "acme", samlsp.LoginOptions{})
	require.ErrorIs(t, err, samlsp.ErrMetadataExpired)
	require.EqualValues(t, 4, f.md.hits.Load())

	// Once the upstream recovers, the next attempt restores the logins.
	f.md.status.Store(0)
	f.clock.advance(sourceRetry + time.Second)
	require.NoError(t, f.login(t))
	require.EqualValues(t, 5, f.md.hits.Load())
}

// TestMetadataSourceKeepsThePinnedEntity serves another IdP's metadata at
// the trusted URL: the refresh refuses it and the connection keeps the
// last good document, so the other IdP still cannot sign anyone in.
func TestMetadataSourceKeepsThePinnedEntity(t *testing.T) {
	t.Parallel()

	idpKey, nextKey := newKey(t, "idp"), newKey(t, "idp-next")
	f := newSourcedFederation(t, idpKey)
	require.NoError(t, f.login(t))

	other := newIdentityProvider(t, newKey(t, "other"), rsaSHA256)
	other.registerSP(t, f.sp.metadata(t, "acme"))
	f.md.publish(other.metadata(t))
	f.md.hold()
	f.clock.advance(sourceRefresh + time.Second)

	require.NoError(t, f.login(t), "the cached document serves meanwhile")
	f.waitHits(t, 2)
	f.failHeld(t, 0)

	// The refresh was refused: the pinned IdP's document still serves, so
	// the SSO URL and the keys are its own.
	idp, err := f.src.IdentityProvider(context.Background())
	require.NoError(t, err)
	require.Equal(t, f.idp.entityID(), idp.EntityID)
	require.True(t, trusts(idpKey.cert)(idp))

	b := newBrowser(t, f.sp.srv)
	redirect := b.redirectOf(t, f.sp.srv.URL+"/login/acme")
	require.True(t, strings.HasPrefix(redirect.String(), f.idp.srv.URL+"/sso?"), "the SSO URL is the pinned IdP's")

	form := answerForgedRequest(t, b, other, f.acme, authnRequest(t, redirect).ID, redirect.Query().Get("RelayState"))
	require.Equal(t, http.StatusForbidden, b.mustPost(t, form))
	require.ErrorIs(t, f.sp.last(t).err, samlsp.ErrInvalidSignature)

	// A refused document counts as a failure: the next attempt comes
	// RetryInterval later and a valid document of the pinned entity is
	// taken. Had the other entity's document been taken, no refresh would
	// be due before an hour.
	f.md.publish(f.idp.metadata(t, nextKey.cert))
	f.clock.advance(sourceRetry + time.Second)
	f.served(t, trusts(idpKey.cert, nextKey.cert))
	require.EqualValues(t, 3, f.md.hits.Load())
}

// TestMetadataPolicyRefusalsFailClosed wires each outbound refusal into a
// connection: BeginLogin fails with ErrMetadataUnavailable and the
// outbound sentinel, sets no cookie, and never echoes the response body.
func TestMetadataPolicyRefusalsFailClosed(t *testing.T) {
	t.Parallel()

	const marker = "body-marker-never-echoed"

	idp := newIdentityProvider(t, newKey(t, "idp"), rsaSHA256)
	doc := idp.metadata(t)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			w.Header().Set("Location", "/metadata")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte(marker))

			return
		}

		_, _ = w.Write(append(doc, []byte("<!-- "+marker+" -->")...))
	}))
	t.Cleanup(upstream.Close)

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())

	trusting := outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool}
	allowList := trusting
	allowList.CheckURL = func(context.Context, *url.URL) error { return errors.New("host not on the allow-list") }

	for _, c := range []struct {
		name    string
		path    string
		policy  outbound.Policy
		maxSize int64
		want    error
	}{
		{"URL refused by CheckURL", "/metadata", allowList, 0, outbound.ErrURLNotAllowed},
		{"loopback without an exemption", "/metadata", outbound.Policy{RootCAs: pool}, 0, outbound.ErrDestinationNotAllowed},
		{"redirect", "/moved", trusting, 0, outbound.ErrRedirectNotAllowed},
		{"document over MaxSize", "/metadata", trusting, 512, outbound.ErrResponseTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			src, err := samlsp.NewMetadataSource(samlsp.MetadataSourceConfig{
				URL: upstream.URL + c.path, EntityID: idp.entityID(), Outbound: c.policy, MaxSize: c.maxSize,
			})
			require.NoError(t, err)

			sp := newServiceProvider(t, spOptions{})
			sp.addSourcedConnection("acme", src)

			rec := httptest.NewRecorder()
			_, err = sp.pick().BeginLogin(context.Background(), rec, httptest.NewRequest(http.MethodGet, "/", nil),
				"acme", samlsp.LoginOptions{})
			require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
			require.ErrorIs(t, err, c.want)
			require.NotContains(t, err.Error(), marker)
			require.Empty(t, rec.Header().Values("Set-Cookie"), "nothing started")
		})
	}
}
