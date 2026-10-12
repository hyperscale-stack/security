// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testClock is a settable clock, safe for concurrent use.
type testClock struct{ ns atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.ns.Store(time.Unix(1_800_000_000, 0).UnixNano())

	return c
}

func (c *testClock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// jwksEndpoint is an https JWK Set server on the loopback interface whose
// document and status can change, and whose requests can be held.
type jwksEndpoint struct {
	srv  *httptest.Server
	hits atomic.Int32

	mu     sync.Mutex
	doc    []byte
	status int
	gate   chan struct{}
}

func newJWKSEndpoint(t *testing.T, doc []byte) *jwksEndpoint {
	t.Helper()

	e := &jwksEndpoint{doc: doc, status: http.StatusOK}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.srv.Close)
	t.Cleanup(e.releaseAll) // runs first: no handler left blocked at Close

	return e
}

func (e *jwksEndpoint) serve(w http.ResponseWriter, r *http.Request) {
	e.hits.Add(1)

	e.mu.Lock()
	doc, status, gate := e.doc, e.status, e.gate
	e.mu.Unlock()

	if gate != nil {
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
	}

	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(status)
	_, _ = w.Write(doc)
}

// set changes the document and status served from now on.
func (e *jwksEndpoint) set(doc []byte, status int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.doc, e.status = doc, status
}

// hold makes the next requests wait until release is called.
func (e *jwksEndpoint) hold() (release func()) {
	gate := make(chan struct{})

	e.mu.Lock()
	e.gate = gate
	e.mu.Unlock()

	var once sync.Once

	return func() {
		once.Do(func() {
			e.mu.Lock()
			if e.gate == gate {
				e.gate = nil
			}
			e.mu.Unlock()
			close(gate)
		})
	}
}

func (e *jwksEndpoint) releaseAll() {
	e.mu.Lock()
	gate := e.gate
	e.gate = nil
	e.mu.Unlock()

	if gate != nil {
		select {
		case <-gate:
		default:
			close(gate)
		}
	}
}

// policy is the outbound policy that reaches this test server: loopback
// exempted, its CA trusted.
func (e *jwksEndpoint) policy() jwtsec.RemoteOption {
	pool := x509.NewCertPool()
	pool.AddCert(e.srv.Certificate())

	return jwtsec.WithOutboundPolicy(outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool})
}

// provider returns a remote provider of this endpoint on clock.
func (e *jwksEndpoint) provider(t *testing.T, clock *testClock, opts ...jwtsec.RemoteOption) jwtsec.JWKSProvider {
	t.Helper()

	p, err := jwtsec.NewRemoteJWKS(e.srv.URL+"/jwks", append([]jwtsec.RemoteOption{e.policy()}, opts...)...)
	require.NoError(t, err)

	jwtsec.SetRemoteJWKSClock(p, clock.Now)
	t.Cleanup(func() { waitIdle(t, p) })

	return p
}

// waitIdle waits for p's fetch in flight, if any, to complete.
func waitIdle(t *testing.T, p jwtsec.JWKSProvider) {
	t.Helper()

	require.Eventually(t, func() bool { return jwtsec.RemoteJWKSIdle(p) }, 10*time.Second, time.Millisecond)
}

// hasKey reports whether p's current set holds kid.
func hasKey(t *testing.T, p jwtsec.JWKSProvider, kid string) bool {
	t.Helper()

	set, err := p.KeySet(context.Background())
	require.NoError(t, err)

	_, ok := set.ByKeyID(kid)

	return ok
}

// tokenFor signs a valid token with priv under kid.
func tokenFor(t *testing.T, priv jwtsec.PrivateKey, kid string) string {
	t.Helper()

	return forge(t, priv.Algorithm, priv.Key, header(priv.Algorithm, kid), claimsPayload())
}

// ecKey returns a P-256 key pair under kid.
func ecKey(t *testing.T, kid string) (jwtsec.PrivateKey, jwtsec.PublicKey) {
	t.Helper()

	priv, pub := genECDSA(t)
	priv.KeyID, pub.KeyID = kid, kid

	return priv, pub
}

// notCredentialFailure asserts that err is not classified as a credential
// failure by the transports: an outage must never become a 401.
func notCredentialFailure(t *testing.T, err error) {
	t.Helper()

	for _, s := range []error{
		security.ErrInvalidCredentials, security.ErrTokenExpired, security.ErrTokenNotFound,
		security.ErrClientSecretMismatch, security.ErrUnsupportedCredential,
	} {
		require.NotErrorIs(t, err, s)
	}
}

// TestRemoteJWKSDefaultPolicyRefusesInternalDestinations pins the project
// rule — every server-side fetch of a configured URL goes through
// outbound — and decision 8 (audit JWT-04, probe R4): by default a
// loopback (any internal) or plain-http JWK Set is never requested.
func TestRemoteJWKSDefaultPolicyRefusesInternalDestinations(t *testing.T) {
	t.Parallel()

	_, pub := ecKey(t, "k")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pub)))

	p, err := jwtsec.NewRemoteJWKS(e.srv.URL + "/jwks")
	require.NoError(t, err)

	_, err = p.KeySet(context.Background())
	require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable)
	require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
	notCredentialFailure(t, err)

	// http needs an explicit policy; loopback stays refused without an
	// exemption.
	plain := httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(plain.Close)

	_, err = jwtsec.NewRemoteJWKS(plain.URL + "/jwks")
	require.ErrorIs(t, err, outbound.ErrURLNotAllowed, "http refused at construction")

	p, err = jwtsec.NewRemoteJWKS(plain.URL+"/jwks", jwtsec.WithOutboundPolicy(outbound.Policy{AllowHTTP: true}))
	require.NoError(t, err)

	_, err = p.KeySet(context.Background())
	require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)

	assert.Equal(t, int32(0), e.hits.Load(), "no request ever reached the internal server")
}

// TestNewRemoteJWKSChecksItsURL pins the URL check at construction: an
// absolute https URL with a host and no userinfo — http only with an
// explicit AllowHTTP policy or the WithHTTPClient opt-out. The errors never
// quote the URL.
func TestNewRemoteJWKSChecksItsURL(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]string{
		"userinfo":          "https://user:S3CR3T@idp.example/jwks",
		"relative":          "/jwks",
		"no host":           "https:///jwks",
		"other scheme":      "ftp://idp.example/jwks",
		"http":              "http://idp.example/jwks?api_key=S3CR3T",
		"unparsable":        "https://idp.example/%zz?api_key=S3CR3T",
		"empty":             "",
		"scheme-less":       "idp.example/jwks",
		"userinfo, no pass": "https://S3CR3T@idp.example/jwks",
	} {
		_, err := jwtsec.NewRemoteJWKS(raw)
		require.ErrorIs(t, err, outbound.ErrURLNotAllowed, name)
		assert.NotContains(t, err.Error(), "S3CR3T", name)
	}

	_, err := jwtsec.NewRemoteJWKS("http://idp.example/jwks", jwtsec.WithOutboundPolicy(outbound.Policy{AllowHTTP: true}))
	require.NoError(t, err)

	_, err = jwtsec.NewRemoteJWKS("http://idp.example/jwks", jwtsec.WithHTTPClient(&http.Client{}))
	require.NoError(t, err, "the opt-out client accepts http")

	_, err = jwtsec.NewRemoteJWKS("https://idp.example/jwks?x=1#frag")
	require.NoError(t, err)
}

func TestNewRemoteJWKSRefusesInvalidOptions(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { jwtsec.WithHTTPClient(nil) })
	assert.Panics(t, func() { jwtsec.WithCacheTTL(0) })
	assert.Panics(t, func() { jwtsec.WithCacheTTL(-time.Second) })
	assert.Panics(t, func() { jwtsec.WithCacheTTL(jwtsec.MaxKeySetStaleness + time.Nanosecond) })
	assert.NotPanics(t, func() { jwtsec.WithCacheTTL(jwtsec.MaxKeySetStaleness) })
	assert.Panics(t, func() {
		_, _ = jwtsec.NewRemoteJWKS("https://idp.example/jwks",
			jwtsec.WithHTTPClient(&http.Client{}), jwtsec.WithOutboundPolicy(outbound.Policy{}))
	}, "the opt-out client and a policy are exclusive")

	_, err := jwtsec.NewRemoteJWKS("https://idp.example/jwks", jwtsec.WithOutboundPolicy(outbound.Policy{Timeout: -1}))
	require.ErrorIs(t, err, outbound.ErrInvalidPolicy)
}

// TestRemoteJWKSRefusesRedirects pins decision 8 and review F11 (audit
// JWT-04 downgrade probe): no redirect is followed by default, an
// https→http redirect never — and a response that came over http for an
// https URL is refused even through the opt-out client, so a network
// attacker cannot serve its own keys.
func TestRemoteJWKSRefusesRedirects(t *testing.T) {
	t.Parallel()

	attacker, attackerPub := ecKey(t, "evil")
	target := newJWKSEndpoint(t, jwksJSON(t, sigKey(attackerPub)))
	plain := httptest.NewServer(http.HandlerFunc(target.serve))
	t.Cleanup(plain.Close)

	to := func(dest string) *httptest.Server {
		front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, dest, http.StatusFound)
		}))
		t.Cleanup(front.Close)

		return front
	}

	frontTLS := to(target.srv.URL + "/jwks")
	pool := x509.NewCertPool()
	pool.AddCert(frontTLS.Certificate())
	pool.AddCert(target.srv.Certificate())

	p, err := jwtsec.NewRemoteJWKS(frontTLS.URL, jwtsec.WithOutboundPolicy(outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool}))
	require.NoError(t, err)

	_, err = p.KeySet(context.Background())
	require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed, "no redirect by default")

	frontPlain := to(plain.URL + "/jwks")
	pool.AddCert(frontPlain.Certificate())

	p, err = jwtsec.NewRemoteJWKS(frontPlain.URL, jwtsec.WithOutboundPolicy(outbound.Policy{
		AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool, MaxRedirects: 1,
	}))
	require.NoError(t, err)

	_, err = p.KeySet(context.Background())
	require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed, "https to http is always refused")
	assert.Equal(t, int32(0), target.hits.Load())

	// The opt-out client follows the downgrade; the keys are not trusted.
	p, err = jwtsec.NewRemoteJWKS(frontPlain.URL, jwtsec.WithHTTPClient(frontPlain.Client()))
	require.NoError(t, err)

	_, err = p.KeySet(context.Background())
	require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable)

	_, err = jwtsec.NewVerifier(p).Verify(context.Background(), tokenFor(t, attacker, "evil"), nil)
	require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable, "a key served over http verifies nothing")
}

// TestRemoteJWKSIgnoresEnvironmentProxy pins that the default client uses
// no proxy (the RP auditor's probe: HTTP(S)_PROXY was honoured). Not
// parallel: it sets the environment. Note: net/http reads the proxy
// environment once per process, so this test alone cannot prove a client
// ignores it — the "default client" mutant is killed by the loopback and
// redirect tests.
func TestRemoteJWKSIgnoresEnvironmentProxy(t *testing.T) {
	var proxied atomic.Int32

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		http.Error(w, "proxied", http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)

	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	_, pub := ecKey(t, "k")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pub)))
	p := e.provider(t, newTestClock())

	assert.True(t, hasKey(t, p, "k"))
	assert.Equal(t, int32(0), proxied.Load(), "no request went through the proxy")
}

// TestRemoteJWKSWithHTTPClientIsAnOptOut pins the documented opt-out: the
// caller's client decides destinations, the provider still bounds the
// fetch — 1 MiB, a fetch timeout even for a client without one.
func TestRemoteJWKSWithHTTPClientIsAnOptOut(t *testing.T) {
	t.Parallel()

	_, pub := ecKey(t, "k")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pub)))
	plain := httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(plain.Close)

	p, err := jwtsec.NewRemoteJWKS(plain.URL+"/jwks", jwtsec.WithHTTPClient(&http.Client{}))
	require.NoError(t, err)

	assert.True(t, hasKey(t, p, "k"), "a plain http loopback set through the opt-out client")

	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("A", 1<<20) + `"}`))
	}))
	t.Cleanup(big.Close)

	p, err = jwtsec.NewRemoteJWKS(big.URL, jwtsec.WithHTTPClient(&http.Client{}))
	require.NoError(t, err)

	_, err = p.KeySet(context.Background())
	require.ErrorIs(t, err, outbound.ErrResponseTooLarge, "the 1 MiB bound holds without the outbound client")

	// A hung upstream and a client without timeout: the fetch is bounded.
	release := e.hold()
	defer release()

	p, err = jwtsec.NewRemoteJWKS(plain.URL+"/jwks", jwtsec.WithHTTPClient(&http.Client{}))
	require.NoError(t, err)

	jwtsec.SetRemoteJWKSFetchTimeout(p, 50*time.Millisecond)

	_, err = p.KeySet(context.Background())
	require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	waitIdle(t, p)
}

// TestRemoteJWKSSingleFlight pins decision 8 (audit JWT-03, probe R2: eight
// verifications made eight serialized fetches): concurrent callers share
// one fetch.
func TestRemoteJWKSSingleFlight(t *testing.T) {
	t.Parallel()

	_, pub := ecKey(t, "k")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pub)))
	release := e.hold()
	p := e.provider(t, newTestClock())

	const callers = 100

	var (
		wg   sync.WaitGroup
		errs atomic.Int32
	)

	for range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if set, err := p.KeySet(context.Background()); err != nil || set == nil {
				errs.Add(1)
			}
		}()
	}

	require.Eventually(t, func() bool { return e.hits.Load() == 1 }, 5*time.Second, time.Millisecond)
	release()
	wg.Wait()

	assert.Equal(t, int32(0), errs.Load())
	assert.Equal(t, int32(1), e.hits.Load(), "one fetch for every caller")
}

// TestRemoteJWKSServesTheCachedSetWhileRefreshing pins that no caller ever
// waits on a TTL refresh while a usable set exists — the lock is not held
// during the fetch (audit JWT-03: an outage coupled every request).
func TestRemoteJWKSServesTheCachedSetWhileRefreshing(t *testing.T) {
	t.Parallel()

	_, pubA := ecKey(t, "A")
	_, pubB := ecKey(t, "B")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pubA)))
	clock := newTestClock()
	p := e.provider(t, clock)

	require.True(t, hasKey(t, p, "A"))

	release := e.hold()
	e.set(jwksJSON(t, sigKey(pubA), sigKey(pubB)), http.StatusOK)
	clock.advance(jwtsec.DefaultCacheTTL)

	done := make(chan bool)

	go func() { done <- hasKey(t, p, "A") }()

	select {
	case ok := <-done:
		assert.True(t, ok, "the cached set is served")
	case <-time.After(5 * time.Second):
		t.Fatal("KeySet waited for the refresh in flight")
	}

	require.Eventually(t, func() bool { return e.hits.Load() == 2 }, 5*time.Second, time.Millisecond, "a background refresh started")
	assert.False(t, jwtsec.RemoteJWKSIdle(p), "the refresh is still in flight")

	release()
	waitIdle(t, p)
	assert.True(t, hasKey(t, p, "B"), "the refreshed set replaced the cached one")
}

// TestRemoteJWKSWaitHonoursTheCallerContext pins that a caller without a
// usable set waits for the fetch only until its own context ends — and
// that giving up does not abort the fetch for the others.
func TestRemoteJWKSWaitHonoursTheCallerContext(t *testing.T) {
	t.Parallel()

	_, pub := ecKey(t, "k")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pub)))
	release := e.hold()
	p := e.provider(t, newTestClock())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := p.KeySet(ctx)

	require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	notCredentialFailure(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.False(t, jwtsec.RemoteJWKSIdle(p), "the fetch goes on")

	release()
	waitIdle(t, p)
	assert.True(t, hasKey(t, p, "k"), "the detached fetch completed for the next callers")
	assert.Equal(t, int32(1), e.hits.Load())
}

// TestRemoteJWKSBacksOff pins decision 8 and review F9: a failing upstream
// is not fetched on every call (audit JWT-03 probe: one fetch per forged
// request) — attempts stay MinKeySetRefreshInterval apart, flat while no
// usable set exists, doubling up to 5 minutes while a stale set serves.
func TestRemoteJWKSBacksOff(t *testing.T) {
	t.Parallel()

	_, pub := ecKey(t, "k")
	good := jwksJSON(t, sigKey(pub))
	e := newJWKSEndpoint(t, good)
	e.set(good, http.StatusInternalServerError) // a valid body: the status is the guard
	clock := newTestClock()
	p := e.provider(t, clock)

	attempt := func(want int32) {
		t.Helper()

		_, _ = p.KeySet(context.Background())
		waitIdle(t, p)
		require.Equal(t, want, e.hits.Load())
	}

	// No usable set: a flat MinKeySetRefreshInterval.
	attempt(1)
	attempt(1)

	for range 3 {
		clock.advance(jwtsec.MinKeySetRefreshInterval - time.Nanosecond)
		attempt(e.hits.Load())
		clock.advance(time.Nanosecond)
		attempt(e.hits.Load() + 1)
	}

	_, err := p.KeySet(context.Background())
	require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable)
	assert.Contains(t, err.Error(), "unexpected status 500")

	// A usable set, then a failing upstream: exponential back-off.
	e.set(good, http.StatusOK)
	clock.advance(jwtsec.MinKeySetRefreshInterval)
	attempt(e.hits.Load() + 1)
	require.True(t, hasKey(t, p, "k"))

	e.set(good, http.StatusInternalServerError)
	clock.advance(jwtsec.DefaultCacheTTL)
	attempt(e.hits.Load() + 1) // first failure, the cached set still served
	require.True(t, hasKey(t, p, "k"))

	for _, wait := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute} {
		clock.advance(wait - time.Nanosecond)
		attempt(e.hits.Load())
		clock.advance(time.Nanosecond)
		attempt(e.hits.Load() + 1)
	}

	require.True(t, hasKey(t, p, "k"), "still within MaxKeySetStaleness")
}

// TestRemoteJWKSRefreshesAfterTTL pins the TTL (an audit surviving mutant:
// "JWKS refresh after TTL").
func TestRemoteJWKSRefreshesAfterTTL(t *testing.T) {
	t.Parallel()

	_, pubA := ecKey(t, "A")
	_, pubB := ecKey(t, "B")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pubA)))
	clock := newTestClock()
	p := e.provider(t, clock, jwtsec.WithCacheTTL(time.Hour))

	require.True(t, hasKey(t, p, "A"))
	e.set(jwksJSON(t, sigKey(pubB)), http.StatusOK)

	clock.advance(time.Hour - time.Nanosecond)
	require.True(t, hasKey(t, p, "A"))
	waitIdle(t, p)
	assert.Equal(t, int32(1), e.hits.Load(), "no refresh before the TTL")

	clock.advance(time.Nanosecond)
	require.True(t, hasKey(t, p, "A"), "served while refreshing")
	waitIdle(t, p)
	assert.Equal(t, int32(2), e.hits.Load())
	assert.True(t, hasKey(t, p, "B"))
	assert.False(t, hasKey(t, p, "A"), "a withdrawn key is gone after the refresh")
}

// TestRemoteJWKSStopsServingAStaleSet pins MaxKeySetStaleness (audit
// JWT-08, probe R3: a withdrawn key stayed trusted for as long as
// refreshes failed).
func TestRemoteJWKSStopsServingAStaleSet(t *testing.T) {
	t.Parallel()

	priv, pub := ecKey(t, "old")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pub)))
	clock := newTestClock()
	p := e.provider(t, clock)
	v := jwtsec.NewVerifier(p, jwtsec.WithClock(clock))
	tok := forge(t, jwtsec.ES256, priv.Key, header(jwtsec.ES256, "old"),
		fmt.Sprintf(`{"sub":"a","exp":%d}`, clock.Now().Add(48*time.Hour).Unix()))

	_, err := v.Verify(context.Background(), tok, nil)
	require.NoError(t, err)

	e.set(nil, http.StatusServiceUnavailable)

	clock.advance(jwtsec.MaxKeySetStaleness)

	_, err = v.Verify(context.Background(), tok, nil)
	require.NoError(t, err, "a set exactly MaxKeySetStaleness old is still used")
	waitIdle(t, p)

	clock.advance(time.Nanosecond)

	_, err = v.Verify(context.Background(), tok, nil)
	require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable)
	notCredentialFailure(t, err)
}

// TestVerifierRefreshesOnUnknownKid pins decision 8 and OpenID Connect
// Core §10.1.1 (audit JWT-08, probe R1: a rotated-in kid was refused for a
// whole TTL, although the godoc promised a refresh): an unknown kid makes
// one refresh, at most once per MinKeySetRefreshInterval; a known kid
// with a bad signature and a kid-less token never fetch.
func TestVerifierRefreshesOnUnknownKid(t *testing.T) {
	t.Parallel()

	privA, pubA := ecKey(t, "A")
	privB, pubB := ecKey(t, "B")
	privC, _ := ecKey(t, "C")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pubA)))
	clock := newTestClock()
	p := e.provider(t, clock)
	v := jwtsec.NewVerifier(p)

	_, err := v.Verify(context.Background(), tokenFor(t, privA, "A"), nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), e.hits.Load())

	e.set(jwksJSON(t, sigKey(pubA), sigKey(pubB)), http.StatusOK)
	clock.advance(jwtsec.MinKeySetRefreshInterval)

	_, err = v.Verify(context.Background(), tokenFor(t, privB, "B"), nil)
	require.NoError(t, err, "the rotated-in key verifies after one refresh")
	require.Equal(t, int32(2), e.hits.Load())

	_, err = v.Verify(context.Background(), tokenFor(t, privC, "C"), nil)
	require.ErrorIs(t, err, jwtsec.ErrInvalidSignature)
	assert.Equal(t, int32(2), e.hits.Load(), "a second unknown kid within the interval does not fetch")

	clock.advance(jwtsec.MinKeySetRefreshInterval)

	_, err = v.Verify(context.Background(), tokenFor(t, privC, "C"), nil)
	require.ErrorIs(t, err, jwtsec.ErrInvalidSignature)
	assert.Equal(t, int32(3), e.hits.Load(), "after the interval, one more refresh")

	clock.advance(jwtsec.MinKeySetRefreshInterval)

	forged := forge(t, jwtsec.ES256, privC.Key, header(jwtsec.ES256, "A"), claimsPayload())
	_, err = v.Verify(context.Background(), forged, nil)
	require.ErrorIs(t, err, jwtsec.ErrInvalidSignature)

	_, err = v.Verify(context.Background(), forge(t, jwtsec.ES256, privA.Key, `{"alg":"ES256"}`, claimsPayload()), nil)
	require.ErrorIs(t, err, jwtsec.ErrInvalidSignature)
	assert.Equal(t, int32(3), e.hits.Load(), "a known kid or no kid never fetches")
}

// TestVerifierRefreshesOnceForConcurrentUnknownKids pins the single flight
// of the unknown-kid refresh (review F12a): callers presenting a new kid
// while a fetch is in flight join it.
func TestVerifierRefreshesOnceForConcurrentUnknownKids(t *testing.T) {
	t.Parallel()

	_, pubA := ecKey(t, "A")
	privB, pubB := ecKey(t, "B")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pubA)))
	clock := newTestClock()
	p := e.provider(t, clock)
	v := jwtsec.NewVerifier(p)

	require.True(t, hasKey(t, p, "A"))
	clock.advance(jwtsec.MinKeySetRefreshInterval)

	e.set(jwksJSON(t, sigKey(pubA), sigKey(pubB)), http.StatusOK)
	release := e.hold()
	tok := tokenFor(t, privB, "B")

	const callers = 100

	var (
		wg   sync.WaitGroup
		errs atomic.Int32
	)

	for range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, err := v.Verify(context.Background(), tok, nil); err != nil {
				errs.Add(1)
			}
		}()
	}

	require.Eventually(t, func() bool { return e.hits.Load() == 2 }, 5*time.Second, time.Millisecond)
	release()
	wg.Wait()

	assert.Equal(t, int32(0), errs.Load(), "every caller verified with the refreshed set")
	assert.Equal(t, int32(2), e.hits.Load(), "one refresh for every caller")
}

// TestRemoteJWKSAuthoritativeEmptySet pins that a set without usable keys,
// fetched successfully, replaces the previous one: the issuer withdrew its
// keys.
func TestRemoteJWKSAuthoritativeEmptySet(t *testing.T) {
	t.Parallel()

	priv, pub := ecKey(t, "A")
	e := newJWKSEndpoint(t, jwksJSON(t, sigKey(pub)))
	clock := newTestClock()
	p := e.provider(t, clock)
	v := jwtsec.NewVerifier(p)

	_, err := v.Verify(context.Background(), tokenFor(t, priv, "A"), nil)
	require.NoError(t, err)

	e.set([]byte(`{"keys":[]}`), http.StatusOK)
	clock.advance(jwtsec.DefaultCacheTTL)
	require.True(t, hasKey(t, p, "A"), "served while the refresh runs")
	waitIdle(t, p)

	_, err = v.Verify(context.Background(), tokenFor(t, priv, "A"), nil)
	require.ErrorIs(t, err, jwtsec.ErrInvalidSignature, "the withdrawn key no longer verifies")
}

// TestRemoteJWKSRefusesMalformedDocuments pins RFC 7517 §5 and review F15:
// a document that is not a JWK Set — bad status, strict-JSON violation,
// too large, too many keys, non-object entries — fails the fetch and keeps
// the previous set (until MaxKeySetStaleness); without one, KeySet fails.
func TestRemoteJWKSRefusesMalformedDocuments(t *testing.T) {
	t.Parallel()

	_, pub := ecKey(t, "A")
	good := jwksJSON(t, sigKey(pub))
	key := strings.TrimSuffix(strings.TrimPrefix(string(good), `{"keys":[`), `]}`)

	many := make([]string, 101)
	for i := range many {
		many[i] = key
	}

	cases := map[string]struct {
		doc    string
		status int
	}{
		"status 500 with a valid body": {string(good), http.StatusInternalServerError},
		"status 302 without redirect":  {string(good), http.StatusFound},
		"duplicate keys member":        {`{"keys":[` + key + `],"keys":[]}`, http.StatusOK},
		"case-variant keys member":     {`{"keys":[` + key + `],"KEYS":[]}`, http.StatusOK},
		"Keys only":                    {`{"Keys":[` + key + `]}`, http.StatusOK},
		"more than 100 keys":           {`{"keys":[` + strings.Join(many, ",") + `]}`, http.StatusOK},
		"not an object":                {`[` + key + `]`, http.StatusOK},
		"no keys member":               {`{}`, http.StatusOK},
		"null keys":                    {`{"keys":null}`, http.StatusOK},
		"non-object entries":           {`{"keys":[1,2]}`, http.StatusOK},
		"a key and a string":           {`{"keys":[` + key + `,"x"]}`, http.StatusOK},
		"not JSON":                     {`<html>`, http.StatusOK},
		"over 1 MiB":                   {`{"keys":[],"pad":"` + strings.Repeat("A", 1<<20) + `"}`, http.StatusOK},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newJWKSEndpoint(t, []byte(tc.doc))
			e.set([]byte(tc.doc), tc.status)
			clock := newTestClock()

			cold := e.provider(t, clock)
			_, err := cold.KeySet(context.Background())
			require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable, "no previous set")
			notCredentialFailure(t, err)

			e.set(good, http.StatusOK)
			warm := e.provider(t, clock)
			require.True(t, hasKey(t, warm, "A"))

			e.set([]byte(tc.doc), tc.status)
			clock.advance(jwtsec.DefaultCacheTTL)
			require.True(t, hasKey(t, warm, "A"))
			waitIdle(t, warm)
			assert.True(t, hasKey(t, warm, "A"), "the previous set is kept")
		})
	}
}

// TestVerifierMapsKeySetFailuresToErrKeySetUnavailable pins audit JWT-I6:
// a key set outage is ErrKeySetUnavailable — never a credential failure
// the transports would answer with 401.
func TestVerifierMapsKeySetFailuresToErrKeySetUnavailable(t *testing.T) {
	t.Parallel()

	priv, _ := ecKey(t, "k")
	tok := tokenFor(t, priv, "k")

	for name, provider := range map[string]jwtsec.JWKSProvider{
		"failing provider": providerFunc(func(context.Context) (jwtsec.KeySet, error) { return nil, errors.New("database down") }),
		"nil key set":      providerFunc(func(context.Context) (jwtsec.KeySet, error) { return nil, nil }),
	} {
		_, err := jwtsec.NewVerifier(provider).Verify(context.Background(), tok, nil)
		require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable, name)
		notCredentialFailure(t, err)
	}
}

type providerFunc func(context.Context) (jwtsec.KeySet, error)

func (f providerFunc) KeySet(ctx context.Context) (jwtsec.KeySet, error) { return f(ctx) }

// panickyTransport panics on every request.
type panickyTransport struct{}

func (panickyTransport) RoundTrip(*http.Request) (*http.Response, error) { panic("transport bug") }

// TestRemoteJWKSRecoversFromPanics pins review F5: the fetch runs on its
// own goroutine, where a panic — of a caller-supplied transport here —
// would crash the process; it is a failed fetch instead.
func TestRemoteJWKSRecoversFromPanics(t *testing.T) {
	t.Parallel()

	p, err := jwtsec.NewRemoteJWKS("https://idp.example/jwks", jwtsec.WithHTTPClient(&http.Client{Transport: panickyTransport{}}))
	require.NoError(t, err)

	_, err = p.KeySet(context.Background())
	require.ErrorIs(t, err, jwtsec.ErrKeySetUnavailable)
	waitIdle(t, p)
}
