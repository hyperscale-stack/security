// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/outbound"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// metadataServer serves IdP metadata over TLS on the loopback interface. Its
// behaviour can be swapped while a test runs, and it records what it saw.
type metadataServer struct {
	srv  *httptest.Server
	hits atomic.Int32

	mu      sync.Mutex
	handle  http.HandlerFunc
	method  string
	path    string
	headers http.Header
}

func newMetadataServer(t *testing.T, handle http.HandlerFunc) *metadataServer {
	t.Helper()

	m := &metadataServer{handle: handle}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits.Add(1)

		m.mu.Lock()
		h := m.handle
		m.method, m.path, m.headers = r.Method, r.URL.Path, r.Header.Clone()
		m.mu.Unlock()

		h(w, r)
	}))
	t.Cleanup(m.srv.Close)

	return m
}

func (m *metadataServer) set(h http.HandlerFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.handle = h
}

func (m *metadataServer) url() string { return m.srv.URL + "/metadata" }

// policy reaches the server: loopback exempted, its certificate trusted.
func (m *metadataServer) policy() outbound.Policy {
	pool := x509.NewCertPool()
	pool.AddCert(m.srv.Certificate())

	return outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool}
}

func serveMetadata(doc []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(doc)
	}
}

func fetchAt(t *testing.T, m *metadataServer, opts samlsp.FetchOptions) (*samlsp.IdentityProvider, error) {
	t.Helper()

	if opts.Now == nil {
		opts.Now = func() time.Time { return t0 }
	}

	return samlsp.FetchIdentityProviderMetadata(context.Background(), m.url(), opts)
}

func TestFetchIdentityProviderMetadata(t *testing.T) {
	t.Parallel()

	k := keys(t)
	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{}.render(t)))

	idp, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy()})
	require.NoError(t, err)
	assert.Equal(t, idpEntity, idp.EntityID)
	assert.Equal(t, "https://idp.example.com/sso", idp.SSOURL)
	require.Len(t, idp.SigningCertificates, 1)
	assert.True(t, idp.SigningCertificates[0].Equal(k.idpA.cert))

	// A plain GET for SAML metadata, without credentials or cookies.
	m.mu.Lock()
	defer m.mu.Unlock()

	assert.Equal(t, http.MethodGet, m.method)
	assert.Equal(t, "/metadata", m.path)
	assert.Equal(t, "application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8", m.headers.Get("Accept"))
	assert.Empty(t, m.headers.Get("Cookie"))
	assert.Empty(t, m.headers.Get("Authorization"))
}

func TestFetchIdentityProviderMetadata_NetworkPolicy(t *testing.T) {
	t.Parallel()

	doc := idpMetadataSpec{}.render(t)

	t.Run("loopback refused by the default policy", func(t *testing.T) {
		t.Parallel()

		m := newMetadataServer(t, serveMetadata(doc))

		_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity})
		require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
		require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
		assert.Zero(t, m.hits.Load(), "refused before any connection to the server")
	})

	t.Run("loopback name refused by the default policy", func(t *testing.T) {
		t.Parallel()

		m := newMetadataServer(t, serveMetadata(doc))
		url := strings.Replace(m.url(), "127.0.0.1", "localhost", 1)

		_, err := samlsp.FetchIdentityProviderMetadata(context.Background(), url, samlsp.FetchOptions{EntityID: idpEntity})
		require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
		assert.Zero(t, m.hits.Load())
	})

	t.Run("redirects are not followed", func(t *testing.T) {
		t.Parallel()

		m := newMetadataServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		})

		_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy()})
		require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
	})

	t.Run("a redirect to http is refused even when redirects are allowed", func(t *testing.T) {
		t.Parallel()

		m := newMetadataServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/metadata", http.StatusFound)
		})
		policy := m.policy()
		policy.MaxRedirects = 2

		_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: policy})
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
	})

	t.Run("a redirect to another origin is refused whatever MaxRedirects says", func(t *testing.T) {
		t.Parallel()

		// The other origin serves a document of the pinned entity with the
		// attacker's key (second review S2).
		other := newMetadataServer(t, serveMetadata(idpMetadataSpec{keyDescriptors: keyDescriptor("signing", keys(t).attacker.cert)}.render(t)))
		m := newMetadataServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.url(), http.StatusFound)
		})

		policy := m.policy()
		policy.MaxRedirects = 3
		policy.RootCAs.AddCert(other.srv.Certificate())

		_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: policy})
		require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
		require.ErrorIs(t, err, outbound.ErrURLNotAllowed)
		assert.Zero(t, other.hits.Load(), "the other origin is never contacted")
	})

	t.Run("a redirect within the origin follows MaxRedirects and the application's CheckURL", func(t *testing.T) {
		t.Parallel()

		m := newMetadataServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/metadata" {
				http.Redirect(w, r, "/metadata/v2", http.StatusMovedPermanently)

				return
			}

			serveMetadata(doc)(w, r)
		})

		policy := m.policy()
		policy.MaxRedirects = 1

		idp, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: policy})
		require.NoError(t, err)
		assert.Equal(t, idpEntity, idp.EntityID)

		var checked []string

		policy.CheckURL = func(_ context.Context, u *url.URL) error {
			checked = append(checked, u.Path)
			if u.Path == "/metadata/v2" {
				return errors.New("not this path")
			}

			return nil
		}

		_, err = fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: policy})
		require.ErrorIs(t, err, outbound.ErrURLNotAllowed)
		assert.Equal(t, []string{"/metadata", "/metadata/v2"}, checked, "the application's hook still sees every hop")
	})

	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusNotModified, http.StatusNoContent} {
		t.Run("status "+http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			m := newMetadataServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("SECRET-BODY"))
			})

			_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy()})
			require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
			assert.NotContains(t, err.Error(), "SECRET-BODY", "a response body is never part of an error")
		})
	}

	t.Run("oversized document", func(t *testing.T) {
		t.Parallel()

		big := append(bytes.Clone(doc), bytes.Repeat([]byte("<!-- padding -->"), 70_000)...) // over 1 MiB
		m := newMetadataServer(t, serveMetadata(big))

		_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy()})
		require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
		require.ErrorIs(t, err, outbound.ErrResponseTooLarge)

		// MaxSize below the policy's limit wins.
		m.set(serveMetadata(doc))

		_, err = fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy(), MaxSize: int64(len(doc) - 1)})
		require.ErrorIs(t, err, outbound.ErrResponseTooLarge)

		// And the policy's limit below MaxSize.
		policy := m.policy()
		policy.MaxResponseBytes = int64(len(doc) - 1)

		_, err = fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: policy})
		require.ErrorIs(t, err, outbound.ErrResponseTooLarge)
	})

	t.Run("gzip bomb", func(t *testing.T) {
		t.Parallel()

		var gz bytes.Buffer

		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(bytes.Repeat([]byte(" "), 16<<20))
		require.NoError(t, zw.Close())

		m := newMetadataServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz.Bytes())
		})

		_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy()})
		require.ErrorIs(t, err, outbound.ErrResponseTooLarge)
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()

		release := make(chan struct{})
		m := newMetadataServer(t, func(http.ResponseWriter, *http.Request) { <-release })
		t.Cleanup(func() { close(release) }) // before the server closes: it waits for the handler

		policy := m.policy()
		policy.Timeout = 200 * time.Millisecond

		start := time.Now()
		_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: policy})
		require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
		assert.Less(t, time.Since(start), 5*time.Second)
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()

		m := newMetadataServer(t, serveMetadata(doc))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := samlsp.FetchIdentityProviderMetadata(ctx, m.url(), samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy()})
		require.ErrorIs(t, err, context.Canceled)
	})
}

// TestFetchIdentityProviderMetadata_AggregateNeedsPin: discovery without
// a pin works for an EntityDescriptor only; an EntitiesDescriptor, even of
// one entity, is imported only for the pinned entity ID.
func TestFetchIdentityProviderMetadata_AggregateNeedsPin(t *testing.T) {
	t.Parallel()

	aggregate := idpMetadataSpec{root: `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">ENTITY</md:EntitiesDescriptor>`}.render(t)
	m := newMetadataServer(t, serveMetadata(aggregate))

	idp, err := fetchAt(t, m, samlsp.FetchOptions{Outbound: m.policy()})
	require.ErrorIs(t, err, samlsp.ErrInvalidMetadata)
	assert.Nil(t, idp)

	idp, err = fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy()})
	require.NoError(t, err)
	assert.Equal(t, idpEntity, idp.EntityID)

	m.set(serveMetadata(idpMetadataSpec{}.render(t)))

	idp, err = fetchAt(t, m, samlsp.FetchOptions{Outbound: m.policy()})
	require.NoError(t, err, "an EntityDescriptor can be discovered without a pin")
	assert.Equal(t, idpEntity, idp.EntityID)
}

func TestFetchIdentityProviderMetadata_Document(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		doc  []byte
		want error
	}{
		"DOCTYPE":         {append([]byte(`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`), idpMetadataSpec{}.render(t)...), samlsp.ErrInvalidMetadata},
		"not XML":         {[]byte("<html>login page</html"), samlsp.ErrInvalidMetadata},
		"another entity":  {idpMetadataSpec{entityID: "https://evil.example.com"}.render(t), samlsp.ErrInvalidMetadata},
		"expired":         {idpMetadataSpec{entityExtra: ` validUntil="2026-10-12T09:00:00Z"`}.render(t), samlsp.ErrMetadataExpired},
		"no signing keys": {idpMetadataSpec{keyDescriptors: keyDescriptor("encryption", keys(t).idpA.cert)}.render(t), samlsp.ErrInvalidMetadata},
		// A published chain is refused on every fetch (audit F-13).
		"certificate chain": {idpMetadataSpec{keyDescriptors: keyDescriptor("signing", testChain(t).leaf.cert, testChain(t).ca.cert)}.render(t), samlsp.ErrInvalidMetadata},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m := newMetadataServer(t, serveMetadata(tc.doc))

			_, err := fetchAt(t, m, samlsp.FetchOptions{EntityID: idpEntity, Outbound: m.policy()})
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestFetchIdentityProviderMetadata_InvalidOptions(t *testing.T) {
	t.Parallel()

	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{}.render(t)))

	// The URLs name the test server, reachable with its policy: only the
	// validation can refuse them.
	cases := map[string]struct {
		url  string
		opts samlsp.FetchOptions
	}{
		"empty URL":              {"", samlsp.FetchOptions{}},
		"relative URL":           {"/metadata", samlsp.FetchOptions{}},
		"ftp":                    {strings.Replace(m.url(), "https:", "ftp:", 1), samlsp.FetchOptions{Outbound: m.policy()}},
		"http without AllowHTTP": {strings.Replace(m.url(), "https:", "http:", 1), samlsp.FetchOptions{Outbound: m.policy()}},
		"credentials in the URL": {strings.Replace(m.url(), "https://", "https://user:secret@", 1), samlsp.FetchOptions{Outbound: m.policy()}},
		"fragment":               {m.url() + "#x", samlsp.FetchOptions{Outbound: m.policy()}},
		"no host":                {"https:///metadata", samlsp.FetchOptions{Outbound: m.policy()}},
		"negative MaxSize":       {m.url(), samlsp.FetchOptions{Outbound: m.policy(), MaxSize: -1}},
		// Hosts and ports outbound refuses on every request fail at once
		// (second review S4).
		"numeric host name":              {"https://127.1/metadata", samlsp.FetchOptions{}},
		"hexadecimal host":               {"https://0x7f.1/metadata", samlsp.FetchOptions{}},
		"trailing dot":                   {"https://idp.example.com./metadata", samlsp.FetchOptions{}},
		"underscore in host":             {"https://idp_x.example.com/metadata", samlsp.FetchOptions{}},
		"non-ASCII host":                 {"https://idp.exämple.com/metadata", samlsp.FetchOptions{}},
		"zoned address":                  {"https://[fe80::1%25en0]/metadata", samlsp.FetchOptions{}},
		"port out of range":              {"https://idp.example.com:99999/metadata", samlsp.FetchOptions{}},
		"port zero":                      {"https://idp.example.com:0/metadata", samlsp.FetchOptions{}},
		"empty label":                    {"https://idp..example.com/metadata", samlsp.FetchOptions{}},
		"label with a hyphen at its end": {"https://idp-.example.com/metadata", samlsp.FetchOptions{}},
		"invalid outbound policy":        {m.url(), samlsp.FetchOptions{Outbound: outbound.Policy{Timeout: -time.Second}}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := samlsp.FetchIdentityProviderMetadata(context.Background(), tc.url, tc.opts)
			require.ErrorIs(t, err, samlsp.ErrInvalidConfig)
		})
	}

	assert.Zero(t, m.hits.Load(), "invalid options never reach the network")
}

// sourceAt returns a MetadataSource over m with the clock clk.
func sourceAt(t *testing.T, m *metadataServer, clk *clock, tune func(*samlsp.MetadataSourceConfig)) *samlsp.MetadataSource {
	t.Helper()

	cfg := samlsp.MetadataSourceConfig{URL: m.url(), EntityID: idpEntity, Outbound: m.policy(), Now: clk.Now}
	if tune != nil {
		tune(&cfg)
	}

	src, err := samlsp.NewMetadataSource(cfg)
	require.NoError(t, err)

	return src
}

func advance(clk *clock, d time.Duration) { clk.set(clk.Now().Add(d)) }

func TestNewMetadataSource_Validation(t *testing.T) {
	t.Parallel()

	base := samlsp.MetadataSourceConfig{URL: "https://idp.example.com/metadata", EntityID: idpEntity}

	cases := map[string]func(*samlsp.MetadataSourceConfig){
		"no URL":                      func(c *samlsp.MetadataSourceConfig) { c.URL = "" },
		"http URL":                    func(c *samlsp.MetadataSourceConfig) { c.URL = "http://idp.example.com/metadata" },
		"no pinned entity ID":         func(c *samlsp.MetadataSourceConfig) { c.EntityID = "" },
		"relative entity ID":          func(c *samlsp.MetadataSourceConfig) { c.EntityID = "idp" },
		"negative MaxSize":            func(c *samlsp.MetadataSourceConfig) { c.MaxSize = -1 },
		"MinRefresh under a minute":   func(c *samlsp.MetadataSourceConfig) { c.MinRefresh = time.Second },
		"MaxRefresh under MinRefresh": func(c *samlsp.MetadataSourceConfig) { c.MinRefresh, c.MaxRefresh = time.Hour, 30*time.Minute },
		"MaxRefresh over 30 days": func(c *samlsp.MetadataSourceConfig) {
			c.MaxRefresh, c.MaxStale = 31*24*time.Hour, 60*24*time.Hour
		},
		"MaxStale under MaxRefresh":       func(c *samlsp.MetadataSourceConfig) { c.MaxStale = time.Hour },
		"MaxStale over a year":            func(c *samlsp.MetadataSourceConfig) { c.MaxStale = 400 * 24 * time.Hour },
		"RetryInterval under a second":    func(c *samlsp.MetadataSourceConfig) { c.RetryInterval = time.Millisecond },
		"RetryInterval over MaxRefresh":   func(c *samlsp.MetadataSourceConfig) { c.RetryInterval = 48 * time.Hour },
		"negative durations":              func(c *samlsp.MetadataSourceConfig) { c.MinRefresh = -time.Minute },
		"invalid outbound policy":         func(c *samlsp.MetadataSourceConfig) { c.Outbound.MaxRedirects = -1 },
		"invalid outbound prefix":         func(c *samlsp.MetadataSourceConfig) { c.Outbound.AllowedPrefixes = []netip.Prefix{{}} },
		"credentials in the metadata URL": func(c *samlsp.MetadataSourceConfig) { c.URL = "https://u:p@idp.example.com/metadata" },
		"numeric metadata host":           func(c *samlsp.MetadataSourceConfig) { c.URL = "https://127.1/metadata" },
	}

	for name, tune := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := base
			tune(&cfg)

			_, err := samlsp.NewMetadataSource(cfg)
			require.ErrorIs(t, err, samlsp.ErrInvalidConfig)
		})
	}

	_, err := samlsp.NewMetadataSource(base)
	require.NoError(t, err, "defaults are valid; no network access at construction")
}

func TestMetadataSource_SingleFlight(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	doc := idpMetadataSpec{}.render(t)
	m := newMetadataServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		serveMetadata(doc)(w, r)
	})
	src := sourceAt(t, m, newClock(), nil)

	const callers = 20

	var wg sync.WaitGroup

	results := make(chan error, callers)

	for range callers {
		wg.Go(func() {
			idp, err := src.IdentityProvider(context.Background())
			if err == nil && idp.EntityID != idpEntity {
				err = errors.New("wrong entity")
			}

			results <- err
		})
	}

	time.Sleep(100 * time.Millisecond) // let every caller join the fetch in flight
	close(release)
	wg.Wait()
	close(results)

	for err := range results {
		require.NoError(t, err)
	}

	assert.Equal(t, int32(1), m.hits.Load(), "one fetch for concurrent callers")
}

func TestMetadataSource_RefreshInterval(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		entityExtra string
		interval    time.Duration
	}{
		{"cacheDuration", ` cacheDuration="PT2H"`, 2 * time.Hour},
		{"no cacheDuration", "", samlsp.DefaultMetadataRefresh},
		{"cacheDuration under MinRefresh", ` cacheDuration="PT1S"`, samlsp.DefaultMetadataMinRefresh},
		{"cacheDuration over MaxRefresh", ` cacheDuration="P30D"`, samlsp.DefaultMetadataMaxRefresh},
		{"validUntil before the cacheDuration", ` cacheDuration="PT6H" validUntil="2026-10-12T13:00:00Z"`, 3 * time.Hour},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := newMetadataServer(t, serveMetadata(idpMetadataSpec{entityExtra: tc.entityExtra}.render(t)))
			clk := newClock()
			src := sourceAt(t, m, clk, nil)

			_, err := src.IdentityProvider(context.Background())
			require.NoError(t, err)
			require.Equal(t, int32(1), m.hits.Load())

			advance(clk, tc.interval-time.Second)
			_, err = src.IdentityProvider(context.Background())
			require.NoError(t, err)
			assert.Equal(t, int32(1), m.hits.Load(), "not refreshed before the interval")

			advance(clk, time.Second)
			_, _ = src.IdentityProvider(context.Background())
			samlsp.WaitMetadataFetch(src)
			assert.Equal(t, int32(2), m.hits.Load(), "refreshed once the interval elapsed")
		})
	}
}

func TestMetadataSource_ZeroCacheDuration(t *testing.T) {
	t.Parallel()

	// An explicit PT0S asks for the shortest interval allowed, unlike an
	// absent cacheDuration (second review S3).
	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{entityExtra: ` cacheDuration="PT0S"`}.render(t)))
	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	_, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)

	advance(clk, samlsp.DefaultMetadataMinRefresh)
	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)
	samlsp.WaitMetadataFetch(src)
	assert.Equal(t, int32(2), m.hits.Load())
}

func TestMetadataSource_ExpiredDocumentRefreshedAtOnce(t *testing.T) {
	t.Parallel()

	// A document whose validUntil comes before the next scheduled refresh
	// is refreshed once it expires, spaced by RetryInterval, instead of
	// failing closed until then (second review S5).
	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{entityExtra: ` validUntil="2026-10-12T10:02:00Z"`}.render(t)))
	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	_, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)

	m.set(serveMetadata(idpMetadataSpec{entityExtra: ` validUntil="2026-10-20T00:00:00Z"`}.render(t)))
	clk.set(time.Date(2026, 10, 12, 10, 2, 0, 0, time.UTC))

	idp, err := src.IdentityProvider(context.Background())
	require.NoError(t, err, "the expired document is replaced without waiting for MinRefresh")
	assert.True(t, idp.ValidUntil.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)))
	assert.Equal(t, int32(2), m.hits.Load())

	// A hostile IdP serving documents that expire seconds after each fetch
	// makes the source fetch at most once per RetryInterval.
	m.set(func(w http.ResponseWriter, r *http.Request) {
		until := clk.Now().Add(10 * time.Second).UTC().Format(time.RFC3339)
		serveMetadata(idpMetadataSpec{entityExtra: ` validUntil="` + until + `"`}.render(t))(w, r)
	})
	clk.set(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC))

	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)

	hits := m.hits.Load()

	advance(clk, 20*time.Second)
	_, err = src.IdentityProvider(context.Background())
	require.ErrorIs(t, err, samlsp.ErrMetadataExpired)
	assert.Equal(t, hits, m.hits.Load(), "no fetch within RetryInterval of the last one")

	advance(clk, samlsp.DefaultMetadataRetryInterval)
	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)
	assert.Equal(t, hits+1, m.hits.Load())
}

func TestMetadataSource_RefreshDoesNotBlockLogins(t *testing.T) {
	t.Parallel()

	// A due refresh of a hung endpoint never delays a caller while a valid
	// document is cached: it runs in the background (second review S1).
	release := make(chan struct{})
	doc := idpMetadataSpec{entityExtra: ` cacheDuration="PT1H"`}.render(t)
	m := newMetadataServer(t, serveMetadata(doc))
	t.Cleanup(func() { close(release) })

	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	_, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)

	m.set(func(w http.ResponseWriter, r *http.Request) {
		<-release
		serveMetadata(doc)(w, r)
	})
	advance(clk, time.Hour)

	var wg sync.WaitGroup

	for range 20 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			start := time.Now()
			idp, err := src.IdentityProvider(ctx)

			if assert.NoError(t, err) {
				assert.Equal(t, idpEntity, idp.EntityID)
			}

			assert.Less(t, time.Since(start), 500*time.Millisecond, "served from the cache")
		})
	}

	wg.Wait()

	require.Eventually(t, func() bool { return m.hits.Load() == 2 }, 5*time.Second, 10*time.Millisecond,
		"one background refresh for every caller")
}

func TestMetadataSource_StaleOnError(t *testing.T) {
	t.Parallel()

	k := keys(t)
	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{entityExtra: ` cacheDuration="PT1H"`}.render(t)))
	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	_, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)

	// The IdP fails: the last-known-good metadata keeps being served, and
	// failed attempts are spaced by the retry interval.
	m.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	advance(clk, time.Hour)

	idp, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)
	assert.True(t, idp.SigningCertificates[0].Equal(k.idpA.cert))
	samlsp.WaitMetadataFetch(src)
	assert.Equal(t, int32(2), m.hits.Load())

	advance(clk, samlsp.DefaultMetadataRetryInterval-time.Second)
	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)
	samlsp.WaitMetadataFetch(src)
	assert.Equal(t, int32(2), m.hits.Load(), "no attempt within the retry interval")

	advance(clk, time.Second)
	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)
	samlsp.WaitMetadataFetch(src)
	assert.Equal(t, int32(3), m.hits.Load())

	// A document of another entity is a failure too: the pinned one stays.
	m.set(serveMetadata(idpMetadataSpec{entityID: "https://evil.example.com", keyDescriptors: keyDescriptor("signing", k.attacker.cert)}.render(t)))
	advance(clk, samlsp.DefaultMetadataRetryInterval)

	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)
	samlsp.WaitMetadataFetch(src)
	assert.Equal(t, int32(4), m.hits.Load())

	idp, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)
	assert.Equal(t, idpEntity, idp.EntityID)
	assert.True(t, idp.SigningCertificates[0].Equal(k.idpA.cert), "keys come only from a valid document of the pinned entity")

	// Without a successful refresh for MaxStale, it fails closed.
	advance(clk, samlsp.DefaultMetadataMaxStale)

	_, err = src.IdentityProvider(context.Background())
	require.ErrorIs(t, err, samlsp.ErrMetadataExpired)
}

func TestMetadataSource_ValidUntilIsAHardStop(t *testing.T) {
	t.Parallel()

	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{entityExtra: ` cacheDuration="PT1H" validUntil="2026-10-12T12:00:00Z"`}.render(t)))
	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	_, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)

	m.set(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })

	advance(clk, time.Hour+30*time.Minute)
	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err, "served while refreshes fail, before validUntil")
	samlsp.WaitMetadataFetch(src)

	clk.set(time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC))

	_, err = src.IdentityProvider(context.Background())
	require.ErrorIs(t, err, samlsp.ErrMetadataExpired, "never past validUntil, whatever MaxStale says")

	// A successful refresh brings it back.
	m.set(serveMetadata(idpMetadataSpec{}.render(t)))
	advance(clk, samlsp.DefaultMetadataRetryInterval)

	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)
}

func TestMetadataSource_ColdFailure(t *testing.T) {
	t.Parallel()

	m := newMetadataServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	_, err := src.IdentityProvider(context.Background())
	require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)

	_, err = src.IdentityProvider(context.Background())
	require.ErrorIs(t, err, samlsp.ErrMetadataUnavailable)
	assert.Equal(t, int32(1), m.hits.Load(), "failed attempts are rate-limited")

	m.set(serveMetadata(idpMetadataSpec{}.render(t)))
	advance(clk, samlsp.DefaultMetadataRetryInterval)

	_, err = src.IdentityProvider(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(2), m.hits.Load())
}

func TestMetadataSource_KeyRollover(t *testing.T) {
	t.Parallel()

	k := keys(t)
	// One KeyDescriptor per key (Metadata Interoperability Profile §2.5.1).
	doc := func(certs ...*x509.Certificate) []byte {
		kds := ""
		for _, c := range certs {
			kds += keyDescriptor("signing", c)
		}

		return idpMetadataSpec{entityExtra: ` cacheDuration="PT1H"`, keyDescriptors: kds}.render(t)
	}

	m := newMetadataServer(t, serveMetadata(doc(k.idpA.cert)))
	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	// certsNow returns the certificates once any refresh the call started
	// completed: a due refresh runs in the background.
	certsNow := func() []*x509.Certificate {
		_, err := src.IdentityProvider(context.Background())
		require.NoError(t, err)
		samlsp.WaitMetadataFetch(src)

		idp, err := src.IdentityProvider(context.Background())
		require.NoError(t, err)

		return idp.SigningCertificates
	}

	require.Len(t, certsNow(), 1)

	// The IdP announces its next key, then retires the old one: each is
	// picked up at the next refresh, never before.
	m.set(serveMetadata(doc(k.idpA.cert, k.idpB.cert)))
	assert.Len(t, certsNow(), 1)

	advance(clk, time.Hour)

	certs := certsNow()
	require.Len(t, certs, 2)
	assert.True(t, certs[1].Equal(k.idpB.cert))

	m.set(serveMetadata(doc(k.idpB.cert)))
	advance(clk, time.Hour)

	certs = certsNow()
	require.Len(t, certs, 1)
	assert.True(t, certs[0].Equal(k.idpB.cert))
}

func TestMetadataSource_CallerCancel(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	doc := idpMetadataSpec{}.render(t)
	m := newMetadataServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		serveMetadata(doc)(w, r)
	})
	src := sourceAt(t, m, newClock(), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := src.IdentityProvider(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded, "the caller stops waiting")

	// The fetch was not abandoned with the caller: the next one gets its
	// result without a new request.
	close(release)

	require.Eventually(t, func() bool {
		_, err := src.IdentityProvider(context.Background())

		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, int32(1), m.hits.Load())
}

func TestMetadataSource_ReturnsCopies(t *testing.T) {
	t.Parallel()

	k := keys(t)
	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{}.render(t)))
	src := sourceAt(t, m, newClock(), nil)

	idp, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)

	idp.SigningCertificates[0] = k.attacker.cert
	idp.EntityID = "https://evil.example.com"

	again, err := src.IdentityProvider(context.Background())
	require.NoError(t, err)
	assert.Equal(t, idpEntity, again.EntityID)
	assert.True(t, again.SigningCertificates[0].Equal(k.idpA.cert))
}

func TestMetadataSource_Concurrency(t *testing.T) {
	t.Parallel()

	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{entityExtra: ` cacheDuration="PT5M"`}.render(t)))
	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	var wg sync.WaitGroup

	for i := range 8 {
		wg.Go(func() {
			for range 50 {
				if i == 0 {
					advance(clk, time.Minute)
				}

				if _, err := src.IdentityProvider(context.Background()); err != nil {
					t.Error(err)

					return
				}
			}
		})
	}

	wg.Wait()
	samlsp.WaitMetadataFetch(src)

	// 50 minutes elapsed: at most one fetch per 5 minutes, plus the first.
	assert.LessOrEqual(t, m.hits.Load(), int32(11))
}

func TestMetadataSource_DrivesALogin(t *testing.T) {
	t.Parallel()

	// The intended wiring: the resolver takes the IdP from the source.
	m := newMetadataServer(t, serveMetadata(idpMetadataSpec{}.render(t)))
	clk := newClock()
	src := sourceAt(t, m, clk, nil)

	e := newEnv(t)
	base := *e.conn

	sp, err := samlsp.New(samlsp.Config{
		TransactionKeys: testTransactionKeys,
		Connections: samlsp.ConnectionResolverFunc(func(ctx context.Context, id string) (*samlsp.Connection, error) {
			idp, err := src.IdentityProvider(ctx)
			if err != nil {
				return nil, err
			}

			conn := base
			conn.ID = id
			conn.IdentityProvider = *idp

			return &conn, nil
		}),
		Transactions: e.store,
		ReplayCache:  e.store,
		Now:          clk.Now,
	})
	require.NoError(t, err)

	e.sp = sp
	lr := begin(t, e, samlsp.LoginOptions{})

	res, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
	require.NoError(t, err)
	assert.Equal(t, nameIDValue, res.Identity.NameID.Value)
}
