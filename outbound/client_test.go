// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package outbound_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// server is an httptest server counting the requests it receives.
type server struct {
	*httptest.Server
	hits atomic.Int64
}

func newServer(t *testing.T, tlsServer bool, h http.HandlerFunc) *server {
	t.Helper()

	s := &server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		h(w, r)
	})

	if tlsServer {
		s.Server = httptest.NewTLSServer(handler)
	} else {
		s.Server = httptest.NewServer(handler)
	}

	t.Cleanup(s.Close)

	return s
}

func okHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "ok")
}

func pool(s *server) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.Certificate())

	return p
}

// loopbackPolicy is the opt-in a test needs to reach an httptest server.
func loopbackPolicy(s *server) outbound.Policy {
	return outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes(), RootCAs: pool(s)}
}

func get(t *testing.T, c *http.Client, rawURL string) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	require.NoError(t, err)

	return c.Do(req)
}

func mustClient(t *testing.T, p outbound.Policy) *http.Client {
	t.Helper()

	c, err := outbound.NewClient(p)
	require.NoError(t, err)

	return c
}

func readBody(t *testing.T, resp *http.Response) (string, error) {
	t.Helper()

	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)

	return string(b), err
}

func TestNewClientRejectsInvalidPolicy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		p    outbound.Policy
	}{
		{"negative redirects", outbound.Policy{MaxRedirects: -1}},
		{"negative body cap", outbound.Policy{MaxResponseBytes: -1}},
		{"negative timeout", outbound.Policy{Timeout: -time.Second}},
		{"invalid prefix", outbound.Policy{AllowedPrefixes: []netip.Prefix{{}}}},
		{"ipv4-mapped prefix", outbound.Policy{AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")}}},
		{"unmasked prefix", outbound.Policy{AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}}},
		{"ipv4 /0", outbound.Policy{AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}},
		{"ipv6 /0", outbound.Policy{AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("::/0")}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			client, err := outbound.NewClient(c.p)
			require.ErrorIs(t, err, outbound.ErrInvalidPolicy)
			assert.Nil(t, client)
		})
	}
}

func TestNewClientDefaults(t *testing.T) {
	t.Parallel()

	c := mustClient(t, outbound.Policy{})
	assert.Equal(t, outbound.DefaultTimeout, c.Timeout)
	assert.Nil(t, c.Jar, "no cookie jar: cookies are never sent to metadata or token endpoints")

	c = mustClient(t, outbound.Policy{Timeout: 3 * time.Second})
	assert.Equal(t, 3*time.Second, c.Timeout)
}

func TestLoopbackPrefixes(t *testing.T) {
	t.Parallel()

	p := outbound.LoopbackPrefixes()
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}, p)

	p[0] = netip.MustParsePrefix("10.0.0.0/8")
	assert.Equal(t, netip.MustParsePrefix("127.0.0.0/8"), outbound.LoopbackPrefixes()[0], "a fresh slice every call")
}

func TestLoopbackIsBlockedByDefault(t *testing.T) {
	t.Parallel()

	s := newServer(t, true, okHandler)

	_, err := get(t, mustClient(t, outbound.Policy{RootCAs: pool(s)}), s.URL)
	require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
	assert.Zero(t, s.hits.Load())
}

func TestResolvedNameIsChecked(t *testing.T) {
	t.Parallel()

	s := newServer(t, true, okHandler)
	port := s.Listener.Addr().(*net.TCPAddr).Port

	_, err := get(t, mustClient(t, outbound.Policy{RootCAs: pool(s)}), "https://localhost:"+strconv.Itoa(port)+"/")
	require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed, "a name resolving to loopback is refused at connect time")
	assert.Zero(t, s.hits.Load())
}

// TestRefusalHidesResolvedAddress checks that a refused connection does
// not name the address the host resolved to: a tenant typing an internal
// name must not learn its internal address from the error.
func TestRefusalHidesResolvedAddress(t *testing.T) {
	t.Parallel()

	s := newServer(t, true, okHandler)
	port := strconv.Itoa(s.Listener.Addr().(*net.TCPAddr).Port)

	_, err := get(t, mustClient(t, outbound.Policy{RootCAs: pool(s)}), "https://localhost:"+port+"/")
	require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
	assert.NotContains(t, err.Error(), "127.0.0.1")
	assert.NotContains(t, err.Error(), "::1")

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		assert.Nil(t, opErr.Addr, "the dial error carries no resolved address")
	}

	errHook := errors.New("denied by the application")
	p := loopbackPolicy(s)
	p.CheckAddr = func(context.Context, netip.AddrPort) error { return errHook }

	_, err = get(t, mustClient(t, p), "https://localhost:"+port+"/")
	require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
	require.ErrorIs(t, err, errHook)
	assert.NotContains(t, err.Error(), "127.0.0.1")
	assert.NotContains(t, err.Error(), "::1")
}

func TestExemptedLoopbackIsReachable(t *testing.T) {
	t.Parallel()

	s := newServer(t, true, okHandler)

	resp, err := get(t, mustClient(t, loopbackPolicy(s)), s.URL)
	require.NoError(t, err)

	body, err := readBody(t, resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", body)
	assert.Equal(t, int64(1), s.hits.Load())
}

func TestHTTPRequiresOptIn(t *testing.T) {
	t.Parallel()

	s := newServer(t, false, okHandler)

	_, err := get(t, mustClient(t, outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes()}), s.URL)
	require.ErrorIs(t, err, outbound.ErrURLNotAllowed)
	assert.Zero(t, s.hits.Load())

	resp, err := get(t, mustClient(t, outbound.Policy{AllowHTTP: true, AllowedPrefixes: outbound.LoopbackPrefixes()}), s.URL)
	require.NoError(t, err)
	_, _ = readBody(t, resp)
	assert.Equal(t, int64(1), s.hits.Load())
}

func TestURLFormsRefusedBeforeDialing(t *testing.T) {
	t.Parallel()

	s := newServer(t, true, okHandler)
	hostPort := s.Listener.Addr().String()

	cases := []struct {
		name string
		url  string
	}{
		{"ftp scheme", "ftp://" + hostPort + "/"},
		{"userinfo", "https://user:pass@" + hostPort + "/"},
		{"user only", "https://user@" + hostPort + "/"},
		{"fullwidth host", "https://ｌｏｃａｌｈｏｓｔ/x"},
		{"idn host", "https://bücher.example/"},
		{"trailing dot", "https://localhost./x"},
		{"underscore host", "https://my_host.example/"},
		{"empty label", "https://a..example/"},
		{"zoned literal", "https://[fe80::1%25lo0]/"},
		{"port zero", "https://example.com:0/"},
		{"port too large", "https://example.com:65536/"},
		{"host too long", "https://" + strings.Repeat("a.", 127) + "com/"},
		{"label too long", "https://" + strings.Repeat("a", 64) + ".example/"},
		{"leading hyphen", "https://-idp.example/"},
		{"empty host", "https:///x"},
	}

	client := mustClient(t, loopbackPolicy(s))

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.url, nil)
			require.NoError(t, err, "net/http accepts the URL: the policy must refuse it")

			_, err = client.Do(req)
			require.ErrorIs(t, err, outbound.ErrURLNotAllowed)
		})
	}

	assert.Zero(t, s.hits.Load())
}

// TestNumericHostNamesRefused checks the host names a resolver parses as
// IPv4 addresses (WHATWG URL "ends in a number"): libc maps 127.1,
// 2130706433, 0x7f.1 or 0177.0.0.1 to 127.0.0.1, so CheckURL would vet a
// name other than the address dialed. Only the canonical dotted-quad form
// is an IPv4 literal.
func TestNumericHostNamesRefused(t *testing.T) {
	t.Parallel()

	refused := []string{
		"127.1", "2130706433", "0x7f.1", "0x7F.0.0.1", "0177.0.0.1", "0x7f000001",
		"127.0.0.01", "1.2.3.4.5", "example.0x", "example.123", "example.0X1f",
	}

	for _, host := range refused {
		t.Run(host, func(t *testing.T) {
			t.Parallel()

			called := false
			client := mustClient(t, outbound.Policy{CheckURL: func(context.Context, *url.URL) error {
				called = true

				return nil
			}})

			_, err := get(t, client, "https://"+host+"/x")
			require.ErrorIs(t, err, outbound.ErrURLNotAllowed)
			assert.False(t, called, "refused before CheckURL")
		})
	}

	errStop := errors.New("stop")

	for _, host := range []string{"127.0.0.1", "123.example", "a1.example", "0x.example", "example.0xg"} {
		t.Run("accepted "+host, func(t *testing.T) {
			t.Parallel()

			client := mustClient(t, outbound.Policy{CheckURL: func(context.Context, *url.URL) error { return errStop }})

			_, err := get(t, client, "https://"+host+"/x")
			require.ErrorIs(t, err, errStop, "reaches CheckURL")
		})
	}
}

func TestCheckURLSeesCanonicalClone(t *testing.T) {
	t.Parallel()

	s := newServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	})

	var seen []string

	p := loopbackPolicy(s)
	p.CheckURL = func(_ context.Context, u *url.URL) error {
		seen = append(seen, u.String())
		u.Path = "/tampered" // must not affect the request

		return nil
	}

	resp, err := get(t, mustClient(t, p), s.URL+"/original")
	require.NoError(t, err)

	body, err := readBody(t, resp)
	require.NoError(t, err)
	assert.Equal(t, "/original", body)
	assert.Equal(t, []string{s.URL + "/original"}, seen)
}

func TestCheckURLLowercasesHost(t *testing.T) {
	t.Parallel()

	errStop := errors.New("stop")

	var host string

	client := mustClient(t, outbound.Policy{CheckURL: func(_ context.Context, u *url.URL) error {
		host = u.Host

		return errStop
	}})

	_, err := get(t, client, "https://IdP.Example.COM:8443/x")
	require.ErrorIs(t, err, outbound.ErrURLNotAllowed)
	require.ErrorIs(t, err, errStop)
	assert.Equal(t, "idp.example.com:8443", host)
}

func TestCheckURLHostForms(t *testing.T) {
	t.Parallel()

	errStop := errors.New("stop")

	cases := []struct{ url, host string }{
		{"https://example.com/x", "example.com"},
		{"https://8.8.8.8/x", "8.8.8.8"},
		{"https://[2606:4700::1]/x", "[2606:4700::1]"},
		{"https://[2606:4700::1]:8443/x", "[2606:4700::1]:8443"},
		{"https://[2606:4700:0:0::1]/x", "[2606:4700::1]"},
	}

	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			t.Parallel()

			var host string

			client := mustClient(t, outbound.Policy{CheckURL: func(_ context.Context, u *url.URL) error {
				host = u.Host

				return errStop
			}})

			_, err := get(t, client, c.url)
			require.ErrorIs(t, err, errStop)
			assert.Equal(t, c.host, host)
		})
	}
}

// closeRecorder is a request body recording that it was closed.
type closeRecorder struct {
	io.Reader
	closed atomic.Bool
}

func (c *closeRecorder) Close() error {
	c.closed.Store(true)

	return nil
}

func TestRefusedRequestClosesBody(t *testing.T) {
	t.Parallel()

	body := &closeRecorder{Reader: strings.NewReader("grant_type=x")}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.com/token", body)
	require.NoError(t, err)

	_, err = mustClient(t, outbound.Policy{}).Do(req)
	require.ErrorIs(t, err, outbound.ErrURLNotAllowed)
	assert.True(t, body.closed.Load(), "http.RoundTripper contract: the body is closed even on error")
}

func TestRedirects(t *testing.T) {
	t.Parallel()

	newChain := func(t *testing.T) *server {
		t.Helper()

		return newServer(t, true, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/one":
				http.Redirect(w, r, "/two", http.StatusFound)
			case "/two":
				http.Redirect(w, r, "/end", http.StatusFound)
			default:
				_, _ = io.WriteString(w, r.URL.Path)
			}
		})
	}

	t.Run("none by default", func(t *testing.T) {
		t.Parallel()

		s := newChain(t)

		_, err := get(t, mustClient(t, loopbackPolicy(s)), s.URL+"/two")
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
		assert.Equal(t, int64(1), s.hits.Load(), "the redirect target is never requested")
	})

	t.Run("within the cap", func(t *testing.T) {
		t.Parallel()

		s := newChain(t)
		p := loopbackPolicy(s)
		p.MaxRedirects = 2

		resp, err := get(t, mustClient(t, p), s.URL+"/one")
		require.NoError(t, err)

		body, err := readBody(t, resp)
		require.NoError(t, err)
		assert.Equal(t, "/end", body)
	})

	t.Run("beyond the cap", func(t *testing.T) {
		t.Parallel()

		s := newChain(t)
		p := loopbackPolicy(s)
		p.MaxRedirects = 1

		_, err := get(t, mustClient(t, p), s.URL+"/one")
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
		assert.Equal(t, int64(2), s.hits.Load())
	})

	t.Run("each hop re-checked by CheckURL", func(t *testing.T) {
		t.Parallel()

		s := newChain(t)
		errStop := errors.New("no /end")
		p := loopbackPolicy(s)
		p.MaxRedirects = 5

		var hops []string

		p.CheckURL = func(_ context.Context, u *url.URL) error {
			hops = append(hops, u.Path)
			if u.Path == "/end" {
				return errStop
			}

			return nil
		}

		_, err := get(t, mustClient(t, p), s.URL+"/one")
		require.ErrorIs(t, err, outbound.ErrURLNotAllowed)
		require.ErrorIs(t, err, errStop)
		assert.Equal(t, []string{"/one", "/two", "/end"}, hops)
		assert.Equal(t, int64(2), s.hits.Load())
	})

	t.Run("hop to a blocked address", func(t *testing.T) {
		t.Parallel()

		s := newServer(t, true, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
		})
		p := loopbackPolicy(s)
		p.MaxRedirects = 3

		_, err := get(t, mustClient(t, p), s.URL)
		require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
	})

	t.Run("https to http refused even with AllowHTTP", func(t *testing.T) {
		t.Parallel()

		plain := newServer(t, false, okHandler)
		s := newServer(t, true, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL+"/x", http.StatusFound)
		})
		p := loopbackPolicy(s)
		p.AllowHTTP = true
		p.MaxRedirects = 3

		_, err := get(t, mustClient(t, p), s.URL)
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed)
		assert.Zero(t, plain.hits.Load())
	})

	t.Run("http to https to http refused", func(t *testing.T) {
		t.Parallel()

		target := newServer(t, false, okHandler)
		secure := newServer(t, true, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/x", http.StatusFound)
		})
		plain := newServer(t, false, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, secure.URL+"/x", http.StatusFound)
		})
		p := loopbackPolicy(secure)
		p.AllowHTTP = true
		p.MaxRedirects = 3

		_, err := get(t, mustClient(t, p), plain.URL)
		require.ErrorIs(t, err, outbound.ErrRedirectNotAllowed, "the downgrade is judged on the previous hop")
		assert.Equal(t, int64(1), secure.hits.Load())
		assert.Zero(t, target.hits.Load())
	})

	t.Run("http to https allowed with AllowHTTP", func(t *testing.T) {
		t.Parallel()

		secure := newServer(t, true, okHandler)
		plain := newServer(t, false, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, secure.URL+"/x", http.StatusFound)
		})
		p := loopbackPolicy(secure)
		p.AllowHTTP = true
		p.MaxRedirects = 1

		resp, err := get(t, mustClient(t, p), plain.URL)
		require.NoError(t, err)
		_, _ = readBody(t, resp)
		assert.Equal(t, int64(1), secure.hits.Load())
	})
}

func TestResponseSizeLimit(t *testing.T) {
	t.Parallel()

	const capBytes = 1024

	t.Run("announced length over the cap", func(t *testing.T) {
		t.Parallel()

		s := newServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(capBytes+1))
			_, _ = w.Write(bytes.Repeat([]byte("a"), capBytes+1))
		})
		p := loopbackPolicy(s)
		p.MaxResponseBytes = capBytes

		_, err := get(t, mustClient(t, p), s.URL)
		require.ErrorIs(t, err, outbound.ErrResponseTooLarge)
	})

	t.Run("streamed body over the cap", func(t *testing.T) {
		t.Parallel()

		s := newServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
			for range 4 {
				_, _ = w.Write(bytes.Repeat([]byte("a"), capBytes/2))
				w.(http.Flusher).Flush()
			}
		})
		p := loopbackPolicy(s)
		p.MaxResponseBytes = capBytes

		resp, err := get(t, mustClient(t, p), s.URL)
		require.NoError(t, err)

		body, err := readBody(t, resp)
		require.ErrorIs(t, err, outbound.ErrResponseTooLarge)
		assert.LessOrEqual(t, len(body), capBytes, "never more than the cap is handed to the caller")
	})

	t.Run("exactly the cap", func(t *testing.T) {
		t.Parallel()

		s := newServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush() // no Content-Length: chunked
			_, _ = w.Write(bytes.Repeat([]byte("a"), capBytes))
		})
		p := loopbackPolicy(s)
		p.MaxResponseBytes = capBytes

		resp, err := get(t, mustClient(t, p), s.URL)
		require.NoError(t, err)

		body, err := readBody(t, resp)
		require.NoError(t, err)
		assert.Len(t, body, capBytes)
	})

	t.Run("gzip bomb counted after decompression", func(t *testing.T) {
		t.Parallel()

		var compressed bytes.Buffer

		zw := gzip.NewWriter(&compressed)
		_, _ = zw.Write(make([]byte, 8<<20))
		require.NoError(t, zw.Close())

		s := newServer(t, true, func(w http.ResponseWriter, r *http.Request) {
			require.Contains(t, r.Header.Get("Accept-Encoding"), "gzip")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(compressed.Bytes())
		})
		p := loopbackPolicy(s)
		p.MaxResponseBytes = 64 * capBytes

		// The bytes on the wire stay under the cap: only the decompressed
		// size can exceed it. (The exact gzip output size depends on the Go
		// release: 8 MiB of zeros compress to 16,438 bytes with Go 1.27.)
		require.Less(t, int64(compressed.Len()), p.MaxResponseBytes)

		resp, err := get(t, mustClient(t, p), s.URL)
		require.NoError(t, err)

		_, err = readBody(t, resp)
		require.ErrorIs(t, err, outbound.ErrResponseTooLarge)
	})

	t.Run("default cap", func(t *testing.T) {
		t.Parallel()

		s := newServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = w.Write(make([]byte, outbound.DefaultMaxResponseBytes+1))
		})

		resp, err := get(t, mustClient(t, loopbackPolicy(s)), s.URL)
		require.NoError(t, err)

		_, err = readBody(t, resp)
		require.ErrorIs(t, err, outbound.ErrResponseTooLarge)
	})
}

// TestResponseHeaderLimit checks the 64 KiB cap on the response header
// block.
func TestResponseHeaderLimit(t *testing.T) {
	t.Parallel()

	s := newServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
		for i := range 2000 {
			w.Header().Set("X-Filler-"+strconv.Itoa(i), strings.Repeat("h", 64))
		}

		_, _ = io.WriteString(w, "ok")
	})

	_, err := get(t, mustClient(t, loopbackPolicy(s)), s.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded")
}

func TestTimeout(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	s := newServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = io.WriteString(w, "late")
	})
	t.Cleanup(func() { close(release) })

	p := loopbackPolicy(s)
	p.Timeout = 200 * time.Millisecond

	start := time.Now()
	_, err := get(t, mustClient(t, p), s.URL)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

// TestProxyEnvironmentIgnored checks that the client never routes through a
// proxy from the environment: the dial-time address check would then judge
// the proxy, not the destination.
func TestProxyEnvironmentIgnored(t *testing.T) { //nolint:paralleltest // t.Setenv
	s := newServer(t, true, okHandler)

	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")

	resp, err := get(t, mustClient(t, loopbackPolicy(s)), s.URL)
	require.NoError(t, err)
	_, _ = readBody(t, resp)
	assert.Equal(t, int64(1), s.hits.Load())
}

func TestTLSFloorAndRoots(t *testing.T) {
	t.Parallel()

	t.Run("TLS below 1.2 refused", func(t *testing.T) {
		t.Parallel()

		s := &server{}
		s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			s.hits.Add(1)
			_, _ = io.WriteString(w, "legacy")
		}))
		s.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11} //nolint:gosec // the point of the test
		s.StartTLS()
		t.Cleanup(s.Close)

		_, err := get(t, mustClient(t, loopbackPolicy(s)), s.URL)
		require.Error(t, err)
		assert.Zero(t, s.hits.Load())
	})

	t.Run("unknown root refused", func(t *testing.T) {
		t.Parallel()

		s := newServer(t, true, okHandler)

		_, err := get(t, mustClient(t, outbound.Policy{AllowedPrefixes: outbound.LoopbackPrefixes()}), s.URL)

		var unknown x509.UnknownAuthorityError
		require.ErrorAs(t, err, &unknown)
		assert.Zero(t, s.hits.Load())
	})
}
