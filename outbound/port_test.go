// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package outbound_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit F-14: CheckURL saw the port as written. "http://h:022/" passed the
// range check as 22 and the hook, comparing strings, saw "022" — a port
// deny-list was bypassed while net/http dialed port 22. CheckURL now sees
// the canonical port: decimal without leading zeros, and none for the
// scheme's default (443 for https, 80 for http), as a WHATWG URL serializes
// it.
func TestCheckURLSeesTheCanonicalPort(t *testing.T) {
	t.Parallel()

	errStop := errors.New("stop")

	cases := []struct{ url, host string }{
		{"https://example.com:8443/x", "example.com:8443"},
		{"https://example.com:08443/x", "example.com:8443"},
		{"https://example.com:0000000022/x", "example.com:22"},
		{"https://example.com:443/x", "example.com"},
		{"https://example.com:0443/x", "example.com"},
		{"https://example.com:80/x", "example.com:80"},
		{"http://example.com:80/x", "example.com"},
		{"http://example.com:080/x", "example.com"},
		{"http://example.com:443/x", "example.com:443"},
		{"https://[2606:4700::1]:0443/x", "[2606:4700::1]"},
		{"https://[2606:4700::1]:08443/x", "[2606:4700::1]:8443"},
		{"https://8.8.8.8:065535/x", "8.8.8.8:65535"},
	}

	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			t.Parallel()

			var host, port string

			client, err := outbound.NewClient(outbound.Policy{AllowHTTP: true, CheckURL: func(_ context.Context, u *url.URL) error {
				host, port = u.Host, u.Port()

				return errStop
			}})
			require.NoError(t, err)

			_, err = client.Get(c.url)
			require.ErrorIs(t, err, errStop)
			assert.Equal(t, c.host, host)

			if port != "" {
				n, convErr := strconv.Atoi(port)
				require.NoError(t, convErr)
				assert.Equal(t, strconv.Itoa(n), port, "no leading zero")
			}
		})
	}
}

// The audit's probe: a CheckURL deny-list of a port no longer lets the
// leading-zero spelling of that port through.
func TestCheckURLPortDenyListHoldsAgainstLeadingZeros(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "reached the denied port")
	}))
	t.Cleanup(s.Close)

	port := strconv.Itoa(s.Listener.Addr().(*net.TCPAddr).Port)

	client, err := outbound.NewClient(outbound.Policy{
		AllowHTTP:       true,
		AllowedPrefixes: outbound.LoopbackPrefixes(),
		CheckURL: func(_ context.Context, u *url.URL) error {
			if u.Port() == port {
				return errors.New("port denied")
			}

			return nil
		},
	})
	require.NoError(t, err)

	for _, spelling := range []string{port, "0" + port, "00" + port} {
		_, err := client.Get("http://127.0.0.1:" + spelling + "/")
		require.ErrorIs(t, err, outbound.ErrURLNotAllowed, spelling)
	}

	assert.Zero(t, hits.Load(), "the denied port was never reached")
}

// A port that is not 1–65535 in decimal digits is refused before the hook,
// whatever its spelling; a URL built by hand can carry one url.Parse
// refuses.
func TestInvalidPortsAreRefused(t *testing.T) {
	t.Parallel()

	client, err := outbound.NewClient(outbound.Policy{CheckURL: func(context.Context, *url.URL) error {
		t.Error("CheckURL called for an invalid port")

		return nil
	}})
	require.NoError(t, err)

	for _, host := range []string{"example.com:0", "example.com:000", "example.com:65536", "example.com:065536", "example.com:+22", "example.com:-1"} {
		req := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: host, Path: "/"}, Header: http.Header{}}

		_, err := client.Do(req.WithContext(context.Background()))
		require.ErrorIs(t, err, outbound.ErrURLNotAllowed, host)
	}
}
