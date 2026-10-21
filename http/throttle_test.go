// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func throttledEngine(err error) security.Engine {
	return security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "basic", err: err}),
		scriptedExtractor{auth: newAuth("alice")},
	)
}

// RFC 6585 §4: a throttled attempt is answered 429 Too Many Requests, with
// a Retry-After field (RFC 9110 §10.2.3, delay-seconds rounded up) when the
// limiter knows the delay; the response is not stored by caches. A Bearer
// resource still challenges (RFC 6750 §3), without an error code: the token
// was not checked.
func TestMiddlewareAnswersAThrottledAttemptWith429(t *testing.T) {
	t.Parallel()

	throttled := fmt.Errorf("basic: %w", &security.TooManyAttemptsError{RetryAfter: 1500 * time.Millisecond})

	cases := []struct {
		name       string
		err        error
		opts       []httpsec.Option
		req        *http.Request
		retryAfter string
		challenge  []string
	}{
		{"bearer resource, bearer token", throttled, nil, bearerRequest(), "2", []string{bearerAPI}},
		{"basic resource", throttled, []httpsec.Option{httpsec.WithChallengeScheme("Basic")},
			httptest.NewRequest(http.MethodGet, "/", nil), "2", nil},
		{"delay unknown", security.ErrTooManyAttempts, nil, bearerRequest(), "", []string{bearerAPI}},
		{"one nanosecond is one second", &security.TooManyAttemptsError{RetryAfter: time.Nanosecond}, nil,
			bearerRequest(), "1", []string{bearerAPI}},
		{"joined with another refusal", errors.Join(security.ErrInvalidCredentials, throttled), nil,
			bearerRequest(), "2", []string{bearerAPI}},
		// Review m3 (mutant H10): an unknown delay sends no Retry-After —
		// "0" would mean "retry now".
		{"zero delay", &security.TooManyAttemptsError{}, nil, bearerRequest(), "", []string{bearerAPI}},
		{"negative delay", &security.TooManyAttemptsError{RetryAfter: -time.Second}, nil, bearerRequest(), "", []string{bearerAPI}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			rec := serve(httpsec.Middleware(throttledEngine(c.err), c.opts...)(next204()), c.req)

			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
			assert.Equal(t, c.retryAfter, rec.Header().Get("Retry-After"))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Equal(t, c.challenge, rec.Header().Values("WWW-Authenticate"))
			assert.NotContains(t, rec.Body.String(), "alice")
		})
	}
}

// Retry-After and Cache-Control belong to the 429 only.
func TestOtherRefusalsCarryNoRetryAfter(t *testing.T) {
	t.Parallel()

	for _, err := range []error{security.ErrInvalidCredentials, security.ErrUnavailable, errors.New("boom")} {
		rec := serve(httpsec.Middleware(throttledEngine(err))(next204()), bearerRequest())

		assert.NotEqual(t, http.StatusTooManyRequests, rec.Code)
		assert.Empty(t, rec.Header().Values("Retry-After"))
		assert.Empty(t, rec.Header().Values("Cache-Control"))
	}
}

// addrSpy records the client address its authentication context carried.
type addrSpy struct {
	addr  netip.Addr
	found bool
}

func (s *addrSpy) Supports(security.Authentication) bool { return true }

func (s *addrSpy) Authenticate(ctx context.Context, _ security.Authentication) (security.Authentication, error) {
	s.addr, s.found = security.ClientAddrFromContext(ctx)

	return newAuth("alice").verified(), nil
}

// The middleware supplies the transport peer as the client address an
// AttemptLimiter keys on, unless a middleware before it stored one.
func TestMiddlewareSuppliesTheClientAddress(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		remoteAddr string
		upstream   *netip.Addr
		forwarded  bool
		want       netip.Addr
		found      bool
	}{
		{"IPv4 peer", "203.0.113.7:51234", nil, false, netip.MustParseAddr("203.0.113.7"), true},
		{"IPv6 peer", "[2001:db8::7]:443", nil, false, netip.MustParseAddr("2001:db8::7"), true},
		{"IPv4-mapped peer", "[::ffff:198.51.100.2]:80", nil, false, netip.MustParseAddr("198.51.100.2"), true},
		{"unparsable peer", "pipe", nil, false, netip.Addr{}, false},
		{"set upstream", "203.0.113.7:51234", new(netip.MustParseAddr("192.0.2.44")), false, netip.MustParseAddr("192.0.2.44"), true},
		{"unknown upstream", "203.0.113.7:51234", new(netip.Addr{}), false, netip.Addr{}, true},
		// Review m4: forwarded headers are client input — trusting them by
		// default would let a client choose its source.
		{"forwarded headers ignored", "203.0.113.7:51234", nil, true, netip.MustParseAddr("203.0.113.7"), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			spy := &addrSpy{}
			engine := security.NewEngine(security.NewManager(spy), scriptedExtractor{auth: newAuth("alice")})

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = c.remoteAddr

			if c.forwarded {
				req.Header.Set("X-Forwarded-For", "192.0.2.66")
				req.Header.Set("X-Real-IP", "192.0.2.67")
				req.Header.Set("Forwarded", "for=192.0.2.68")
			}

			if c.upstream != nil {
				req = req.WithContext(security.WithClientAddr(req.Context(), *c.upstream))
			}

			rec := serve(httpsec.Middleware(engine)(next204()), req)

			require.Equal(t, http.StatusNoContent, rec.Code)
			assert.Equal(t, c.found, spy.found)
			assert.Equal(t, c.want, spy.addr)
		})
	}
}
