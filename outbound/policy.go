// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// Defaults applied to the zero fields of a [Policy].
const (
	// DefaultTimeout bounds a whole exchange when Policy.Timeout is zero.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxResponseBytes caps a response body when
	// Policy.MaxResponseBytes is zero. It counts the bytes handed to the
	// caller, after any transparent gzip decompression.
	DefaultMaxResponseBytes int64 = 1 << 20
)

// Transport bounds derived from the policy.
const (
	dialTimeout         = 5 * time.Second
	handshakeTimeout    = 5 * time.Second
	headerTimeout       = 10 * time.Second
	keepAlive           = 30 * time.Second
	idleConnTimeout     = 90 * time.Second
	expectContinue      = time.Second
	maxIdleConns        = 16
	maxIdleConnsPerHost = 2
	maxHeaderBytes      = 64 << 10
)

// Errors returned by [NewClient] and by the requests of the clients it
// builds. A request error comes wrapped (in a *url.Error for client.Do, or
// as is from a body Read): match it with errors.Is.
var (
	// ErrInvalidPolicy reports a Policy NewClient refuses: a negative limit
	// or an unusable AllowedPrefixes entry.
	ErrInvalidPolicy = errors.New("outbound: invalid policy")
	// ErrURLNotAllowed reports a request URL refused before any connection:
	// a scheme other than https (or http with AllowHTTP), userinfo, a
	// missing, non-ASCII, malformed or trailing-dot host, an invalid port,
	// or a refusal by Policy.CheckURL.
	ErrURLNotAllowed = errors.New("outbound: URL not allowed")
	// ErrDestinationNotAllowed reports an address refused at connect time:
	// zoned, outside the publicly routable space and not exempted, or
	// refused by Policy.CheckAddr.
	ErrDestinationNotAllowed = errors.New("outbound: destination address not allowed")
	// ErrRedirectNotAllowed reports a redirect beyond Policy.MaxRedirects or
	// from https to http.
	ErrRedirectNotAllowed = errors.New("outbound: redirect not allowed")
	// ErrResponseTooLarge reports a response body over
	// Policy.MaxResponseBytes, announced (Content-Length) or streamed.
	ErrResponseTooLarge = errors.New("outbound: response body too large")
)

// Policy configures [NewClient]. Its zero value is the strictest policy:
// https only, publicly routable destinations only (judged on the address
// actually connected to), no redirects, [DefaultTimeout],
// [DefaultMaxResponseBytes], TLS 1.2 or later verified against the system
// roots, no proxy, any port.
type Policy struct {
	// AllowHTTP permits http URLs. Development and tests only: an http
	// exchange is neither confidential nor authenticated. A redirect from
	// https to http is refused regardless.
	AllowHTTP bool

	// AllowedPrefixes exempts destination addresses from the built-in
	// block list: 127.0.0.0/8 in tests ([LoopbackPrefixes]), an
	// on-premises identity provider's subnet in production. An address is
	// exempted when it, or the IPv4 address embedded in a 64:ff9b::/96
	// NAT64 address, lies in a prefix. NewClient refuses IPv4-mapped,
	// non-masked and /0 prefixes; a zoned address is never exempted.
	AllowedPrefixes []netip.Prefix

	// CheckURL, when set, is called before any connection with a clone of
	// the canonical URL (host lower-cased) of the initial request and of
	// every redirect hop. A non-nil error refuses the request with
	// [ErrURLNotAllowed]. Use it for host allow-lists and port
	// restrictions.
	CheckURL func(ctx context.Context, u *url.URL) error

	// CheckAddr, when set, is called at connect time with every address
	// about to be dialed, unmapped and unzoned, once the built-in checks
	// accepted it. A non-nil error refuses the connection with
	// [ErrDestinationNotAllowed]: the hook can only restrict.
	CheckAddr func(ctx context.Context, addr netip.AddrPort) error

	// MaxRedirects is the number of redirects followed. Zero, the
	// default, follows none: a redirect fails with [ErrRedirectNotAllowed].
	MaxRedirects int

	// MaxResponseBytes caps every response body, counted after transparent
	// gzip decompression; zero means [DefaultMaxResponseBytes].
	MaxResponseBytes int64

	// Timeout bounds a whole exchange: connection, TLS handshake,
	// redirects and reading the body; zero means [DefaultTimeout]. The
	// dial and the TLS handshake are also bounded by min(Timeout, 5s), the
	// wait for the response headers by min(Timeout, 10s).
	Timeout time.Duration

	// RootCAs replaces the system roots used to verify servers (private
	// PKI, httptest). nil uses the system pool. Certificate verification
	// is never disabled.
	RootCAs *x509.CertPool
}

// NewClient returns an *http.Client enforcing p on every request it sends,
// redirects included. The client has no cookie jar and never uses a proxy:
// the address check would otherwise judge the proxy, not the destination.
// NewClient fails with [ErrInvalidPolicy] when p is unusable. The client is
// safe for concurrent use; build one per policy and reuse it.
func NewClient(p Policy) (*http.Client, error) {
	return newClient(p, nil)
}

// LoopbackPrefixes returns a new slice holding 127.0.0.0/8 and ::1/128, the
// AllowedPrefixes tests and local development need to reach a server on the
// loopback interface.
func LoopbackPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
}

// newClient is NewClient with an injectable resolver, nil meaning the
// default one; tests use it to simulate DNS rebinding.
func newClient(p Policy, resolver *net.Resolver) (*http.Client, error) {
	g, err := newGuard(p)
	if err != nil {
		return nil, err
	}

	timeout := p.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	dialer := &net.Dialer{
		Timeout:        min(timeout, dialTimeout),
		KeepAlive:      keepAlive,
		ControlContext: g.control,
		Resolver:       resolver,
	}

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.RootCAs},
		TLSHandshakeTimeout:    min(timeout, handshakeTimeout),
		ResponseHeaderTimeout:  min(timeout, headerTimeout),
		ExpectContinueTimeout:  expectContinue,
		IdleConnTimeout:        idleConnTimeout,
		MaxIdleConns:           maxIdleConns,
		MaxIdleConnsPerHost:    maxIdleConnsPerHost,
		MaxResponseHeaderBytes: maxHeaderBytes,
		ForceAttemptHTTP2:      true,
	}

	return &http.Client{
		Transport:     &roundTripper{guard: g, next: transport},
		CheckRedirect: g.checkRedirect,
		Timeout:       timeout,
	}, nil
}

// newGuard validates p and freezes it into a guard.
func newGuard(p Policy) (*guard, error) {
	switch {
	case p.MaxRedirects < 0:
		return nil, fmt.Errorf("%w: negative MaxRedirects", ErrInvalidPolicy)
	case p.MaxResponseBytes < 0:
		return nil, fmt.Errorf("%w: negative MaxResponseBytes", ErrInvalidPolicy)
	case p.Timeout < 0:
		return nil, fmt.Errorf("%w: negative Timeout", ErrInvalidPolicy)
	}

	allowed := make([]netip.Prefix, 0, len(p.AllowedPrefixes))

	for _, prefix := range p.AllowedPrefixes {
		if err := validPrefix(prefix); err != nil {
			return nil, err
		}

		allowed = append(allowed, prefix)
	}

	maxBytes := p.MaxResponseBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxResponseBytes
	}

	return &guard{
		allowHTTP:    p.AllowHTTP,
		allowed:      allowed,
		checkURL:     p.CheckURL,
		checkAddr:    p.CheckAddr,
		maxRedirects: p.MaxRedirects,
		maxBytes:     maxBytes,
	}, nil
}

// validPrefix refuses the AllowedPrefixes entries that would silently
// never match (IPv4-mapped: addresses are unmapped before matching), that
// are ambiguous (host bits set) or that disable the guard (/0).
func validPrefix(p netip.Prefix) error {
	switch {
	case !p.IsValid():
		return fmt.Errorf("%w: invalid prefix", ErrInvalidPolicy)
	case p.Addr().Is4In6():
		return fmt.Errorf("%w: IPv4-mapped prefix %s, use the IPv4 form", ErrInvalidPolicy, p)
	case p != p.Masked():
		return fmt.Errorf("%w: prefix %s has host bits set", ErrInvalidPolicy, p)
	case p.Bits() == 0:
		return fmt.Errorf("%w: prefix %s exempts every address", ErrInvalidPolicy, p)
	}

	return nil
}
