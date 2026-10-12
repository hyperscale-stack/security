// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package outbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Hostname limits (RFC 1035 §2.3.4).
const (
	maxHostnameLength = 253
	maxLabelLength    = 63
)

// URL schemes.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// roundTripper checks every request URL, the initial one and each redirect
// hop, before handing it to the transport, and caps every response body.
type roundTripper struct {
	guard *guard
	next  http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.guard.checkRequestURL(req.Context(), req.URL); err != nil {
		if req.Body != nil {
			_ = req.Body.Close() // RoundTrip must close the body, even on error
		}

		return nil, err
	}

	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("outbound: %w", err)
	}

	if resp.ContentLength > t.guard.maxBytes {
		_ = resp.Body.Close()

		return nil, fmt.Errorf("%w: announced %d bytes, limit %d", ErrResponseTooLarge, resp.ContentLength, t.guard.maxBytes)
	}

	resp.Body = &limitedBody{body: resp.Body, remaining: t.guard.maxBytes}

	return resp, nil
}

// checkRedirect is the http.Client.CheckRedirect hook: it bounds the
// number of hops and refuses a downgrade from https. The URL of the next hop
// is then checked by the round tripper like any request.
func (g *guard) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > g.maxRedirects {
		return fmt.Errorf("%w: more than %d", ErrRedirectNotAllowed, g.maxRedirects)
	}

	if via[len(via)-1].URL.Scheme == schemeHTTPS && req.URL.Scheme != schemeHTTPS {
		return fmt.Errorf("%w: https to %s", ErrRedirectNotAllowed, req.URL.Scheme)
	}

	return nil
}

// checkRequestURL refuses a URL the policy does not allow, then hands a
// canonical clone to the application's CheckURL hook.
func (g *guard) checkRequestURL(ctx context.Context, u *url.URL) error {
	switch {
	case u.Scheme == schemeHTTPS:
	case u.Scheme == schemeHTTP && g.allowHTTP:
	default:
		return fmt.Errorf("%w: scheme %q", ErrURLNotAllowed, u.Scheme)
	}

	if u.User != nil {
		return fmt.Errorf("%w: userinfo", ErrURLNotAllowed)
	}

	host, err := canonicalHost(u.Hostname())
	if err != nil {
		return err
	}

	port := u.Port()
	if err := checkPort(port); err != nil {
		return err
	}

	if g.checkURL == nil {
		return nil
	}

	clone := *u
	clone.Host = joinHostPort(host, port)

	if err := g.checkURL(ctx, &clone); err != nil {
		return fmt.Errorf("%w: %w", ErrURLNotAllowed, err)
	}

	return nil
}

// canonicalHost validates a URL host and returns its canonical form: an IP
// literal without a zone, or a lower-cased ASCII host name made of
// letter-digit-hyphen labels (RFC 1123 §2.1). Non-ASCII names (U-labels,
// which net/http would map to another name before dialing),
// percent-encoded or underscore characters, empty labels, a trailing dot
// and a name ending in a number (which a resolver reads as an IPv4
// address) are refused: the name the application vets in CheckURL must be
// the name dialed.
func canonicalHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("%w: missing host", ErrURLNotAllowed)
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", fmt.Errorf("%w: scoped address literal", ErrURLNotAllowed)
		}

		return addr.String(), nil
	}

	if len(host) > maxHostnameLength {
		return "", fmt.Errorf("%w: host name too long", ErrURLNotAllowed)
	}

	for label := range strings.SplitSeq(host, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("%w: malformed host name", ErrURLNotAllowed)
		}
	}

	if endsInNumber(host) {
		return "", fmt.Errorf("%w: numeric host name", ErrURLNotAllowed)
	}

	return strings.ToLower(host), nil
}

// endsInNumber reports whether the last label of a host name is a number:
// decimal digits, or "0x" or "0X" followed by hexadecimal digits. The
// WHATWG URL parser then reads the whole name as an IPv4 address, and so
// do libc resolvers (127.1, 2130706433, 0x7f.1 and 0177.0.0.1 all reach
// 127.0.0.1); no top-level domain is numeric. A canonical dotted-quad
// address never gets here: it is an IP literal.
func endsInNumber(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]

	digits := "0123456789"
	if len(last) >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X') {
		last, digits = last[2:], "0123456789abcdefABCDEF"
	}

	for i := range len(last) {
		if !strings.ContainsRune(digits, rune(last[i])) {
			return false
		}
	}

	return true
}

// validLabel reports whether label is an RFC 1123 host-name label: 1 to 63
// ASCII letters, digits or hyphens, not starting or ending with a hyphen.
func validLabel(label string) bool {
	if label == "" || len(label) > maxLabelLength || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for i := range len(label) {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}

	return true
}

// checkPort refuses a port outside 1–65535; an empty port is the scheme's
// default.
func checkPort(port string) error {
	if port == "" {
		return nil
	}

	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: invalid port", ErrURLNotAllowed)
	}

	return nil
}

// joinHostPort rebuilds a URL host from a canonical host and an optional
// port, bracketing IPv6 literals.
func joinHostPort(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}

	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}

	return host
}

// limitedBody hands at most remaining bytes to the caller and fails with
// ErrResponseTooLarge as soon as the body proves longer.
type limitedBody struct {
	body      io.ReadCloser
	remaining int64
	exceeded  bool
}

// Read implements io.Reader. It reads one byte past the limit to tell a
// body of exactly the limit from a longer one.
func (b *limitedBody) Read(p []byte) (int, error) {
	if b.exceeded {
		return 0, ErrResponseTooLarge
	}

	if int64(len(p)) > b.remaining {
		p = p[:b.remaining+1]
	}

	n, err := b.body.Read(p)
	if int64(n) > b.remaining {
		b.exceeded = true
		n = int(b.remaining)
		b.remaining = 0

		return n, ErrResponseTooLarge
	}

	b.remaining -= int64(n)

	return n, err //nolint:wrapcheck // io.Reader contract: io.EOF must be returned as is
}

// Close implements io.Closer.
func (b *limitedBody) Close() error {
	return b.body.Close() //nolint:wrapcheck // transparent wrapper around the response body
}
