// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// maxResponseOrigins bounds Connection.ResponseOrigins.
const maxResponseOrigins = 8

var errBadOrigin = errors.New(`not a serialized origin: https://host or https://host:port with a ` +
	`lower-case ASCII host and no default port (http only on a loopback host), never "null"`)

// Static details of the ErrOriginMismatch refusals.
const (
	errOriginSeveral = "several Origin headers"
	errOriginNull    = "opaque origin (Origin: null)"
	errOriginOther   = "Origin is not an allowed response origin"
	errOriginNone    = "neither an Origin nor a single Referer"
	errRefererOther  = "Referer is not from an allowed response origin"
)

// validateResponseOrigins checks Connection.ResponseOrigins: at most
// maxResponseOrigins serialized origins.
func validateResponseOrigins(origins []string) error {
	if len(origins) > maxResponseOrigins {
		return fmt.Errorf("%w: at most %d response origins", ErrInvalidConnection, maxResponseOrigins)
	}

	for _, o := range origins {
		if err := validateOrigin(o); err != nil {
			return fmt.Errorf("%w: response origin: %w", ErrInvalidConnection, err)
		}
	}

	return nil
}

// validateOrigin requires the ASCII serialization of an origin (RFC 6454
// §6.2), exactly as a browser sends it in Origin: scheme, lower-case host
// (IPv6 in its canonical bracketed form), and the port only when it is not
// the scheme's default; https, or http on a loopback host. Comparing s with
// the serialization of its own origin refuses everything else: a path, a
// query, a fragment, user info, an upper-case or non-ASCII host, a default
// or zero-padded port.
func validateOrigin(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return errBadOrigin
	}

	origin, ok := serializedOrigin(u)
	if !ok || origin != s || (u.Scheme == schemeHTTP && !isLoopbackHost(u.Hostname())) {
		return errBadOrigin
	}

	return nil
}

// serializedOrigin returns the ASCII serialization of the origin of an
// absolute http(s) URL (RFC 6454 §6.2): lower-case scheme and host, IPv6
// in canonical bracketed form, the port only when it is not the scheme's
// default. It reports false for anything else.
func serializedOrigin(u *url.URL) (string, bool) {
	if (u.Scheme != schemeHTTPS && u.Scheme != schemeHTTP) || u.Hostname() == "" || !isASCII(u.Host) {
		return "", false
	}

	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		ip := net.ParseIP(host)
		if ip == nil {
			return "", false
		}

		host = "[" + ip.String() + "]"
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", false
		}

		port = strconv.FormatUint(n, 10)
	}

	if port == "" || port == defaultPort(u.Scheme) {
		return u.Scheme + "://" + host, true
	}

	return u.Scheme + "://" + host + ":" + port, true
}

// checkResponseOrigin enforces Connection.ResponseOrigins (audit SAML-02):
// the request's Origin (Fetch §3.2) must be one of them; a browser that
// sent no Origin is judged on the origin of its Referer. An opaque origin
// ("null"), several Origin headers, or neither header is refused.
func checkResponseOrigin(r *http.Request, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}

	origins := r.Header.Values("Origin")

	switch {
	case len(origins) > 1:
		return reject(ErrOriginMismatch, errOriginSeveral, nil)
	case len(origins) == 1 && origins[0] == "null":
		return reject(ErrOriginMismatch, errOriginNull, nil)
	case len(origins) == 1 && slices.Contains(allowed, origins[0]):
		return nil
	case len(origins) == 1:
		return reject(ErrOriginMismatch, errOriginOther, nil)
	}

	referers := r.Header.Values("Referer")
	if len(referers) != 1 {
		return reject(ErrOriginMismatch, errOriginNone, nil)
	}

	if u, err := url.Parse(referers[0]); err == nil {
		if origin, ok := serializedOrigin(u); ok && slices.Contains(allowed, origin) {
			return nil
		}
	}

	return reject(ErrOriginMismatch, errRefererOther, nil)
}
