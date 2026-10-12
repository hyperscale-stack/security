// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
)

// parseIssuer validates the issuer identifier issuer (OpenID Connect Core
// §2, Discovery §3, RFC 9207 §2): an https URL — or, with
// AllowInsecureLoopbackIssuer, an http URL whose host is exactly localhost
// or a loopback address — with a host, without user info, query or
// fragment, and in canonical form: issuers are compared exactly, character
// by character (Core §14, Discovery §4.3), so a value the URL syntax would
// rewrite is refused rather than published in two forms.
func (p *Provider) parseIssuer(issuer string) (*url.URL, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: not a URL", ErrInvalidIssuer)
	}

	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && p.cfg.AllowInsecureLoopbackIssuer && loopbackHost(u.Hostname()):
	default:
		return nil, fmt.Errorf("%w: not an https URL", ErrInvalidIssuer)
	}

	switch {
	case u.Host == "", u.Opaque != "":
		return nil, fmt.Errorf("%w: no host", ErrInvalidIssuer)
	case u.User != nil:
		return nil, fmt.Errorf("%w: user info", ErrInvalidIssuer)
	case u.RawQuery != "" || u.ForceQuery:
		return nil, fmt.Errorf("%w: query component", ErrInvalidIssuer)
	case u.Fragment != "":
		return nil, fmt.Errorf("%w: fragment component", ErrInvalidIssuer)
	case u.String() != issuer:
		// Also refuses an empty query or fragment ("…/?", "…/#") the
		// parsed URL drops.
		return nil, fmt.Errorf("%w: not in canonical form", ErrInvalidIssuer)
	}

	return u, nil
}

// loopbackHost reports whether host is exactly "localhost" or a loopback IP
// address — never a name merely starting or ending like one.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}

	ip, err := netip.ParseAddr(host)

	return err == nil && ip.Unmap().IsLoopback()
}

// resolveIssuer returns the issuer the server's IssuerResolver resolves for
// r, validated.
func (p *Provider) resolveIssuer(r *http.Request) (string, error) {
	issuer, _, err := p.server.Config().IssuerResolver.Resolve(r.Context(), r)
	if err != nil {
		return "", fmt.Errorf("oidcprovider: resolve issuer: %w", err)
	}

	if _, err := p.parseIssuer(issuer); err != nil {
		return "", err
	}

	return issuer, nil
}
