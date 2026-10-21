// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// ErrInvalidIssuer reports an issuer identifier the server cannot use: not
// an https URL — or, with [ServerConfig.AllowInsecureLoopbackIssuer], an
// http URL whose host is localhost or a loopback IP address — with a host,
// without user info, query or fragment, with a port from 1 to 65535 when it
// names one, in the form Go's net/url writes it (RFC 8414 §2: "a URL that
// uses the "https" scheme and has no query or fragment components"; RFC
// 9207 §2). [NewServer] wraps it for a [StaticIssuer]; an [IssuerResolver]
// returning such an issuer fails the request as an outage, with
// ErrInvalidIssuer as the cause the [ErrorHook] gets. The reason it carries
// never echoes the issuer.
//
// Spellings RFC 3986 §6.2 holds equivalent but net/url keeps as written —
// an upper-case host, the default port (":443"), a port with a leading zero,
// dot segments, a zone in an IPv6 loopback literal — are accepted and
// published as given: clients compare iss by simple string (RFC 9207 §2.4),
// and one normalizing the URL first would then reject every response. Use
// the RFC 3986 §6.2.2 normal form: lower-case host, no default port, no dot
// segment.
var ErrInvalidIssuer = errors.New("oauth2: invalid issuer identifier")

// IssuerResolver returns the issuer identifier (and matching audience) for
// the request being processed. The interface lets multi-tenant deployments
// dispatch on the Host header or a routing prefix without baking the
// tenant into every grant handler.
//
// The issuer is the realm of a grant: /authorize records it with the
// authorization code, and every token records it; the authorization_code
// and refresh_token grants refuse, with invalid_grant, a code or refresh
// token issued under another issuer than the one resolved for the /token
// request (OIDC Core §16.15: a subject is only meaningful within its
// issuer). A resolver MUST therefore return the same issuer for every
// request of one realm — /authorize, /token, /revoke, /introspect — and
// issuers are compared exactly. Changing an issuer invalidates the
// outstanding codes and refresh tokens issued under the former one.
//
// The issuer is also the iss parameter of every authorization response
// (RFC 9207 §2) and the issuer of the metadata document (RFC 8414 §2): the
// server validates it on every request — an https URL without user info,
// query or fragment, in canonical form; http on a loopback host only with
// [ServerConfig.AllowInsecureLoopbackIssuer] (see [ErrInvalidIssuer]). A
// resolver error, or an issuer the server cannot use, is an outage, never
// an answer naming another issuer or none: a bare 500 at /authorize — never
// redirected, no client loaded —, server_error at /token, /introspect and
// the metadata, 503 temporarily_unavailable at /revoke. Clients registered
// at some issuers only ([IssuerBoundClient]) are checked against the issuer
// returned. A resolver MUST NOT derive the issuer from an unvalidated Host
// header.
type IssuerResolver interface {
	Resolve(ctx context.Context, r *http.Request) (issuer, audience string, err error)
}

// StaticIssuer returns an [IssuerResolver] that always returns the
// configured (issuer, audience) pair. The canonical single-tenant setup:
// [NewServer] refuses an issuer it could not publish ([ErrInvalidIssuer]).
func StaticIssuer(issuer, audience string) IssuerResolver {
	return staticIssuer{issuer: issuer, audience: audience}
}

type staticIssuer struct {
	issuer   string
	audience string
}

// Resolve implements [IssuerResolver].
func (s staticIssuer) Resolve(context.Context, *http.Request) (string, string, error) {
	return s.issuer, s.audience, nil
}

// checkIssuer returns why issuer is not an issuer identifier the server may
// publish (ErrInvalidIssuer), or nil: an https URL — http too when
// allowLoopbackHTTP is set and the host is localhost or a loopback IP
// address — then issuerParts. The rules are oidc/provider's, so an OpenID
// Connect deployment meets one definition, plus a valid port.
func checkIssuer(issuer string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%w: not a URL", ErrInvalidIssuer)
	}

	switch {
	case u.Scheme == schemeHTTPS:
	case u.Scheme == schemeHTTP && allowLoopbackHTTP && loopbackHost(u.Hostname()):
	default:
		return fmt.Errorf("%w: not an https URL", ErrInvalidIssuer)
	}

	if reason := issuerParts(u, issuer); reason != "" {
		return fmt.Errorf("%w: %s", ErrInvalidIssuer, reason)
	}

	return nil
}

// issuerParts returns why the parsed issuer u breaks the host, user info,
// port, query, fragment or canonical-form rules, or "".
func issuerParts(u *url.URL, issuer string) string {
	switch {
	case u.Host == "":
		return reasonNoHost
	case u.User != nil:
		return "user info"
	case strings.HasSuffix(u.Host, ":"), u.Port() != "" && !inPortRange(u.Port()):
		return "an empty port or one outside 1-65535"
	case u.RawQuery != "" || u.ForceQuery:
		return "a query component"
	case u.Fragment != "":
		return "a fragment component"
	case u.String() != issuer:
		// Issuers are compared exactly (RFC 9207 §2.4): a value Go's URL
		// syntax rewrites — an upper-case scheme, an unescaped character,
		// an empty query or fragment ("…/?", "…/#") — is refused rather
		// than published in two forms. Forms net/url keeps as written are
		// not caught (see ErrInvalidIssuer).
		return "not in canonical form"
	default:
		return ""
	}
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
