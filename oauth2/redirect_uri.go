// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// ErrInvalidRedirectURI is wrapped by every [ValidateRedirectURI] refusal.
// It is the cause the [ErrorHook] gets when /authorize meets a registered
// redirect URI the rules refuse: the request is then answered with a bare
// 400, never redirected (RFC 6749 §3.1.2.4).
var ErrInvalidRedirectURI = errors.New("oauth2: invalid redirect URI")

// reservedRedirectParameters are the authorization response parameters the
// server adds to the query of a redirect URI (RFC 6749 §4.1.2, §4.1.2.1;
// RFC 9207 §2): a registered query naming one would carry it twice (RFC
// 6749 §3.1).
var reservedRedirectParameters = []string{paramCode, paramState, "iss", "error", "error_description", "error_uri"}

// ValidateRedirectURI reports whether uri may be registered as a redirect
// URI, wrapping [ErrInvalidRedirectURI] with the reason when it may not.
// Call it when registering a client; [Server.AuthorizeHandler] applies it to
// the registered URI a request resolves to as well. The rules:
//
//   - an absolute URI (RFC 6749 §3.1.2: "MUST be an absolute URI", RFC 3986
//     §4.3) made of RFC 3986 characters, its percent-encodings valid;
//   - no fragment, not even an empty one (RFC 6749 §3.1.2: "MUST NOT include
//     a fragment component");
//   - for http and https, a host, no userinfo and, when present, a port
//     within 1–65535 — TLS is not required (RFC 6749 §3.1.2.1 SHOULD;
//     http://localhost serves development);
//   - for any other scheme — the private-use scheme of a native app — a
//     scheme holding a "." (RFC 8252 §7.1: a reverse domain name; §8.4:
//     "any private-use URI scheme that doesn't contain a period character
//     SHOULD be rejected"), which also refuses javascript:, data:,
//     vbscript:, file: and a bare myapp:;
//   - a query, kept as registered when the response is added (RFC 6749
//     §3.1.2), naming — split on "&" and ";" — none of the parameters the
//     server adds: code, state, iss, error, error_description, error_uri
//     (RFC 6749 §3.1: no parameter twice).
func ValidateRedirectURI(uri string) error {
	if reason := redirectURISyntax(uri); reason != "" {
		return fmt.Errorf("%w: %s", ErrInvalidRedirectURI, reason)
	}

	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRedirectURI, err)
	}

	if reason := redirectURIParts(u); reason != "" {
		return fmt.Errorf("%w: %s", ErrInvalidRedirectURI, reason)
	}

	return nil
}

// redirectURISyntax returns why uri is not made of RFC 3986 characters
// without fragment, or "".
func redirectURISyntax(uri string) string {
	switch {
	case uri == "":
		return "empty"
	case strings.Contains(uri, "#"):
		return "it has a fragment"
	}

	for i := 0; i < len(uri); i++ {
		switch c := uri[i]; {
		case c == '%':
			if i+2 >= len(uri) || !isHexDigit(uri[i+1]) || !isHexDigit(uri[i+2]) {
				return "an invalid percent-encoding"
			}

			i += 2
		case !isURIChar(c):
			return "a character outside RFC 3986"
		}
	}

	return ""
}

// redirectURIParts returns why the parsed URI u breaks the scheme, host or
// query rules, or "".
func redirectURIParts(u *url.URL) string {
	switch u.Scheme {
	case "":
		return "not an absolute URI"
	case "http", "https":
		// Hostname, not Host: "http://:80/cb" has an authority, no host
		// (RFC 9110 §4.2.1: such a URI MUST be rejected as invalid).
		if u.Hostname() == "" {
			return "no host"
		}

		if u.User != nil {
			return "userinfo"
		}

		if port := u.Port(); port != "" && !inPortRange(port) {
			return "a port outside 1-65535"
		}
	default:
		if !strings.Contains(u.Scheme, ".") {
			return "a private-use scheme without a period (RFC 8252 §7.1)"
		}
	}

	for field := range strings.FieldsFuncSeq(u.RawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		name, _, _ := strings.Cut(field, "=")

		if name, err := url.QueryUnescape(name); err == nil && slices.Contains(reservedRedirectParameters, name) {
			return "its query names an authorization response parameter"
		}
	}

	return ""
}

// inPortRange reports whether the decimal port is a TCP port a URI may name:
// 1 to 65535 (0 is reserved, RFC 6335 §6).
func inPortRange(port string) bool {
	n, err := strconv.Atoi(port)

	return err == nil && n >= 1 && n <= 65535
}

// isURIChar reports whether c may appear, unencoded, in an RFC 3986 URI:
// unreserved (ALPHA DIGIT - . _ ~) or reserved (gen-delims and sub-delims).
func isURIChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	default:
		return strings.IndexByte("-._~:/?#[]@!$&'()*+,;=", c) >= 0
	}
}

// isHexDigit reports whether c is an RFC 3986 HEXDIG.
func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// errUnregisteredRedirectURI is the cause of a request naming no redirect
// URI the client registered — or none at all, for a client registering
// several.
var errUnregisteredRedirectURI = errors.New("oauth2: missing or unregistered redirect_uri")

// resolveRedirectURI returns the redirect URI of a request: the requested
// one when it exactly matches a registered URI (RFC 6749 §3.1.2.3: simple
// string comparison) or a registered loopback IP redirect URI but for the
// port (RFC 8252 §7.3), or the sole registered URI when the request omitted
// the parameter. The registered URI it rests on must pass
// [ValidateRedirectURI]: an invalid one is never redirected to.
func resolveRedirectURI(client Client, requested string) (string, error) {
	registered := client.RedirectURIs()

	var used, resolved string

	switch {
	case requested == "":
		if len(registered) != 1 {
			return "", errUnregisteredRedirectURI
		}

		used, resolved = registered[0], registered[0]
	case slices.Contains(registered, requested):
		used, resolved = requested, requested
	default:
		i := slices.IndexFunc(registered, func(r string) bool { return loopbackRedirect(r, requested) })
		if i < 0 {
			return "", errUnregisteredRedirectURI
		}

		used, resolved = registered[i], requested
	}

	if err := ValidateRedirectURI(used); err != nil {
		return "", err
	}

	return resolved, nil
}

// loopbackRedirect reports whether requested is the loopback IP redirect
// URI registered but for its port: RFC 8252 §7.3 — "The authorization
// server MUST allow any port to be specified at the time of the request for
// loopback IP redirect URIs" — and RFC 9700 §2.1, the one exception to
// exact matching. Both URIs use http and the IP literal 127.0.0.1 or [::1]
// (localhost gets no variance, RFC 8252 §8.3), any port being a decimal
// number from 1 to 65535 without a leading zero, and they are byte-for-byte
// equal once the port of each authority is removed — path, query and
// fragment included.
func loopbackRedirect(registered, requested string) bool {
	regHost, regRest, ok := loopbackParts(registered)
	if !ok {
		return false
	}

	reqHost, reqRest, ok := loopbackParts(requested)

	return ok && regHost == reqHost && regRest == reqRest
}

// loopbackParts splits a loopback IP redirect URI — "http://", 127.0.0.1 or
// [::1], an optional valid port, then the rest — into its host and the rest
// that follows the authority, and reports whether uri is one.
func loopbackParts(uri string) (string, string, bool) {
	const scheme = "http://"

	if !strings.HasPrefix(uri, scheme) {
		return "", "", false
	}

	authority, rest := uri[len(scheme):], ""
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority, rest = authority[:i], authority[i:]
	}

	for _, host := range []string{"127.0.0.1", "[::1]"} {
		if port, ok := strings.CutPrefix(authority, host); ok && (port == "" || validPort(port)) {
			return host, rest, true
		}
	}

	return "", "", false
}

// validPort reports whether p is ":" and a port from 1 to 65535 written
// without a leading zero.
func validPort(p string) bool {
	digits, ok := strings.CutPrefix(p, ":")
	if !ok || digits == "" || len(digits) > 5 || digits[0] == '0' {
		return false
	}

	n := 0

	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}

		n = n*10 + int(digits[i]-'0')
	}

	return n <= 65535
}
