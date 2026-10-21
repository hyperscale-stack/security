// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package outbound builds the *http.Client values the security modules use
// for server-side requests to URLs that come from configuration or from
// remote metadata: OpenID Connect discovery documents and JWK Sets, token
// and UserInfo endpoints, SAML metadata. Such URLs are often supplied by a
// tenant or by a remote party, so they must not let the server reach its
// own network (server-side request forgery).
//
// The zero [Policy] is the strictest one:
//
//   - https only; http is a development opt-in, and an https→http redirect
//     is always refused;
//   - publicly routable destinations only: the address actually connected
//     to — after DNS resolution, in net.Dialer.ControlContext — is refused
//     when it is loopback, private (RFC 1918, RFC 4193), shared (RFC 6598),
//     link-local (cloud metadata endpoints), multicast, unspecified,
//     reserved, documentation or benchmarking space, judged on the IPv4
//     address an IPv4-mapped or NAT64 (64:ff9b::/96) address carries, or
//     scoped (zoned); an ISATAP address (RFC 5214 §6.1), which tunnels to
//     the IPv4 address it embeds, is refused from any prefix. Checking the dialed address defeats DNS rebinding.
//     IPv4 is a deny-list of the IANA special-purpose registry (RFC 6890);
//     IPv6 is an allow-list of 2000::/3 minus its special-purpose blocks;
//   - host names must be ASCII, are compared lower-cased, and may not end
//     with a dot or in a number (127.1, 0x7f.1, which a resolver reads as
//     an IPv4 address), so an application host check sees the name
//     dialed;
//   - no redirect is followed; no proxy is used; no cookie is stored;
//   - DefaultTimeout for the whole exchange, DefaultMaxResponseBytes per
//     body (after transparent decompression, which defuses gzip bombs);
//   - TLS 1.2 or later, certificates verified against the system roots.
//
// Applications widen the policy explicitly — AllowedPrefixes for an
// on-premises identity provider or the loopback interface in tests,
// AllowHTTP for local development, MaxRedirects — and narrow it with the
// CheckURL (host allow-lists; it sees canonical ports) and CheckAddr (port
// and address policy on the numeric address dialed) hooks. Only the
// well-known NAT64 prefix is decoded: on a network translating a
// network-specific prefix (RFC 6052), refuse that prefix in CheckAddr.
//
// A dial error names neither the address dialed nor the resolver; an error
// after the connection may name the address. Show tenants a generic
// message.
//
// The package depends on the standard library only; it is the only
// networking code of the core module.
package outbound
