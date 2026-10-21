// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"net/netip"
)

// authCtxKey is the private key used to store an [Authentication] in a
// context.Context. The unexported type guarantees that no other package can
// shadow or read the value without going through the accessors below.
type authCtxKey struct{}

// WithAuthentication returns a copy of ctx with auth attached. Subsequent
// calls overwrite the previous value; this is the expected behavior when an
// authenticator promotes an unauthenticated value to an authenticated one.
//
// Passing a nil Authentication — or a typed nil, an interface holding a nil
// pointer — clears the slot: useful for "logout" middlewares.
func WithAuthentication(ctx context.Context, auth Authentication) context.Context {
	return context.WithValue(ctx, authCtxKey{}, auth)
}

// FromContext returns the [Authentication] stored in ctx and a boolean
// indicating whether one was present. When the slot is empty (or holds a
// typed nil), it returns the anonymous authentication (see [Anonymous]) so
// callers can rely on a usable value without a nil check.
func FromContext(ctx context.Context) (Authentication, bool) {
	v, ok := ctx.Value(authCtxKey{}).(Authentication)
	if !ok || isNil(v) {
		return Anonymous(), false
	}

	return v, true
}

// clientAddrCtxKey is the private key of the client address in a
// context.Context.
type clientAddrCtxKey struct{}

// WithClientAddr returns a copy of ctx carrying addr as the address of the
// client the request comes from: the source an [AttemptLimiter] keys on.
// addr is stored unmapped (an IPv4-mapped IPv6 address becomes IPv4) and
// without its zone; the zero Addr records "unknown".
//
// The transport adapters (httpsec, grpcsec, connectrpcsec) store the
// address of the transport peer when the context carries none. Behind a
// reverse proxy every request comes from the proxy: store the client
// address the proxy forwards in a middleware or interceptor that runs
// before the adapter — taken from the hop your trusted proxy appended (the
// right-most entry of X-Forwarded-For it wrote, or the Forwarded field of
// RFC 7239), never the left-most entry, which the client chooses: a client
// choosing its source escapes every per-source allowance.
func WithClientAddr(ctx context.Context, addr netip.Addr) context.Context {
	return context.WithValue(ctx, clientAddrCtxKey{}, addr.Unmap().WithZone(""))
}

// ClientAddrFromContext returns the client address stored in ctx by
// [WithClientAddr], and whether one was stored. A stored zero Addr means
// the address is unknown. Code outside the transport adapters — an OAuth
// 2.0 endpoint — reads the client address the same way, so that one
// middleware serves every verifier: from the context first, then from its
// transport peer ([ParseClientAddr] of r.RemoteAddr).
func ClientAddrFromContext(ctx context.Context) (netip.Addr, bool) {
	addr, ok := ctx.Value(clientAddrCtxKey{}).(netip.Addr)

	return addr, ok
}

// ParseClientAddr parses the address of a transport peer — "host:port" as
// net/http's Request.RemoteAddr, Connect's Peer().Addr and gRPC's
// peer.Addr.String() give it, or a bare IP address — into an unmapped
// address without zone. It returns the zero Addr when s is not an IP
// address: a Unix socket, an in-memory listener, a host name.
func ParseClientAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}

	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().WithZone("")
	}

	return netip.Addr{}
}
