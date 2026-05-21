// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"context"
	"io"
	"net/http"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
)

// bearerHeader builds a request header carrying a Bearer token.
func bearerHeader(token string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)

	return h
}

// newEngine builds an Engine pairing tokenExtractor with tokenAuthenticator,
// minting an authentication carrying the given authorities.
func newEngine(authorities ...string) security.Engine {
	return security.NewEngine(
		security.NewManager(tokenAuthenticator{authorities: authorities}),
		tokenExtractor{},
	)
}

// --- fakes mirroring the core test doubles ------------------------------

type fakePrincipal struct{ sub string }

func (p fakePrincipal) Subject() string { return p.sub }

type fakeAuth struct {
	pr            security.Principal
	authorities   []string
	authenticated bool
}

func newAuth(sub string, authorities ...string) fakeAuth {
	return fakeAuth{pr: fakePrincipal{sub: sub}, authorities: authorities, authenticated: true}
}

func (a fakeAuth) Principal() security.Principal { return a.pr }
func (a fakeAuth) Credentials() any              { return nil }
func (a fakeAuth) Authorities() []string         { return a.authorities }
func (a fakeAuth) IsAuthenticated() bool         { return a.authenticated }
func (a fakeAuth) Name() string                  { return a.pr.Subject() }

// tokenExtractor reads the "authorization" header and produces a pending
// bearer-like authentication carrying the raw token.
type tokenExtractor struct{}

func (tokenExtractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	v := c.Get("authorization")
	if v == "" {
		return nil, nil
	}

	const prefix = "Bearer "
	if len(v) <= len(prefix) {
		return nil, nil
	}

	return pendingAuth{token: v[len(prefix):]}, nil
}

// pendingAuth is the un-validated authentication produced by tokenExtractor.
type pendingAuth struct{ token string }

func (a pendingAuth) Principal() security.Principal { return security.AnonymousPrincipal }
func (a pendingAuth) Credentials() any              { return a.token }
func (a pendingAuth) Authorities() []string         { return nil }
func (a pendingAuth) IsAuthenticated() bool         { return false }
func (a pendingAuth) Name() string                  { return "pending" }

// tokenAuthenticator accepts the magic token "letmein" and rejects the rest.
type tokenAuthenticator struct{ authorities []string }

func (tokenAuthenticator) Supports(a security.Authentication) bool {
	_, ok := a.(pendingAuth)

	return ok
}

func (ta tokenAuthenticator) Authenticate(
	_ context.Context,
	a security.Authentication,
) (security.Authentication, error) {
	p, ok := a.(pendingAuth)
	if !ok {
		return a, security.ErrUnsupportedCredential
	}

	if p.token != "letmein" {
		return a, security.ErrInvalidCredentials
	}

	return newAuth("alice", ta.authorities...), nil
}

// --- ConnectRPC test doubles --------------------------------------------

// fakeStreamingHandlerConn is a controllable connect.StreamingHandlerConn so
// the streaming interceptors can be exercised without a generated service.
type fakeStreamingHandlerConn struct {
	spec    connect.Spec
	reqHdr  http.Header
	respHdr http.Header
	trailer http.Header
}

func newStreamConn(reqHdr http.Header) *fakeStreamingHandlerConn {
	if reqHdr == nil {
		reqHdr = http.Header{}
	}

	return &fakeStreamingHandlerConn{
		spec:    connect.Spec{Procedure: "/test.v1.Service/Stream", StreamType: connect.StreamTypeServer},
		reqHdr:  reqHdr,
		respHdr: http.Header{},
		trailer: http.Header{},
	}
}

func (c *fakeStreamingHandlerConn) Spec() connect.Spec           { return c.spec }
func (c *fakeStreamingHandlerConn) Peer() connect.Peer           { return connect.Peer{} }
func (c *fakeStreamingHandlerConn) Receive(any) error            { return io.EOF }
func (c *fakeStreamingHandlerConn) Send(any) error               { return nil }
func (c *fakeStreamingHandlerConn) RequestHeader() http.Header   { return c.reqHdr }
func (c *fakeStreamingHandlerConn) ResponseHeader() http.Header  { return c.respHdr }
func (c *fakeStreamingHandlerConn) ResponseTrailer() http.Header { return c.trailer }

var _ connect.StreamingHandlerConn = (*fakeStreamingHandlerConn)(nil)

// clientRequest wraps a connect.Request and reports itself as a client-side
// call, so the WrapUnary client-skip branch can be exercised. Embedding the
// real *connect.Request promotes the unexported AnyRequest methods.
type clientRequest struct {
	*connect.Request[struct{}]
}

func (clientRequest) Spec() connect.Spec {
	return connect.Spec{Procedure: "/test.v1.Service/Unary", IsClient: true}
}
