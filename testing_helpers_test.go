// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"net/textproto"
	"strings"
	"sync/atomic"

	"github.com/hyperscale-stack/security"
)

// fakePrincipal is a minimal Principal used across core tests.
type fakePrincipal struct{ subject string }

func (p fakePrincipal) Subject() string { return p.subject }

// fakeAuthentication is a minimal, immutable Authentication used by tests.
// Each "mutation" returns a new value.
type fakeAuthentication struct {
	principal     security.Principal
	credentials   any
	authorities   []string
	authenticated bool
	name          string
}

func newFakeAuth(subject string, authorities ...string) fakeAuthentication {
	return fakeAuthentication{
		principal:   fakePrincipal{subject: subject},
		authorities: authorities,
		name:        subject,
	}
}

func (a fakeAuthentication) Principal() Principal { //nolint:revive,unused-receiver
	return a.principal
}

// Reproduce Authentication interface using the exported alias below so test
// helpers do not need to import the package on every line.

type (
	// Principal/Authentication aliases keep the test file readable.
	Principal      = security.Principal
	Authentication = security.Authentication
)

func (a fakeAuthentication) Credentials() any     { return a.credentials }
func (a fakeAuthentication) Authorities() []string { return a.authorities }
func (a fakeAuthentication) IsAuthenticated() bool { return a.authenticated }
func (a fakeAuthentication) Name() string          { return a.name }

func (a fakeAuthentication) withAuthenticated() fakeAuthentication {
	a.authenticated = true

	return a
}

func (a fakeAuthentication) withCredentials(c any) fakeAuthentication {
	a.credentials = c

	return a
}

// mapCarrier is a hash-backed [Carrier] used by tests. Keys are normalised
// using textproto.CanonicalMIMEHeaderKey to mirror HTTP semantics.
type mapCarrier struct {
	values map[string][]string
}

func newMapCarrier() *mapCarrier {
	return &mapCarrier{values: make(map[string][]string)}
}

func (c *mapCarrier) key(k string) string { return textproto.CanonicalMIMEHeaderKey(k) }

func (c *mapCarrier) Get(k string) string {
	vs := c.values[c.key(k)]
	if len(vs) == 0 {
		return ""
	}

	return vs[0]
}

func (c *mapCarrier) Values(k string) []string {
	vs := c.values[c.key(k)]
	if vs == nil {
		return nil
	}

	out := make([]string, len(vs))
	copy(out, vs)

	return out
}

func (c *mapCarrier) Set(k, v string) { c.values[c.key(k)] = []string{v} }
func (c *mapCarrier) Add(k, v string) {
	ck := c.key(k)
	c.values[ck] = append(c.values[ck], v)
}

// scriptedExtractor returns a pre-recorded (auth, err) tuple on every call,
// useful for asserting Engine wiring.
type scriptedExtractor struct {
	auth Authentication
	err  error
}

func (s scriptedExtractor) Extract(_ context.Context, _ security.Carrier) (Authentication, error) {
	return s.auth, s.err
}

// countingExtractor records how many times Extract was called and proxies to
// an underlying scripted result.
type countingExtractor struct {
	scripted scriptedExtractor
	calls    int
}

func (c *countingExtractor) Extract(ctx context.Context, car security.Carrier) (Authentication, error) {
	c.calls++

	return c.scripted.Extract(ctx, car)
}

// scriptedAuthenticator validates by returning the configured result. It
// supports filtering via the supports closure. Race-safe via atomic counter.
type scriptedAuthenticator struct {
	name     string
	supports func(Authentication) bool
	result   Authentication
	err      error
	callsN   atomic.Int32
}

func (s *scriptedAuthenticator) AuthenticatorName() string { return s.name }

func (s *scriptedAuthenticator) Supports(a Authentication) bool {
	if s.supports == nil {
		return true
	}

	return s.supports(a)
}

func (s *scriptedAuthenticator) Authenticate(_ context.Context, _ Authentication) (Authentication, error) {
	s.callsN.Add(1)

	return s.result, s.err
}

func (s *scriptedAuthenticator) calls() int { return int(s.callsN.Load()) }

// scriptedVoter returns a fixed verdict; Supports matches when the attribute
// has the given prefix (e.g. "scope:read").
type scriptedVoter struct {
	prefix string
	vote   security.Decision
	calls  int
}

func (s *scriptedVoter) Supports(a security.Attribute) bool {
	return strings.HasPrefix(a.String(), s.prefix)
}

func (s *scriptedVoter) Vote(_ context.Context, _ Authentication, _ []security.Attribute) security.Decision {
	s.calls++

	return s.vote
}

// stringAttr is the smallest possible Attribute implementation.
type stringAttr string

func (s stringAttr) String() string { return string(s) }
