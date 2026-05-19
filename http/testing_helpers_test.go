// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"context"
	"sync/atomic"

	"github.com/hyperscale-stack/security"
)

// fakePrincipal/fakeAuth mirror the helpers used by the core tests; copied
// here to avoid cross-module test imports.
type fakePrincipal struct{ sub string }

func (p fakePrincipal) Subject() string { return p.sub }

type fakeAuth struct {
	pr            security.Principal
	creds         any
	authorities   []string
	authenticated bool
}

func newAuth(sub string, authorities ...string) fakeAuth {
	return fakeAuth{pr: fakePrincipal{sub: sub}, authorities: authorities}
}

func (a fakeAuth) Principal() security.Principal { return a.pr }
func (a fakeAuth) Credentials() any              { return a.creds }
func (a fakeAuth) Authorities() []string         { return a.authorities }
func (a fakeAuth) IsAuthenticated() bool         { return a.authenticated }
func (a fakeAuth) Name() string                  { return a.pr.Subject() }

func (a fakeAuth) verified() fakeAuth { a.authenticated = true; return a }

// scriptedExtractor returns a fixed (auth, err) tuple.
type scriptedExtractor struct {
	auth security.Authentication
	err  error
}

func (s scriptedExtractor) Extract(_ context.Context, _ security.Carrier) (security.Authentication, error) {
	return s.auth, s.err
}

// scriptedAuthn validates by returning the configured result with race-safe
// invocation counter.
type scriptedAuthn struct {
	name   string
	result security.Authentication
	err    error
	calls  atomic.Int32
}

func (s *scriptedAuthn) AuthenticatorName() string         { return s.name }
func (s *scriptedAuthn) Supports(security.Authentication) bool { return true }
func (s *scriptedAuthn) Authenticate(_ context.Context, _ security.Authentication) (security.Authentication, error) {
	s.calls.Add(1)

	return s.result, s.err
}

// scriptedADM lets tests force a verdict without running real voters.
type scriptedADM struct {
	err error
}

func (s scriptedADM) Decide(_ context.Context, _ security.Authentication, _ []security.Attribute) error {
	return s.err
}

// fakeAttr is the smallest Attribute implementation.
type fakeAttr string

func (a fakeAttr) String() string { return string(a) }
