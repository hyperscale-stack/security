// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package voter_test

import "github.com/hyperscale-stack/security"

// fakePrincipal / fakeAuth mirror the minimal Principal+Authentication used
// across other packages' test suites.
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

func newAnonymous() fakeAuth {
	return fakeAuth{pr: security.AnonymousPrincipal}
}

func (a fakeAuth) Principal() security.Principal { return a.pr }
func (a fakeAuth) Credentials() any              { return nil }
func (a fakeAuth) Authorities() []string         { return a.authorities }
func (a fakeAuth) IsAuthenticated() bool         { return a.authenticated }
func (a fakeAuth) Name() string                  { return a.pr.Subject() }
