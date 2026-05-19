// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security"
)

// userAuth is an example concrete Authentication produced by a fictional
// authenticator. The point of this example is the Engine wiring, so the type
// is kept minimal.
type userAuth struct {
	sub         string
	roles       []string
	credentials string
	verified    bool
}

func (u userAuth) Principal() security.Principal { return userPrincipal{sub: u.sub} }
func (u userAuth) Credentials() any              { return u.credentials }
func (u userAuth) Authorities() []string         { return u.roles }
func (u userAuth) IsAuthenticated() bool         { return u.verified }
func (u userAuth) Name() string                  { return u.sub }

type userPrincipal struct{ sub string }

func (p userPrincipal) Subject() string { return p.sub }

// staticExtractor returns a fixed userAuth when the "X-Demo-User" header is
// set, and (nil, nil) otherwise.
type staticExtractor struct{}

func (staticExtractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	sub := c.Get("X-Demo-User")
	if sub == "" {
		return nil, nil
	}

	return userAuth{sub: sub, credentials: "password"}, nil
}

// staticAuthenticator accepts only "alice" / "password".
type staticAuthenticator struct{}

func (staticAuthenticator) AuthenticatorName() string                  { return "static" }
func (staticAuthenticator) Supports(_ security.Authentication) bool    { return true }
func (staticAuthenticator) Authenticate(_ context.Context, a security.Authentication) (security.Authentication, error) {
	u, ok := a.(userAuth)
	if !ok {
		return a, security.ErrUnsupportedCredential
	}

	if u.sub != "alice" || u.credentials != "password" {
		return a, security.ErrInvalidCredentials
	}

	u.roles = []string{"ROLE_USER"}
	u.verified = true

	return u, nil
}

// demoCarrier is a tiny Carrier used to drive the example without depending
// on the http sub-module.
type demoCarrier struct{ headers map[string]string }

func (c *demoCarrier) Get(k string) string         { return c.headers[k] }
func (c *demoCarrier) Values(k string) []string    { return []string{c.headers[k]} }
func (c *demoCarrier) Set(k, v string)             { c.headers[k] = v }
func (c *demoCarrier) Add(k, v string)             { c.headers[k] = v }

// roleVoter implements [security.Voter] for the example. It supports any
// attribute string starting with "role:" and grants when the principal has
// the matching role.
type roleVoter struct{}

func (roleVoter) Supports(a security.Attribute) bool {
	if a == nil {
		return false
	}
	const prefix = "role:"
	if len(a.String()) < len(prefix) {
		return false
	}

	return a.String()[:len(prefix)] == prefix
}

func (roleVoter) Vote(_ context.Context, auth security.Authentication, attrs []security.Attribute) security.Decision {
	for _, a := range attrs {
		const prefix = "role:"
		if len(a.String()) < len(prefix) || a.String()[:len(prefix)] != prefix {
			continue
		}

		want := a.String()[len(prefix):]
		for _, r := range auth.Authorities() {
			if r == want {
				return security.DecisionGrant
			}
		}
	}

	return security.DecisionDeny
}

type roleAttr string

func (r roleAttr) String() string { return "role:" + string(r) }

// Example_engine shows the canonical pipeline: extractor -> authenticator
// orchestrated by the Engine, ending with an AccessDecisionManager.
func Example_engine() {
	engine := security.NewEngine(
		security.NewManager(staticAuthenticator{}),
		staticExtractor{},
	)

	carrier := &demoCarrier{headers: map[string]string{"X-Demo-User": "alice"}}

	ctx, auth, err := engine.Process(context.Background(), carrier)
	if err != nil {
		fmt.Println("auth error:", err)

		return
	}

	fmt.Printf("authenticated=%t subject=%s\n", auth.IsAuthenticated(), auth.Principal().Subject())

	adm := security.NewAffirmativeDecisionManager(roleVoter{})
	if err := adm.Decide(ctx, auth, []security.Attribute{roleAttr("ROLE_USER")}); err != nil {
		fmt.Println("denied:", err)

		return
	}

	fmt.Println("granted")
	// Output:
	// authenticated=true subject=alice
	// granted
}

// ExampleNewManager illustrates first-success-wins semantics.
func ExampleNewManager() {
	first := security.AuthenticatorFunc(func(_ context.Context, a security.Authentication) (security.Authentication, error) {
		return a, errors.New("first refuses")
	})
	second := security.AuthenticatorFunc(func(_ context.Context, a security.Authentication) (security.Authentication, error) {
		return userAuth{sub: "bob", verified: true}, nil
	})

	m := security.NewManager(first, second)

	auth, err := m.Authenticate(context.Background(), userAuth{sub: "bob"})
	fmt.Println(auth.Name(), err)
	// Output:
	// bob <nil>
}
