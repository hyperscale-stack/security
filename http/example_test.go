// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
)

// ExampleMiddleware shows wiring a [security.Engine] into a net/http server
// with a header-based extractor and a stub authenticator that hands back an
// authenticated value when the magic token is presented.
func ExampleMiddleware() {
	extractor := exExtractor{}
	authn := exAuthn{}

	engine := security.NewEngine(security.NewManager(authn), extractor)

	handler := httpsec.Middleware(engine, httpsec.WithRealm("demo"))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth, _ := security.FromContext(r.Context())
			_, _ = fmt.Fprintf(w, "hello %s\n", auth.Principal().Subject())
		}),
	)

	for _, token := range []string{"", "bad", "letmein"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		body, _ := io.ReadAll(rec.Result().Body)
		_ = rec.Result().Body.Close()
		fmt.Printf("status=%d body=%s\n", rec.Result().StatusCode, strings.TrimSpace(string(body)))
	}
	// Output:
	// status=401 body=Unauthorized
	// status=401 body=Unauthorized
	// status=200 body=hello alice
}

type exExtractor struct{}

func (exExtractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	v := c.Get("Authorization")
	if v == "" {
		return nil, nil
	}

	tok, ok := httpsec.ExtractAuthorizationValue("Bearer", v)
	if !ok {
		return nil, nil
	}

	return demoAuth{token: tok}, nil
}

type exAuthn struct{}

func (exAuthn) Supports(a security.Authentication) bool {
	_, ok := a.(demoAuth)

	return ok
}

func (exAuthn) Authenticate(_ context.Context, a security.Authentication) (security.Authentication, error) {
	d := a.(demoAuth)
	if d.token != "letmein" {
		return a, security.ErrInvalidCredentials
	}

	return demoAuth{token: d.token, name: "alice", authed: true}, nil
}

type demoAuth struct {
	token  string
	name   string
	authed bool
}

func (d demoAuth) Principal() security.Principal {
	return demoPrincipal{sub: d.name}
}

func (d demoAuth) Credentials() any      { return d.token }
func (d demoAuth) Authorities() []string { return nil }
func (d demoAuth) IsAuthenticated() bool { return d.authed }
func (d demoAuth) Name() string          { return d.name }

type demoPrincipal struct{ sub string }

func (p demoPrincipal) Subject() string { return p.sub }
