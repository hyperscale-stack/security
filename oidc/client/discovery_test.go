// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newWithOP(t *testing.T, op *fakeOP, mutators ...func(*oidcclient.Config)) error {
	t.Helper()

	_, err := oidcclient.New(context.Background(), op.config(mutators...))

	return err
}

// TestDiscoveryURL checks OpenID Connect Discovery 1.0 §4.1: the issuer,
// one terminating "/" removed, plus /.well-known/openid-configuration —
// path issuers included — and §4.3: the trailing slash stays significant
// in the issuer comparison.
func TestDiscoveryURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, issuerPath, wantPath string
	}{
		{"root issuer", "", "/.well-known/openid-configuration"},
		{"path issuer", "/tenants/acme", "/tenants/acme/.well-known/openid-configuration"},
		{"path issuer with trailing slash", "/tenants/acme/", "/tenants/acme/.well-known/openid-configuration"},
		{"root issuer with trailing slash", "/", "/.well-known/openid-configuration"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t, c.issuerPath)
			require.NoError(t, newWithOP(t, op))

			op.set(func(op *fakeOP) {
				assert.Equal(t, []string{c.wantPath}, op.discoveryPaths)
			})
		})
	}
}

// TestDiscoveryHTTP checks that only a 200 application/json response is
// used (Discovery §4, §4.2), within the outbound policy.
func TestDiscoveryHTTP(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		setup  func(*fakeOP)
		policy func(*outbound.Policy)
		ok     bool
	}{
		"server error":           {setup: func(op *fakeOP) { op.metadataStatus = http.StatusInternalServerError }},
		"not found":              {setup: func(op *fakeOP) { op.metadataStatus = http.StatusNotFound }},
		"html":                   {setup: func(op *fakeOP) { op.metadataType = "text/html" }},
		"no content type":        {setup: func(op *fakeOP) { op.metadataType = "" }},
		"json with charset":      {setup: func(op *fakeOP) { op.metadataType = "application/json; charset=utf-8" }, ok: true},
		"json upper case":        {setup: func(op *fakeOP) { op.metadataType = "Application/JSON" }, ok: true},
		"jwt content type":       {setup: func(op *fakeOP) { op.metadataType = "application/jwt" }},
		"oversized document":     {policy: func(p *outbound.Policy) { p.MaxResponseBytes = 64 }},
		"loopback not exempted":  {policy: func(p *outbound.Policy) { p.AllowedPrefixes = nil }},
		"redirected (no follow)": {setup: func(op *fakeOP) { op.metadataStatus = http.StatusFound }},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			if c.setup != nil {
				op.set(c.setup)
			}

			err := newWithOP(t, op, func(cfg *oidcclient.Config) {
				if c.policy != nil {
					c.policy(&cfg.Outbound)
				}
			})

			if c.ok {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, oidcclient.ErrDiscovery)
		})
	}

	t.Run("server down", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		cfg := op.config()
		op.srv.Close()

		_, err := oidcclient.New(context.Background(), cfg)
		require.ErrorIs(t, err, oidcclient.ErrDiscovery)
	})

	t.Run("policy refusal is reported", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		err := newWithOP(t, op, func(cfg *oidcclient.Config) { cfg.Outbound.AllowedPrefixes = nil })
		require.ErrorIs(t, err, outbound.ErrDestinationNotAllowed)
	})
}

// TestIssuerMismatch checks Discovery §4.3 / §7.2: the metadata issuer
// must be byte-for-byte the issuer the document was requested for; no
// normalization (Discovery §5).
func TestIssuerMismatch(t *testing.T) {
	t.Parallel()

	cases := map[string]func(issuer string) string{
		"trailing slash added": func(iss string) string { return iss + "/" },
		"upper-case scheme":    func(iss string) string { return strings.Replace(iss, "https", "HTTPS", 1) },
		"other path":           func(iss string) string { return iss + "/other" },
		"other host":           func(string) string { return "https://evil.example.com" },
		"default port spelled": func(iss string) string { return iss + ":443" },
		"percent-encoded":      func(iss string) string { return strings.Replace(iss, "127.0.0.1", "127.0.0.%31", 1) },
		"empty":                func(string) string { return "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.metadata["issuer"] = mutate(op.issuer) })

			err := newWithOP(t, op)
			if name == "empty" {
				require.ErrorIs(t, err, oidcclient.ErrInvalidMetadata)

				return
			}

			require.ErrorIs(t, err, oidcclient.ErrIssuerMismatch)
		})
	}

	t.Run("path issuer with trailing slash must match exactly", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t, "/tenant/")
		op.set(func(op *fakeOP) { op.metadata["issuer"] = strings.TrimSuffix(op.issuer, "/") })

		require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrIssuerMismatch)
	})
}

// TestRequiredMetadata checks the REQUIRED members of Discovery §3 (an
// empty array counts as omitted, §4.2) and their JSON types.
func TestRequiredMetadata(t *testing.T) {
	t.Parallel()

	required := []string{
		"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
		"response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported",
	}

	for _, member := range required {
		t.Run("missing "+member, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { delete(op.metadata, member) })

			require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrInvalidMetadata)
		})

		t.Run("wrong type "+member, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.metadata[member] = 42 })

			require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrInvalidMetadata)
		})
	}

	for _, member := range []string{"response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"} {
		t.Run("empty "+member, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.metadata[member] = []string{} })

			require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrInvalidMetadata)
		})
	}

	t.Run("unused member of an unexpected type is ignored", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) {
			op.metadata["claims_supported"] = "not-an-array"
			op.metadata["scopes_supported"] = 42
			op.metadata["end_session_endpoint"] = map[string]any{"x": 1}
		})

		require.NoError(t, newWithOP(t, op))
	})
}

// TestEndpointURLs checks that every endpoint is an absolute https URL
// without fragment or userinfo (Discovery §3), and that the authorization
// endpoint query, retained (RFC 6749 §3.1), cannot carry a parameter the
// client sends.
func TestEndpointURLs(t *testing.T) {
	t.Parallel()

	endpoints := []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"}
	forms := map[string]func(base string) string{
		"http":       func(base string) string { return strings.Replace(base, "https://", "http://", 1) },
		"relative":   func(string) string { return "/endpoint" },
		"fragment":   func(base string) string { return base + "/endpoint#x" },
		"userinfo":   func(base string) string { return strings.Replace(base, "https://", "https://u:p@", 1) + "/endpoint" },
		"no host":    func(string) string { return "https:///endpoint" },
		"spaces":     func(base string) string { return base + "/end point" },
		"unparsable": func(string) string { return "https://[::1/endpoint" },
	}

	for _, endpoint := range endpoints {
		for form, build := range forms {
			t.Run(endpoint+" "+form, func(t *testing.T) {
				t.Parallel()

				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.metadata[endpoint] = build(op.srv.URL) })

				require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrInvalidMetadata)
			})
		}
	}

	t.Run("userinfo endpoint is optional", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) { delete(op.metadata, "userinfo_endpoint") })

		require.NoError(t, newWithOP(t, op))
	})

	t.Run("authorization endpoint malformed query", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) { op.metadata["authorization_endpoint"] = op.srv.URL + "/authorize?a=%zz" })

		require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrInvalidMetadata)
	})

	for _, param := range []string{"client_id", "state", "nonce", "redirect_uri", "scope", "code_challenge", "response_type", "prompt", "login_hint"} {
		t.Run("authorization endpoint query with "+param, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.metadata["authorization_endpoint"] = op.srv.URL + "/authorize?" + param + "=x" })

			require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrInvalidMetadata)
		})
	}

	// The Client keeps the endpoint's query (RFC 6749 §3.1): a query using
	// a parameter the Client sends, in any spelling a server may read as
	// it, or using one twice, would make the request repeat a parameter.
	for name, query := range map[string]string{
		"reserved upper case":     "State=x",
		"reserved mixed case":     "NONCE=x",
		"reserved title case":     "Request_Uri=x",
		"reserved dotted":         "request.uri=x",
		"reserved long s":         "%C5%BFtate=x", // U+017F folds to s; .NET upper-cases it to S
		"reserved with a space":   "redirect%20uri=x",
		"reserved with a bracket": "code%5Bchallenge=x",
		"repeated":                "tenant=a&tenant=b",
		"repeated in case":        "tenant=a&TENANT=b",
		"repeated dotted":         "tenant.id=a&tenant_id=b",
	} {
		t.Run("authorization endpoint query "+name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.metadata["authorization_endpoint"] = op.srv.URL + "/authorize?" + query })

			require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrInvalidMetadata)
		})
	}
}

// TestCapabilities checks what the configuration needs against what the
// provider lists: a capability is refused when its member lists values
// without it, and a public client requires S256 to be advertised.
func TestCapabilities(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		metadata func(map[string]any)
		config   func(*oidcclient.Config)
		ok       bool
	}{
		"no code response type": {metadata: func(m map[string]any) { m["response_types_supported"] = []string{"id_token", "code id_token"} }},
		"form_post not listed": {
			metadata: func(m map[string]any) { m["response_modes_supported"] = []string{"query", "fragment"} },
			config:   func(c *oidcclient.Config) { c.ResponseMode = oidcclient.ResponseModeFormPost },
		},
		"form_post with modes omitted": {
			metadata: func(m map[string]any) { delete(m, "response_modes_supported") },
			config:   func(c *oidcclient.Config) { c.ResponseMode = oidcclient.ResponseModeFormPost },
			ok:       true,
		},
		"query not listed":      {metadata: func(m map[string]any) { m["response_modes_supported"] = []string{"form_post"} }},
		"no authorization_code": {metadata: func(m map[string]any) { m["grant_types_supported"] = []string{"implicit"} }},
		"grant types omitted":   {metadata: func(m map[string]any) { delete(m, "grant_types_supported") }, ok: true},
		"basic not listed":      {metadata: func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"} }},
		"auth methods omitted":  {metadata: func(m map[string]any) { delete(m, "token_endpoint_auth_methods_supported") }, ok: true},
		"only plain pkce":       {metadata: func(m map[string]any) { m["code_challenge_methods_supported"] = []string{"plain"} }},
		"confidential, no pkce": {metadata: func(m map[string]any) { delete(m, "code_challenge_methods_supported") }, ok: true},
		"public client, no pkce": {
			metadata: func(m map[string]any) { delete(m, "code_challenge_methods_supported") },
			config: func(c *oidcclient.Config) {
				c.AuthMethod = oidcclient.AuthMethodNone
				c.ClientSecret = oidcclient.Secret{}
			},
		},
		"public client, plain only": {
			metadata: func(m map[string]any) { m["code_challenge_methods_supported"] = []string{"plain"} },
			config: func(c *oidcclient.Config) {
				c.AuthMethod = oidcclient.AuthMethodNone
				c.ClientSecret = oidcclient.Secret{}
			},
		},
		"public client with S256": {
			config: func(c *oidcclient.Config) {
				c.AuthMethod = oidcclient.AuthMethodNone
				c.ClientSecret = oidcclient.Secret{}
			},
			ok: true,
		},
		"only HMAC advertised": {metadata: func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"HS256", "none"} }},
		"no common algorithm": {
			metadata: func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"RS256"} },
			config:   func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{oidcclient.ES256} },
		},
		"ES256 only, RS256 by default": {
			metadata: func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"ES256"} },
		},
		"ES256 only, ES256 configured": {
			metadata: func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"ES256"} },
			config:   func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{oidcclient.ES256} },
			ok:       true,
		},
		"iss parameter flag wrong type": {metadata: func(m map[string]any) { m["authorization_response_iss_parameter_supported"] = "true" }},
		"response modes wrong type":     {metadata: func(m map[string]any) { m["response_modes_supported"] = "query" }},
		"pkce methods wrong type":       {metadata: func(m map[string]any) { m["code_challenge_methods_supported"] = []int{1} }},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			if c.metadata != nil {
				op.set(func(op *fakeOP) { c.metadata(op.metadata) })
			}

			err := newWithOP(t, op, func(cfg *oidcclient.Config) {
				if c.config != nil {
					c.config(cfg)
				}
			})

			if c.ok {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, oidcclient.ErrInvalidMetadata)
		})
	}
}

// TestStrictMetadataJSON checks that the discovery document is parsed
// strictly: exact member names (OpenID Connect Discovery §5 compares code
// points), no duplicate or case-variant members at any level, valid UTF-8,
// paired surrogates, one object, bounded depth.
func TestStrictMetadataJSON(t *testing.T) {
	t.Parallel()

	valid := func(op *fakeOP) string {
		return `"issuer":"` + op.issuer + `","authorization_endpoint":"` + op.srv.URL + `/authorize","token_endpoint":"` +
			op.srv.URL + `/token","jwks_uri":"` + op.srv.URL + `/jwks","response_types_supported":["code"],` +
			`"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]`
	}

	cases := map[string]func(op *fakeOP) string{
		"duplicate issuer":           func(op *fakeOP) string { return `{` + valid(op) + `,"issuer":"` + op.issuer + `"}` },
		"case-variant issuer":        func(op *fakeOP) string { return `{` + valid(op) + `,"Issuer":"https://evil.example.com"}` },
		"only a case-variant issuer": func(op *fakeOP) string { return `{` + strings.Replace(valid(op), `"issuer"`, `"Issuer"`, 1) + `}` },
		"kelvin-sign variant":        func(op *fakeOP) string { return `{` + valid(op) + `,"\u212auid":1,"kuid":2}` },
		"escaped duplicate":          func(op *fakeOP) string { return `{` + valid(op) + `,"jwks_\u0075ri":"x"}` },
		"nested duplicate":           func(op *fakeOP) string { return `{` + valid(op) + `,"x":{"a":1,"a":2}}` },
		"nested case variant":        func(op *fakeOP) string { return `{` + valid(op) + `,"x":[{"Sub":1,"sub":2}]}` },
		"invalid UTF-8":              func(op *fakeOP) string { return `{` + valid(op) + ",\"x\":\"\xff\"}" },
		"lone surrogate":             func(op *fakeOP) string { return `{` + valid(op) + `,"x":"\ud800"}` },
		"trailing data":              func(op *fakeOP) string { return `{` + valid(op) + `} {}` },
		"array":                      func(op *fakeOP) string { return `[{` + valid(op) + `}]` },
		"too deep": func(op *fakeOP) string {
			return `{` + valid(op) + `,"x":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`
		},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.metadataRaw = []byte(body(op)) })

			require.ErrorIs(t, newWithOP(t, op), oidcclient.ErrInvalidMetadata)
		})
	}

	t.Run("valid surrogate pair and deep enough nesting", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) {
			op.metadataRaw = []byte(`{` + valid(op) + `,"x":"\ud83d\ude00","y":` + strings.Repeat("[", 30) + strings.Repeat("]", 30) + `}`)
		})

		require.NoError(t, newWithOP(t, op))
	})
}
