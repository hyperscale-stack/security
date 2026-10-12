// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reservedParams are the request parameters an ExtraParams entry may never
// set, whatever its spelling: those the Client sends and those it does not
// support (request objects could override state, nonce or PKCE).
var reservedParams = []string{
	"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge",
	"code_challenge_method", "response_mode", "request", "request_uri", "claims", "registration",
	"id_token_hint", "login_hint", "max_age", "prompt", "acr_values", "ui_locales", "display",
}

// spellings returns names a server may read as name: other cases, and '.'
// for '_' (PHP rewrites dots of parameter names as underscores).
func spellings(name string) []string {
	out := []string{strings.ToUpper(name), strings.ToUpper(name[:1]) + name[1:]}

	if strings.Contains(name, "_") {
		out = append(out, strings.ReplaceAll(name, "_", "."), strings.ToUpper(strings.ReplaceAll(name, "_", ".")))
	}

	return out
}

// beginRefused runs Begin with opts against an OP whose authorization
// endpoint has query, and checks that nothing was stored nor returned.
func beginRefused(t *testing.T, query string, opts oidcclient.AuthOptions) error {
	t.Helper()

	op := newFakeOP(t)
	if query != "" {
		op.set(func(op *fakeOP) { op.metadata["authorization_endpoint"] = op.srv.URL + "/authorize?" + query })
	}

	store := newSpyStore()
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = store })

	ar, err := c.Begin(context.Background(), opts)
	assert.Nil(t, ar)

	store.mu.Lock()
	assert.Empty(t, store.saved, "nothing stored for a refused request")
	store.mu.Unlock()

	return err
}

// TestBeginRefusesOtherSpellingsOfReservedParams checks that no spelling of
// a reserved parameter passes: a server comparing names case-insensitively
// (ASP.NET) or rewriting '.' as '_' (PHP) would read it as the parameter
// itself — request and request_uri included, which the godoc promises to
// refuse (RFC 6749 §3.1: no parameter twice).
func TestBeginRefusesOtherSpellingsOfReservedParams(t *testing.T) {
	t.Parallel()

	for _, reserved := range reservedParams {
		for _, name := range append(spellings(reserved), "rEqUeSt_UrI") {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				err := beginRefused(t, "", oidcclient.AuthOptions{ExtraParams: map[string]string{name: "x"}})
				require.ErrorIs(t, err, oidcclient.ErrInvalidAuthRequest)
			})
		}
	}
}

// TestBeginRefusesParamsOfTheEndpointQuery checks that ExtraParams cannot
// repeat a parameter of the authorization endpoint's own query, which the
// request keeps (RFC 6749 §3.1), in any spelling.
func TestBeginRefusesParamsOfTheEndpointQuery(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"tenant", "Tenant", "TENANT", "tenant_id", "tenant.id", "Tenant.Id"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := beginRefused(t, "tenant=acme&tenant_id=t1", oidcclient.AuthOptions{ExtraParams: map[string]string{name: "evil"}})
			require.ErrorIs(t, err, oidcclient.ErrInvalidAuthRequest)
		})
	}
}

// TestBeginRefusesRepeatedExtraParams checks that two ExtraParams entries
// may not be one parameter to a case-insensitive or name-rewriting server.
func TestBeginRefusesRepeatedExtraParams(t *testing.T) {
	t.Parallel()

	for name, params := range map[string]map[string]string{
		"case":         {"tenant": "a", "TENANT": "b"},
		"dot":          {"a.b": "x", "a_b": "y"},
		"dot and case": {"a.b": "x", "A_B": "y"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := beginRefused(t, "", oidcclient.AuthOptions{ExtraParams: params})
			require.ErrorIs(t, err, oidcclient.ErrInvalidAuthRequest)
		})
	}
}

// TestBeginSendsEveryParameterOnce checks the whole authorization request:
// every option set, the endpoint's own query kept, extra parameters added —
// and no name appears twice, nor two names a server could read as one.
func TestBeginSendsEveryParameterOnce(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) { op.metadata["authorization_endpoint"] = op.srv.URL + "/authorize?tenant=acme&p=x" })
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.ResponseMode = oidcclient.ResponseModeFormPost })
	maxAge := time.Minute

	ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{
		LoginHint:   "jane@example.com",
		IDTokenHint: "eyJ.x.y",
		Prompt:      []string{"login"},
		MaxAge:      &maxAge,
		ACRValues:   []string{"urn:mfa"},
		UILocales:   []string{"fr"},
		Display:     "page",
		ExtraParams: map[string]string{"domain_hint": "acme.example", "kc_idp_hint": "saml", "tenant_hint": "t"},
	})
	require.NoError(t, err)

	u, err := url.Parse(ar.URL)
	require.NoError(t, err)

	query, err := url.ParseQuery(u.RawQuery)
	require.NoError(t, err)

	keys := map[string]string{}

	for name, values := range query {
		assert.Len(t, values, 1, "%s is sent once", name)

		key := strings.ReplaceAll(strings.ToLower(name), ".", "_")
		assert.NotContains(t, keys, key, "%s and %s are one parameter to some servers", name, keys[key])
		keys[key] = name
	}

	assert.Equal(t, []string{"acme"}, query["tenant"], "the endpoint's query is kept")
	assert.Equal(t, []string{"saml"}, query["kc_idp_hint"])
	assert.Len(t, query, 21, "the 8 fixed parameters, response_mode, 7 options, 2 of the endpoint, 3 extra")
}
