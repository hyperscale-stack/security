// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPromptNoneRefusalOfAnUntrustedClientIsNotRedirected pins RFC 9700
// §4.11.2, attack 3, through the provider: a silent authentication request
// (prompt=none) the application refuses with login_required authenticated
// nobody, so it is answered with a bare page when
// oauth2.AuthorizeConfig.TrustedRedirect does not trust the client, and
// redirected when it does.
func TestPromptNoneRefusalOfAnUntrustedClientIsNotRedirected(t *testing.T) {
	t.Parallel()

	for _, trusted := range []bool{false, true} {
		e := newEnv(t)
		e.interaction.silent = func(*http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error) {
			return &oidcprovider.Decision{Refusal: oauth2.ErrLoginRequired}, nil
		}

		cfg := oauth2.AuthorizeConfig{TrustedRedirect: func(context.Context, oauth2.Client, string) bool { return trusted }}
		rec := e.authorizeWith(cfg, with(authorizeQuery(), "prompt", "none"))

		if trusted {
			assert.Equal(t, oauth2.CodeLoginRequired, redirect(t, rec).Get("error"))

			continue
		}

		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Empty(t, rec.Header().Get("Location"), "never redirected")
		assert.Equal(t, "oauth2: authorization request refused: login_required\n", rec.Body.String())
	}
}
