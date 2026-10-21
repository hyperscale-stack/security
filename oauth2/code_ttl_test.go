// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorizeHandlerBoundsTheCodeTTL pins RFC 6749 §4.1.2 — "A maximum
// authorization code lifetime of 10 minutes is RECOMMENDED" — and OAuth 2.1
// §4.1.2 ("MUST expire shortly after it is issued"): AuthorizeHandler
// refuses, by panicking at construction, a CodeTTL beyond 10 minutes; a
// zero or negative one means 10 minutes, any other is honored.
func TestAuthorizeHandlerBoundsTheCodeTTL(t *testing.T) {
	t.Parallel()

	const panicMessage = "oauth2: AuthorizeHandler: CodeTTL exceeds 10 minutes (RFC 6749 §4.1.2)"

	for _, ttl := range []time.Duration{10*time.Minute + time.Nanosecond, 11 * time.Minute, 365 * 24 * time.Hour} {
		srv := newAuthorizeServer(t, oauth2.Profile20BCP)
		assert.PanicsWithValue(t, panicMessage, func() { srv.AuthorizeHandler(oauth2.AuthorizeConfig{CodeTTL: ttl}, approve) }, ttl)
	}

	cases := map[time.Duration]time.Duration{
		0:                0,
		-time.Second:     0,
		time.Second:      time.Second,
		5 * time.Minute:  5 * time.Minute,
		10 * time.Minute: 10 * time.Minute,
	}

	for configured, want := range cases {
		if want == 0 {
			want = 10 * time.Minute
		}

		store := memory.New()
		srv := newAuthorizeServerWith(t, oauth2.Profile20BCP, store)

		rec := runAuthorizeCfg(srv, oauth2.AuthorizeConfig{CodeTTL: configured}, authorizeQuery(), approve)
		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

		code, err := store.ConsumeAuthorizationCode(t.Context(), oauth2.HashToken(nil, mustLocation(t, rec).Query().Get("code")))
		require.NoError(t, err)
		assert.Equal(t, want, code.ExpiresAt.Sub(code.IssuedAt), "CodeTTL %v", configured)
	}
}
