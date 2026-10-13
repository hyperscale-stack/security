// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idpOrigin is the origin of the fixture IdP's pages.
const idpOrigin = "https://idp.example.com"

// withResponseOrigins sets the connection's ResponseOrigins.
func withResponseOrigins(origins ...string) envOption {
	return func(_ *samlsp.Config, c *samlsp.Connection) { c.ResponseOrigins = origins }
}

// completeWith posts samlResponse for the login lr from its browser, with
// the given header lines.
func completeWith(e *env, lr loginResult, samlResponse string, header http.Header) (*samlsp.LoginResult, error) {
	req := acsRequest(samlResponse, lr.relayState, lr.cookie.Value)
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	return e.sp.CompleteLogin(context.Background(), req, connID)
}

// TestCompleteLogin_LeakedRequestLoginCSRF (audit SAML-02): whoever learns
// a victim's in-flight IdP redirect URL (request ID and RelayState handle)
// can obtain the IdP's response to it for her own account and auto-post it
// into the victim's browser, which attaches its binding cookie. Without
// ResponseOrigins the victim ends up signed in as the attacker — the
// documented residual risk; with it, the POST from the attacker's page is
// refused before the transaction is touched, and the victim's own login
// completes.
func TestCompleteLogin_LeakedRequestLoginCSRF(t *testing.T) {
	t.Parallel()

	attackersAccount := onAssertion(func(a *etree.Element) { path(a, "Subject", "NameID").SetText("mallory-own-account") })
	fromAttacker := http.Header{"Origin": {"https://attacker.example"}}

	t.Run("without ResponseOrigins (residual)", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		victim := begin(t, e, samlsp.LoginOptions{})

		res, err := completeWith(e, victim, respond(t, victim.requestID, attackersAccount), fromAttacker)
		require.NoError(t, err)
		assert.Equal(t, "mallory-own-account", res.Identity.NameID.Value)
	})

	t.Run("with ResponseOrigins", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, withResponseOrigins(idpOrigin))
		victim := begin(t, e, samlsp.LoginOptions{})

		_, err := completeWith(e, victim, respond(t, victim.requestID, attackersAccount), fromAttacker)
		requireRejected(t, e, victim, err, samlsp.ErrOriginMismatch)

		res, err := completeWith(e, victim, respond(t, victim.requestID, respOpts{}), http.Header{"Origin": {idpOrigin}})
		require.NoError(t, err)
		assert.Equal(t, nameIDValue, res.Identity.NameID.Value)
	})
}

// TestCompleteLogin_ResponseOriginsCloseTheForcedForgeryBurn: the forged
// POST that burns a login at a connection without ResponseOrigins (review
// F3, TestCompleteLogin_ForcedForgeryBurnsTheLogin) is refused before the
// consumption when the connection sets them.
func TestCompleteLogin_ResponseOriginsCloseTheForcedForgeryBurn(t *testing.T) {
	t.Parallel()

	e := newEnv(t, withResponseOrigins(idpOrigin))
	lr := begin(t, e, samlsp.LoginOptions{})

	forged := respond(t, lr.requestID, respOpts{assertionSig: sigOpts{signer: keys(t).attacker}})
	_, err := completeWith(e, lr, forged, http.Header{"Origin": {"https://attacker.example"}})
	requireRejected(t, e, lr, err, samlsp.ErrOriginMismatch)

	_, err = completeWith(e, lr, respond(t, lr.requestID, respOpts{}), http.Header{"Origin": {idpOrigin}})
	require.NoError(t, err)
}

// TestCompleteLogin_ResponseOrigins: Origin decides when present (exactly
// one, never "null"); a browser that sent no Origin is judged on its
// Referer's origin; without ResponseOrigins nothing is checked.
func TestCompleteLogin_ResponseOrigins(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		allowed []string
		header  http.Header
		detail  string // "" when accepted
	}{
		{"IdP origin", []string{idpOrigin}, http.Header{"Origin": {idpOrigin}}, ""},
		{"one of several", []string{"https://other.example", idpOrigin}, http.Header{"Origin": {idpOrigin}}, ""},
		{"IdP origin with a non-default port", []string{"https://idp.example.com:8443"},
			http.Header{"Origin": {"https://idp.example.com:8443"}}, ""},
		{"IdP Referer without Origin", []string{idpOrigin}, http.Header{"Referer": {"https://idp.example.com/sso?x=1"}}, ""},
		{"IdP Referer with an explicit default port and upper-case host", []string{idpOrigin},
			http.Header{"Referer": {"https://IDP.Example.com:443/sso"}}, ""},
		{"unset: any origin", nil, http.Header{"Origin": {"https://attacker.example"}}, ""},
		{"unset: no header", nil, nil, ""},
		{"another origin", []string{idpOrigin}, http.Header{"Origin": {"https://attacker.example"}},
			"Origin is not an allowed response origin"},
		{"another port", []string{idpOrigin}, http.Header{"Origin": {"https://idp.example.com:8443"}},
			"Origin is not an allowed response origin"},
		{"http instead of https", []string{idpOrigin}, http.Header{"Origin": {"http://idp.example.com"}},
			"Origin is not an allowed response origin"},
		{"Origin compared exactly", []string{idpOrigin}, http.Header{"Origin": {"https://IDP.example.com"}},
			"Origin is not an allowed response origin"},
		{"empty Origin", []string{idpOrigin}, http.Header{"Origin": {""}, "Referer": {"https://idp.example.com/sso"}},
			"Origin is not an allowed response origin"},
		{"Origin null", []string{idpOrigin}, http.Header{"Origin": {"null"}, "Referer": {"https://idp.example.com/sso"}},
			"opaque origin (Origin: null)"},
		{"Origin wins over a matching Referer", []string{idpOrigin},
			http.Header{"Origin": {"https://attacker.example"}, "Referer": {"https://idp.example.com/sso"}},
			"Origin is not an allowed response origin"},
		{"two Origin headers", []string{idpOrigin}, http.Header{"Origin": {idpOrigin, idpOrigin}}, "several Origin headers"},
		{"another Referer", []string{idpOrigin}, http.Header{"Referer": {"https://attacker.example/landing"}},
			"Referer is not from an allowed response origin"},
		{"a Referer on a look-alike host", []string{idpOrigin}, http.Header{"Referer": {"https://idp.example.com.attacker.example/"}},
			"Referer is not from an allowed response origin"},
		{"a relative Referer", []string{idpOrigin}, http.Header{"Referer": {"/sso"}},
			"Referer is not from an allowed response origin"},
		{"two Referer headers", []string{idpOrigin}, http.Header{"Referer": {"https://idp.example.com/", "https://idp.example.com/"}},
			"neither an Origin nor a single Referer"},
		{"no header", []string{idpOrigin}, nil, "neither an Origin nor a single Referer"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t, withResponseOrigins(tc.allowed...))
			lr := begin(t, e, samlsp.LoginOptions{})

			res, err := completeWith(e, lr, respond(t, lr.requestID, respOpts{}), tc.header)
			if tc.detail == "" {
				require.NoError(t, err)
				assert.Equal(t, nameIDValue, res.Identity.NameID.Value)

				return
			}

			requireRejected(t, e, lr, err, samlsp.ErrOriginMismatch)
			assert.Equal(t, samlsp.ErrOriginMismatch.Error()+" ("+tc.detail+")", err.Error())
		})
	}
}

func TestConnection_ValidateResponseOrigins(t *testing.T) {
	t.Parallel()

	refused := []string{
		"", "null", "idp.example.com", "//idp.example.com",
		"https://idp.example.com/", "https://idp.example.com/sso", "https://idp.example.com?", "https://idp.example.com?x=1",
		"https://idp.example.com#", "https://user@idp.example.com", "https://IDP.example.com", "HTTPS://idp.example.com",
		"https://idp.example.com:443", "http://localhost:80", "https://idp.example.com:0443", "https://idp.example.com:0",
		"https://idp.example.com:65536", "https://idp.example.com:x", "http://idp.example.com", "ftp://idp.example.com",
		"https://[2001:0db8::1]", "https://[2001:DB8::1]", "https://2001:db8::1", "https://bücher.example",
		"https://idp.example.com ", "https://idp .example.com",
	}

	for _, origin := range refused {
		t.Run("refused "+origin, func(t *testing.T) {
			t.Parallel()

			c := newConnection(t)
			c.ResponseOrigins = []string{idpOrigin, origin}

			err := c.Validate()
			require.ErrorIs(t, err, samlsp.ErrInvalidConnection)
			assert.NotContains(t, err.Error(), "bücher", "the error never echoes the configured value")
		})
	}

	accepted := [][]string{
		nil, {idpOrigin}, {"https://idp.example.com:8443"}, {"http://localhost:8080"}, {"http://127.0.0.1"},
		{"http://[::1]:9000"}, {"https://[2001:db8::1]"}, {"https://[2001:db8::1]:8443"}, {"https://xn--bcher-kva.example"},
	}

	eight := make([]string, 8)
	for i := range eight {
		eight[i] = fmt.Sprintf("https://idp%d.example.com", i)
	}

	accepted = append(accepted, eight)

	for _, origins := range accepted {
		t.Run("accepted "+strings.Join(origins, " "), func(t *testing.T) {
			t.Parallel()

			c := newConnection(t)
			c.ResponseOrigins = origins
			require.NoError(t, c.Validate())
		})
	}

	c := newConnection(t)
	c.ResponseOrigins = append(eight, "https://idp8.example.com")
	require.ErrorIs(t, c.Validate(), samlsp.ErrInvalidConnection, "at most 8 origins")
}
