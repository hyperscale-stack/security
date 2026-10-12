// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decide scripts every interaction to approve with the event mutate
// returns, and the decision options.
func (e *env) decide(mutate func(*oidcprovider.AuthenticationEvent), opts func(*oidcprovider.Decision)) {
	e.approveWith(func(req *oidcprovider.Request) *oidcprovider.Decision {
		ev := e.event(req)
		if mutate != nil {
			mutate(ev)
		}

		d := &oidcprovider.Decision{Authentication: ev}
		if opts != nil {
			opts(d)
		}

		return d
	})
}

// TestFreshnessIsEnforcedByTheProvider pins OIDC Core §3.1.2.1 and
// §3.1.2.3 end to end: an application returning a stale session for
// prompt=login or max_age gets login_required, never a code.
func TestFreshnessIsEnforcedByTheProvider(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		query   []string
		age     time.Duration
		started time.Duration // 0: none
		want    string        // "" = code issued
	}{
		{"prompt=login, stale session", []string{"prompt", "login"}, 10 * time.Minute, 0, oauth2.CodeLoginRequired},
		{"prompt=login, fresh authentication", []string{"prompt", "login"}, 0, 0, ""},
		{"prompt=login, multi-request login", []string{"prompt", "login"}, 2 * time.Minute, 3 * time.Minute, ""},
		{"prompt=login, interaction too old", []string{"prompt", "login"}, 0, 16 * time.Minute, oauth2.CodeServerError},
		{"max_age=60, 60s old", []string{"max_age", "60"}, time.Minute, 0, ""},
		{"max_age=60, 61s old", []string{"max_age", "60"}, time.Minute + time.Second, 0, oauth2.CodeLoginRequired},
		{"max_age=0, stale", []string{"max_age", "0"}, time.Second, 0, oauth2.CodeLoginRequired},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spy := &spyStore{}
			e := newEnv(t, withSpy(spy))
			e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.AuthTime = e.clock.Now().Add(-tc.age) },
				func(d *oidcprovider.Decision) {
					if tc.started != 0 {
						d.InteractionStartedAt = e.clock.Now().Add(-tc.started)
					}
				})

			params := redirect(t, e.authorize(with(authorizeQuery(), tc.query...)))
			assert.Equal(t, tc.want, params.Get("error"))

			if tc.want != "" {
				assert.Zero(t, spy.codes.Load(), "nothing is issued")
			}
		})
	}
}

// TestEssentialACRIsEnforced pins OIDC Core §5.5.1.1: an essential acr
// request with values that the authentication does not satisfy is a failed
// authentication (access_denied; login_required under prompt=none).
func TestEssentialACRIsEnforced(t *testing.T) {
	t.Parallel()

	claims := `{"id_token": {"acr": {"essential": true, "values": ["urn:loa:3", "urn:loa:2"]}}}`

	for acr, want := range map[string]string{"urn:loa:2": "", "urn:loa:1": oauth2.CodeAccessDenied, "": oauth2.CodeAccessDenied} {
		e := newEnv(t)
		e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.ACR = acr }, nil)

		params := redirect(t, e.authorize(with(authorizeQuery(), "claims", claims)))
		assert.Equal(t, want, params.Get("error"), "acr %q", acr)

		if want == "" {
			_, idt := e.idToken(tokens(t, e.exchange(params.Get("code"))).IDToken)
			assert.Equal(t, acr, idt["acr"])
		}
	}

	e := newEnv(t)
	e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.ACR = "urn:loa:1" }, nil)
	params := redirect(t, e.authorize(with(authorizeQuery(), "claims", claims, "prompt", "none")))
	assert.Equal(t, oauth2.CodeLoginRequired, params.Get("error"))
}

// TestVoluntaryACRIsNotEnforced pins OIDC Core §3.1.2.1: acr_values
// requests the acr as a voluntary claim.
func TestVoluntaryACRIsNotEnforced(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.ACR = "urn:loa:1" }, nil)

	resp := e.flow(with(authorizeQuery(), "acr_values", "urn:loa:3"))
	_, claims := e.idToken(resp.IDToken)
	assert.Equal(t, "urn:loa:1", claims["acr"])
}

// TestRealmIsEnforced: an authentication established in another issuer's
// realm is no authentication here.
func TestRealmIsEnforced(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.Issuer = "https://other.example" }, nil)

	assert.Equal(t, oauth2.CodeLoginRequired, redirect(t, e.authorize(authorizeQuery())).Get("error"))
	assert.Equal(t, oauth2.CodeAccessDenied, redirect(t, e.authorize(with(authorizeQuery(), "scope", "read"))).Get("error"),
		"an OAuth 2.0 request is bound to its realm too")
}

// TestApprovalContractViolations: an application approving with an
// authentication the provider cannot vouch for fails closed with
// server_error, nothing issued.
func TestApprovalContractViolations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*oidcprovider.AuthenticationEvent, time.Time)
		opts   func(*oidcprovider.Decision)
	}{
		{"non-ASCII subject", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) { ev.Subject = "alicé" }, nil},
		{"subject with a control character", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) { ev.Subject = "al\tice" }, nil},
		{"zero authentication time", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) { ev.AuthTime = time.Time{} }, nil},
		{"authentication in the future", func(ev *oidcprovider.AuthenticationEvent, now time.Time) { ev.AuthTime = now.Add(6 * time.Second) }, nil},
		{"acr over 255 bytes", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) { ev.ACR = strings.Repeat("a", 256) }, nil},
		{"acr with a control character", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) { ev.ACR = "urn:\n" }, nil},
		{"more than 10 amr", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) {
			ev.AMR = strings.Split("pwd otp mfa hwk swk sms pin fpt face iris user", " ")
		}, nil},
		{"amr over 32 bytes", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) { ev.AMR = []string{strings.Repeat("m", 33)} }, nil},
		{"amr with a space", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) { ev.AMR = []string{"one two"} }, nil},
		{"empty amr", func(ev *oidcprovider.AuthenticationEvent, _ time.Time) { ev.AMR = []string{""} }, nil},
		{"granted scope without openid", nil, func(d *oidcprovider.Decision) { d.Scope = "profile" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spy := &spyStore{}
			e := newEnv(t, withSpy(spy))
			e.decide(func(ev *oidcprovider.AuthenticationEvent) {
				if tc.mutate != nil {
					tc.mutate(ev, e.clock.Now())
				}
			}, tc.opts)

			assert.Equal(t, oauth2.CodeServerError, redirect(t, e.authorize(authorizeQuery())).Get("error"))
			assert.Zero(t, spy.codes.Load())
		})
	}

	t.Run("grant context over its budget", func(t *testing.T) {
		t.Parallel()

		// JSON escapes "<" as \u003c: an event within its bounds can leave
		// no room for a large claims request. Nothing is issued.
		spy := &spyStore{}
		e := newEnv(t, withSpy(spy))
		e.decide(func(ev *oidcprovider.AuthenticationEvent) {
			ev.ACR = strings.Repeat("<", 255)
			ev.AMR = slices.Repeat([]string{strings.Repeat("<", 32)}, 10)
		}, func(d *oidcprovider.Decision) { d.Claims = []string{"email"} })

		var values []string
		for _, c := range "abcd" {
			values = append(values, `"`+strings.Repeat(string(c), 200)+`"`)
		}

		claims := `{"id_token":{"email":{"values":[` + strings.Join(values, ",") + `]}}}`
		assert.Equal(t, oauth2.CodeServerError, redirect(t, e.authorize(with(authorizeQuery(), "claims", claims))).Get("error"))
		assert.Zero(t, spy.codes.Load())
	})

	t.Run("authentication within the skew", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.AuthTime = e.clock.Now().Add(5 * time.Second) }, nil)
		assert.NotEmpty(t, redirect(t, e.authorize(authorizeQuery())).Get("code"))
	})

	t.Run("subject of 255 printable characters", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		e.decide(func(ev *oidcprovider.AuthenticationEvent) { ev.Subject = "a b" + strings.Repeat("c", 252) }, nil)
		assert.NotEmpty(t, redirect(t, e.authorize(authorizeQuery())).Get("code"))
	})
}

// TestOfflineAccessRequiresConsent pins OIDC Core §11 and §17.4: a
// requested offline_access is ignored unless the end-user consented —
// through the prompt=consent dialog it requires, or under the application's
// other conditions — and a refresh token only comes with it (the env wires
// RefreshTokenScope = offline_access).
func TestOfflineAccessRequiresConsent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		prompt  string
		consent oidcprovider.OfflineAccessConsent
		granted bool
		failure string
	}{
		{"no consent", "consent", oidcprovider.NoOfflineAccess, false, ""},
		{"prompted consent", "consent", oidcprovider.OfflineAccessPrompted, true, ""},
		{"prompted without prompt=consent", "", oidcprovider.OfflineAccessPrompted, false, oauth2.CodeServerError},
		{"by policy", "", oidcprovider.OfflineAccessByPolicy, true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			e.decide(nil, func(d *oidcprovider.Decision) { d.OfflineAccess = tc.consent })

			params := redirect(t, e.authorize(with(authorizeQuery(), "scope", "openid offline_access", "prompt", tc.prompt)))
			if tc.failure != "" {
				assert.Equal(t, tc.failure, params.Get("error"))

				return
			}

			resp := tokens(t, e.exchange(params.Get("code")))
			assert.Equal(t, tc.granted, strings.Contains(resp.Scope, "offline_access"), resp.Scope)
			assert.Equal(t, tc.granted, resp.RefreshToken != "")
			assert.NotEmpty(t, resp.IDToken)
		})
	}
}

// TestReleasedClaims pins the release rule: only the individually requested
// claims the end-user agreed to (Decision.Claims), a base name releasing
// its language-tagged variants (Core §5.2).
func TestReleasedClaims(t *testing.T) {
	t.Parallel()

	request := `{"id_token": {"email": null, "name": null, "given_name#fr": null, "phone_number#x#y": null}}`

	cases := []struct {
		released []string
		want     []string
		absent   []string
	}{
		{nil, nil, []string{"email", "name", "name#fr"}},
		{[]string{"email"}, []string{"email"}, []string{"name", "name#fr"}},
		{[]string{"name"}, []string{"name", "name#fr"}, []string{"email"}},
		{[]string{"name#fr"}, nil, []string{"name", "name#fr", "email"}},
		{[]string{"phone_number#x"}, nil, []string{"phone_number#x#y"}},
		{[]string{"phone_number"}, []string{"phone_number#x#y"}, nil},
	}

	for _, tc := range cases {
		e := newEnv(t)
		e.decide(nil, func(d *oidcprovider.Decision) { d.Claims = tc.released })

		_, claims := e.idToken(e.flow(with(authorizeQuery(), "claims", request)).IDToken)
		for _, name := range tc.want {
			assert.Contains(t, claims, name, "released %v", tc.released)
		}

		for _, name := range tc.absent {
			assert.NotContains(t, claims, name, "released %v", tc.released)
		}
	}
}

// TestDecisionScopeNarrows: a consent may narrow the scope; the token
// response says what was granted.
func TestDecisionScopeNarrows(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.decide(nil, func(d *oidcprovider.Decision) { d.Scope = "openid email" })

	resp := e.flow(with(authorizeQuery(), "scope", "openid profile email"))
	assert.Equal(t, "openid email", resp.Scope)
	require.NotEmpty(t, resp.IDToken)
}
