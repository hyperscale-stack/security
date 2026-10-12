// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPromptNoneIsSilent pins OIDC Core §3.1.2.3: with prompt=none the
// provider MUST NOT interact — it calls the method without ResponseWriter.
func TestPromptNoneIsSilent(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	resp := e.flow(with(authorizeQuery(), "prompt", "none"))
	assert.NotEmpty(t, resp.IDToken)

	interactive, silent := e.interaction.calls()
	assert.Empty(t, interactive)
	require.Len(t, silent, 1)
	assert.True(t, silent[0].Prompt.None)
}

// TestPromptNoneRefusals pins OIDC Core §3.1.2.6: the interaction codes
// travel back to the client, with the state and the issuer.
func TestPromptNoneRefusals(t *testing.T) {
	t.Parallel()

	for _, refusal := range []*oauth2.Error{
		oauth2.ErrLoginRequired, oauth2.ErrConsentRequired, oauth2.ErrInteractionRequired, oauth2.ErrAccountSelectionRequired,
	} {
		t.Run(refusal.Code, func(t *testing.T) {
			t.Parallel()

			spy := &spyStore{}
			e := newEnv(t, withSpy(spy))
			e.interaction.scriptSilent(func(*http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error) {
				return &oidcprovider.Decision{Refusal: refusal}, nil
			})

			params := redirect(t, e.authorize(with(authorizeQuery(), "prompt", "none")))
			assert.Equal(t, refusal.Code, params.Get("error"))
			assert.Equal(t, "st-1", params.Get("state"))
			assert.Equal(t, testIssuer, params.Get("iss"))
			assert.Zero(t, spy.codes.Load(), "nothing is issued")
		})
	}
}

// TestSilentRefusalsRevealNothing (code review F4): under prompt=none, no
// session, a session of another realm, of another end-user or a stale one
// read the same on the wire — login_required with the same description —
// so a client cannot probe the browser's sessions; the reason reaches the
// ErrorHook only.
func TestSilentRefusalsRevealNothing(t *testing.T) {
	t.Parallel()

	silent := with(authorizeQuery(), "prompt", "none")
	cases := map[string]struct {
		mutate func(*oidcprovider.AuthenticationEvent)
		query  url.Values
	}{
		"session of another realm": {func(ev *oidcprovider.AuthenticationEvent) { ev.Issuer = "https://tenant-a.example" }, silent},
		"session of another end-user": {func(ev *oidcprovider.AuthenticationEvent) { ev.Subject = "bob" },
			with(silent, "claims", `{"id_token": {"sub": {"value": "alice"}}}`)},
		"stale session": {func(ev *oidcprovider.AuthenticationEvent) { ev.AuthTime = ev.AuthTime.Add(-time.Hour) },
			with(silent, "max_age", "60")},
		"essential acr unmet": {nil, with(silent, "claims", `{"id_token": {"acr": {"essential": true, "value": "urn:loa:3"}}}`)},
	}

	baseline := newEnv(t)
	baseline.interaction.scriptSilent(func(*http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error) {
		return &oidcprovider.Decision{Refusal: oauth2.ErrLoginRequired}, nil
	})

	noSession := redirect(t, baseline.authorize(silent))
	require.Equal(t, oauth2.CodeLoginRequired, noSession.Get("error"))

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			e.decide(tc.mutate, nil)

			params := redirect(t, e.authorize(tc.query))
			assert.Equal(t, noSession.Get("error"), params.Get("error"))
			assert.Equal(t, noSession.Get("error_description"), params.Get("error_description"))
			assert.NotEmpty(t, e.sink.all(), "the reason reaches the hook")
		})
	}
}

func TestPromptNoneWithoutDecisionIsAServerError(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.interaction.scriptSilent(func(*http.Request, *oidcprovider.Request) (*oidcprovider.Decision, error) { return nil, nil })

	assert.Equal(t, oauth2.CodeServerError, redirect(t, e.authorize(with(authorizeQuery(), "prompt", "none"))).Get("error"))
}

// TestPromptNoneIgnoresInteractionStartedAt: there is no interaction under
// prompt=none — an InteractionStartedAt cannot stretch max_age.
func TestPromptNoneIgnoresInteractionStartedAt(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	e.approveWith(func(req *oidcprovider.Request) *oidcprovider.Decision {
		ev := e.event(req)
		ev.AuthTime = e.clock.Now().Add(-10 * time.Minute)

		return &oidcprovider.Decision{Authentication: ev, InteractionStartedAt: e.clock.Now().Add(-10 * time.Minute)}
	})

	params := redirect(t, e.authorize(with(authorizeQuery(), "prompt", "none", "max_age", "60")))
	assert.Equal(t, oauth2.CodeLoginRequired, params.Get("error"))
}

// TestInteractionRendersItsOwnPage: (nil, nil) from Authorize means the
// application answered — its login page — and nothing is issued.
func TestInteractionRendersItsOwnPage(t *testing.T) {
	t.Parallel()

	spy := &spyStore{}
	e := newEnv(t, withSpy(spy))
	e.interaction.script(func(w http.ResponseWriter, _ *http.Request, _ *oidcprovider.Request) (*oidcprovider.Decision, error) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("login page"))

		return nil, nil
	})

	rec := e.authorize(authorizeQuery())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "login page", rec.Body.String())
	assert.Zero(t, spy.codes.Load())
}

func TestInteractionFailures(t *testing.T) {
	t.Parallel()

	ev := func(req *oidcprovider.Request) *oidcprovider.AuthenticationEvent {
		return &oidcprovider.AuthenticationEvent{Issuer: req.Issuer, Subject: "alice", AuthTime: newTestClock().Now()}
	}

	cases := []struct {
		name     string
		decision func(*oidcprovider.Request) (*oidcprovider.Decision, error)
		code     string
	}{
		{"error", func(*oidcprovider.Request) (*oidcprovider.Decision, error) {
			return nil, errors.New("session store down")
		}, oauth2.CodeServerError},
		{"approval and refusal", func(req *oidcprovider.Request) (*oidcprovider.Decision, error) {
			return &oidcprovider.Decision{Authentication: ev(req), Refusal: oauth2.ErrLoginRequired}, nil
		}, oauth2.CodeServerError},
		{"refusal that is no protocol error", func(*oidcprovider.Request) (*oidcprovider.Decision, error) {
			return &oidcprovider.Decision{Refusal: errors.New("nope")}, nil
		}, oauth2.CodeServerError},
		{"refusal with a token-endpoint code", func(*oidcprovider.Request) (*oidcprovider.Decision, error) {
			return &oidcprovider.Decision{Refusal: oauth2.ErrInvalidGrant}, nil
		}, oauth2.CodeServerError},
		{"denial", func(*oidcprovider.Request) (*oidcprovider.Decision, error) {
			return &oidcprovider.Decision{}, nil
		}, oauth2.CodeAccessDenied},
		{"wrapped refusal", func(*oidcprovider.Request) (*oidcprovider.Decision, error) {
			return &oidcprovider.Decision{Refusal: errors.Join(errors.New("ctx"), oauth2.ErrConsentRequired)}, nil
		}, oauth2.CodeConsentRequired},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spy := &spyStore{}
			e := newEnv(t, withSpy(spy))
			e.interaction.script(func(_ http.ResponseWriter, _ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
				return tc.decision(req)
			})

			params := redirect(t, e.authorize(authorizeQuery()))
			assert.Equal(t, tc.code, params.Get("error"))
			assert.Zero(t, spy.codes.Load())
		})
	}
}

// TestTheInteractionGetsACopy: mutating the Request — its fields or the
// slices it shares nothing with — changes nothing the provider verifies or
// releases.
func TestTheInteractionGetsACopy(t *testing.T) {
	t.Parallel()

	t.Run("requirements", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		e.interaction.script(func(_ http.ResponseWriter, _ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
			ev := e.event(req)
			ev.AuthTime = e.clock.Now().Add(-time.Hour)

			req.MaxAge, req.Prompt, req.Subjects, req.EssentialACR, req.Issuer = nil, oidcprovider.Prompt{}, nil, nil, "x"

			return &oidcprovider.Decision{Authentication: ev}, nil
		})

		params := redirect(t, e.authorize(with(authorizeQuery(), "max_age", "60")))
		assert.Equal(t, oauth2.CodeLoginRequired, params.Get("error"))
	})

	t.Run("claims", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		e.interaction.script(func(_ http.ResponseWriter, _ *http.Request, req *oidcprovider.Request) (*oidcprovider.Decision, error) {
			req.Claims.IDToken[0].Name = "name"
			req.Claims.IDToken[0].Values = append(req.Claims.IDToken[0].Values, raw(`"x"`))

			return &oidcprovider.Decision{Authentication: e.event(req), Claims: []string{"email", "name"}}, nil
		})

		resp := e.flow(with(authorizeQuery(), "claims", `{"id_token": {"email": null}}`))
		_, claims := e.idToken(resp.IDToken)
		assert.Equal(t, "alice@example.com", claims["email"])
		assert.NotContains(t, claims, "name", "only what was requested is released")
	})
}

// TestForeignConsentFuncNeverRunsForOpenIDRequests: an authorization
// endpoint mounted with Server().AuthorizeHandler and another ConsentFunc
// refuses OpenID requests before that ConsentFunc can run — it could
// render a page for prompt=none — and keeps serving OAuth 2.0 ones.
func TestForeignConsentFuncNeverRunsForOpenIDRequests(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	called := 0
	foreign := e.op.Server().AuthorizeHandler(oauth2.AuthorizeConfig{},
		func(w http.ResponseWriter, _ *http.Request, _ *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			called++
			w.WriteHeader(http.StatusOK)

			return nil, nil
		})

	rec := serve(foreign, get("/oauth2/authorize?"+with(authorizeQuery(), "prompt", "none").Encode()))
	assert.Equal(t, oauth2.CodeServerError, redirect(t, rec).Get("error"))
	assert.Zero(t, called)

	plain := serve(foreign, get("/oauth2/authorize?"+with(authorizeQuery(), "scope", "read").Encode()))
	assert.Equal(t, http.StatusOK, plain.Code)
	assert.Equal(t, 1, called, "OAuth 2.0 requests keep their ConsentFunc")

	approving := e.op.Server().AuthorizeHandler(oauth2.AuthorizeConfig{},
		func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
			return &oauth2.Consent{Approved: true, Subject: "alice"}, nil
		})

	code := redirect(t, serve(approving, get("/oauth2/authorize?"+with(authorizeQuery(), "scope", "read").Encode()))).Get("code")
	require.NotEmpty(t, code, "an OAuth 2.0 approval by another ConsentFunc keeps OAuth 2.0 semantics")
	assert.Empty(t, tokens(t, e.exchange(code)).IDToken)
}

// TestRequestCheck pins the freshness, subject and acr rules the provider
// applies to every OpenID approval (Core §3.1.2.1, §3.1.2.2, §3.1.2.3,
// §5.5.1, §5.5.1.1), as the application can apply them beforehand.
func TestRequestCheck(t *testing.T) {
	t.Parallel()

	received := newTestClock().Now()
	at := func(d time.Duration) time.Time { return received.Add(d) }
	ev := func(authTime time.Time) oidcprovider.AuthenticationEvent {
		return oidcprovider.AuthenticationEvent{Issuer: testIssuer, Subject: "alice", AuthTime: authTime, ACR: "urn:b"}
	}

	base := oidcprovider.Request{Issuer: testIssuer, OpenID: true, ReceivedAt: received}
	login := base
	login.Prompt.Login = true
	maxAge60 := base
	maxAge60.MaxAge = durationPtr(time.Minute)
	maxAge0 := base
	maxAge0.MaxAge = durationPtr(0)
	designated := base
	designated.Subjects = []string{"bob", "carol"}
	acr := base
	acr.EssentialACR = []string{"urn:a"}
	acrSilent := acr
	acrSilent.Prompt.None = true
	acrEmpty := base
	acrEmpty.EssentialACR = []string{""}
	noACR := ev(at(0))
	noACR.ACR = ""
	oauthOnly := oidcprovider.Request{Issuer: testIssuer, ReceivedAt: received}

	otherRealm := ev(received)
	otherRealm.Issuer = "https://other.example"

	cases := []struct {
		name    string
		req     oidcprovider.Request
		ev      oidcprovider.AuthenticationEvent
		started time.Time
		want    *oauth2.Error
	}{
		{"plain session", base, ev(at(-24 * time.Hour)), time.Time{}, nil},
		{"other realm", base, otherRealm, time.Time{}, oauth2.ErrLoginRequired},
		{"other realm, OAuth 2.0 request", oauthOnly, otherRealm, time.Time{}, oauth2.ErrAccessDenied},
		{"prompt=login, stale", login, ev(at(-time.Second)), time.Time{}, oauth2.ErrLoginRequired},
		{"prompt=login, same second", login, ev(at(0)), time.Time{}, nil},
		{"prompt=login, later", login, ev(at(3 * time.Second)), time.Time{}, nil},
		{"prompt=login, interaction started earlier", login, ev(at(-2 * time.Minute)), at(-3 * time.Minute), nil},
		{"prompt=login, before the interaction", login, ev(at(-4 * time.Minute)), at(-3 * time.Minute), oauth2.ErrLoginRequired},
		{"interaction older than 15 minutes", login, ev(at(0)), at(-15*time.Minute - time.Second), oauth2.ErrServerError},
		{"interaction 15 minutes old", login, ev(at(0)), at(-15 * time.Minute), nil},
		{"interaction in the future", login, ev(at(0)), at(6 * time.Second), oauth2.ErrServerError},
		{"interaction within the skew", login, ev(at(5 * time.Second)), at(5 * time.Second), nil},
		{"max_age, exactly", maxAge60, ev(at(-time.Minute)), time.Time{}, nil},
		{"max_age, one second over", maxAge60, ev(at(-time.Minute - time.Second)), time.Time{}, oauth2.ErrLoginRequired},
		{"max_age=0 is prompt=login", maxAge0, ev(at(-time.Second)), time.Time{}, oauth2.ErrLoginRequired},
		{"max_age=0, fresh", maxAge0, ev(at(0)), time.Time{}, nil},
		{"designated subject", designated, ev(at(0)), time.Time{}, oauth2.ErrLoginRequired},
		{"essential acr unmet", acr, ev(at(0)), time.Time{}, oauth2.ErrAccessDenied},
		{"essential acr unmet, prompt=none", acrSilent, ev(at(0)), time.Time{}, oauth2.ErrLoginRequired},
		{"essential acr never met without acr", acrEmpty, noACR, time.Time{}, oauth2.ErrAccessDenied},
		{"OAuth 2.0 request ignores OpenID rules", oauthOnly, ev(at(-24 * time.Hour)), time.Time{}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.req.Check(tc.ev, tc.started)
			if tc.want == nil {
				require.NoError(t, err)

				return
			}

			var oe *oauth2.Error
			require.ErrorAs(t, err, &oe)
			assert.Equal(t, tc.want.Code, oe.Code)
			assert.Equal(t, tc.want.Description, oe.Description, "a fixed description: the reason never reaches the wire")
		})
	}

	met := acr
	assert.NoError(t, met.Check(oidcprovider.AuthenticationEvent{Issuer: testIssuer, Subject: "alice", AuthTime: received, ACR: "urn:a"}, time.Time{}))

	ok := designated
	assert.NoError(t, ok.Check(oidcprovider.AuthenticationEvent{Issuer: testIssuer, Subject: "carol", AuthTime: received}, time.Time{}))
}
