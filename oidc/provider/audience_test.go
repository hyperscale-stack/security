// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	oidcprovider "github.com/hyperscale-stack/security/oidc/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientLookups wraps the env's ClientStore: it records the IDs looked up
// and answers some with a client or an error of its own. A generated mock
// cannot stand in: mockery's MockClientStore lives in package oauth2's own
// test binary, and the server needs a real store to authenticate the env's
// clients.
type clientLookups struct {
	inner oauth2.ClientStore

	mu      sync.Mutex
	ids     []string
	answers map[string]lookupAnswer
}

type lookupAnswer struct {
	client oauth2.Client
	err    error
}

// withClientLookups wraps the env's ClientStore in l: apply it after
// withClient.
func withClientLookups(l *clientLookups) envOption {
	return func(s *oauth2.ServerConfig, _ *grant.Config, _ *oidcprovider.Config) {
		l.inner, s.ClientStore = s.ClientStore, l
	}
}

func (l *clientLookups) LoadClient(ctx context.Context, id string) (oauth2.Client, error) {
	l.mu.Lock()
	l.ids = append(l.ids, id)
	a, ok := l.answers[id]
	l.mu.Unlock()

	if ok {
		return a.client, a.err
	}

	return l.inner.LoadClient(ctx, id) //nolint:wrapcheck // test double
}

// answer makes the store answer id with c and err from now on.
func (l *clientLookups) answer(id string, c oauth2.Client, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.answers == nil {
		l.answers = map[string]lookupAnswer{}
	}

	l.answers[id] = lookupAnswer{client: c, err: err}
}

// lookedUp returns the IDs looked up so far.
func (l *clientLookups) lookedUp() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.ids)
}

// switchableAudience resolves the test issuer with an access-token audience
// a test changes between requests.
type switchableAudience struct{ aud atomic.Pointer[string] }

func newSwitchableAudience(aud string) *switchableAudience {
	s := &switchableAudience{}
	s.set(aud)

	return s
}

func (s *switchableAudience) set(aud string) { s.aud.Store(&aud) }

func (s *switchableAudience) Resolve(context.Context, *http.Request) (string, string, error) {
	return testIssuer, *s.aud.Load(), nil
}

// TestAccessTokenAudienceNamingARelyingPartyIsRefused (RFC 8725 §2.8,
// §3.11, §3.12; OIDC Core §2): an access token never takes the audience of
// a client the issuer gives ID Tokens to — the requesting client, or any
// client registered at the issuer that runs the authorization code flow —
// lest that client, not checking typ, take it for one of its ID Tokens.
// Clients that cannot receive ID Tokens may be the audience. A refused
// exchange answers server_error and persists nothing.
func TestAccessTokenAudienceNamingARelyingPartyIsRefused(t *testing.T) {
	t.Parallel()

	codeFlow := []string{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeRefreshToken}
	cases := []struct {
		name    string
		aud     string
		clients []oauth2.Client
		answer  *lookupAnswer
		refused bool
	}{
		{name: "the requesting client", aud: webClientID, refused: true},
		{name: "another relying party of the issuer", aud: spaClientID, refused: true},
		{name: "a relying party bound to the issuer", aud: "late-rp", clients: []oauth2.Client{
			&oauth2.DefaultClient{IDValue: "late-rp", GrantTypeValues: codeFlow, IssuerValues: []string{testIssuer}},
		}, refused: true},
		{name: "a relying party of another issuer", aud: "other-rp", clients: []oauth2.Client{
			&oauth2.DefaultClient{IDValue: "other-rp", GrantTypeValues: codeFlow, IssuerValues: []string{"https://other.example"}},
		}},
		{name: "a resource server registered for introspection", aud: "https://api.example", clients: []oauth2.Client{
			&oauth2.DefaultClient{IDValue: "https://api.example", Secret: webClientSecret, TypeValue: oauth2.ClientConfidential},
		}},
		{name: "a client_credentials client", aud: "batch", clients: []oauth2.Client{
			&oauth2.DefaultClient{
				IDValue: "batch", Secret: webClientSecret, TypeValue: oauth2.ClientConfidential,
				GrantTypeValues: []string{oauth2.GrantTypeClientCredentials},
			},
		}},
		{name: "a client the store returns for another spelling", aud: "SPA-APP",
			answer: &lookupAnswer{client: testClients()[spaClientID]}},
		{name: "an unknown audience answered invalid_client", aud: "https://unknown.example",
			answer: &lookupAnswer{err: oauth2.ErrInvalidClient}},
		{name: "an audience the store fails to look up", aud: "https://api.example",
			answer: &lookupAnswer{err: errors.New("client store down")}, refused: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spy, lookups := &spyStore{}, &clientLookups{}
			opts := []envOption{withSpy(spy), withResolver(audienceIssuer(tc.aud))}

			for _, c := range tc.clients {
				opts = append(opts, withClient(c))
			}

			e := newEnv(t, append(opts, withClientLookups(lookups))...)

			if tc.answer != nil {
				lookups.answer(tc.aud, tc.answer.client, tc.answer.err)
			}

			rec := e.exchange(e.code(authorizeQuery()))

			if !tc.refused {
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				assert.NotEmpty(t, tokens(t, rec).IDToken)

				return
			}

			assert.Equal(t, oauth2.CodeServerError, oauthError(t, rec))
			assert.NotContains(t, rec.Body.String(), "access_token")
			assert.Zero(t, spy.pairs.Load(), "nothing is persisted")
			assert.NotEmpty(t, e.sink.all(), "the cause reaches the ErrorHook")
		})
	}
}

// TestAnEmptyAudienceIsNotLookedUp: without an access-token audience there
// is nothing to compare, and the ClientStore is not asked.
func TestAnEmptyAudienceIsNotLookedUp(t *testing.T) {
	t.Parallel()

	lookups := &clientLookups{}
	e := newEnv(t, withResolver(audienceIssuer("")), withClientLookups(lookups))
	lookups.answer("", nil, errors.New("an empty ID is never looked up"))

	require.NotEmpty(t, tokens(t, e.exchange(e.code(authorizeQuery()))).IDToken)
	assert.NotContains(t, lookups.lookedUp(), "")
}

// TestPlainGrantAudienceIsChecked: the audience rule holds for every
// exchange the provider sees — a plain OAuth 2.0 grant's access token is no
// less a JWT a relying party could take for an ID Token.
func TestPlainGrantAudienceIsChecked(t *testing.T) {
	t.Parallel()

	for _, aud := range []string{webClientID, spaClientID} {
		spy := &spyStore{}
		e := newEnv(t, withSpy(spy), withResolver(audienceIssuer(aud)))

		rec := e.exchange(e.code(with(authorizeQuery(), "scope", "read", "nonce", "")))
		assert.Equal(t, oauth2.CodeServerError, oauthError(t, rec), aud)
		assert.Zero(t, spy.pairs.Load(), "%s: nothing is persisted", aud)
	}
}

// TestRefreshChecksTheAudience: the audience is checked at every refresh
// too — the resolver's audience may change — and a refused refresh rotates
// nothing: the refresh token still works once the audience is fixed.
func TestRefreshChecksTheAudience(t *testing.T) {
	t.Parallel()

	spy, audience := &spyStore{}, newSwitchableAudience("api")
	e := newEnv(t, withSpy(spy), withResolver(audience))
	e.consentOffline()

	resp := e.flow(offlineQuery())
	require.NotEmpty(t, resp.RefreshToken)

	persisted := spy.pairs.Load()

	audience.set(spaClientID)
	assert.Equal(t, oauth2.CodeServerError, oauthError(t, e.refresh(resp.RefreshToken, "")))
	assert.Equal(t, persisted, spy.pairs.Load(), "nothing is rotated")

	audience.set("api")
	assert.NotEmpty(t, tokens(t, e.refresh(resp.RefreshToken, "")).IDToken)
}
