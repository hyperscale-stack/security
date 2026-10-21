// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcstack_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	clientmemory "github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawResponse is a raw answer of the provider.
type rawResponse struct {
	status int
	header http.Header
	body   string
}

// post sends form to path, authenticated with client_secret_basic as
// id/secret (form-encoded, RFC 6749 §2.3.1).
func (o *op) post(t *testing.T, path, id, sec string, form url.Values) rawResponse {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, o.base+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(sec))

	resp, err := o.srv.Client().Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	h := resp.Header.Clone()
	h.Del("Date")

	return rawResponse{status: resp.StatusCode, header: h, body: string(body)}
}

// TestClientBoundToAnotherIssuer checks the provider's client ↔ issuer
// binding (oauth2.IssuerBoundClient) from the relying party: a connection
// that uses the registration of tenant-a at tenant-b never gets a callback —
// the authorization endpoint answers 400 without redirecting — and its
// credentials at tenant-b's token, introspection and revocation endpoints
// read exactly like those of a client that exists nowhere: no
// cross-tenant existence oracle. The same registration works at tenant-a;
// an unbound registration works at every issuer.
func TestClientBoundToAnotherIssuer(t *testing.T) {
	t.Parallel()

	o := newOP(t)

	misbound := o.rp(t, conn("tenant-b", o.base+tenantB, tenantAID, secret, oidcclient.AuthMethodClientSecretBasic))

	ar, err := misbound.Begin(t.Context(), oidcclient.AuthOptions{})
	require.NoError(t, err)

	resp := o.authorize(t, ar.URL)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "never redirected")
	assert.Zero(t, o.enduserRequests(), "the Interaction is never reached")

	pathsB := o.paths(o.base + tenantB)

	for name, p := range map[string]struct {
		path string
		form url.Values
	}{
		"token":      {pathsB.Token, url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "redirect_uri": {callback("tenant-a")}}},
		"introspect": {pathsB.Introspect, url.Values{"token": {"x"}}},
		"revoke":     {pathsB.Revoke, url.Values{"token": {"x"}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			bound := o.post(t, p.path, tenantAID, secret, p.form)
			unknown := o.post(t, p.path, "nobody", secret, p.form)

			assert.Equal(t, http.StatusUnauthorized, bound.status)
			assert.Contains(t, bound.body, `"invalid_client"`)
			assert.Equal(t, unknown, bound, "byte-identical to an unknown client")
		})
	}

	t.Run("its own issuer", func(t *testing.T) {
		t.Parallel()

		_, err := o.login(t, o.rp(t, o.tenant(tenantA, tenantAID)), oidcclient.AuthOptions{})
		require.NoError(t, err)
	})

	t.Run("an unbound registration serves every issuer", func(t *testing.T) {
		t.Parallel()

		for _, c := range []connection{
			conn("shared-a", o.base+tenantA, sharedID, secret, oidcclient.AuthMethodClientSecretBasic),
			conn("shared-b", o.base+tenantB, sharedID, secret, oidcclient.AuthMethodClientSecretBasic),
		} {
			id, err := o.login(t, o.rp(t, c), oidcclient.AuthOptions{})
			require.NoError(t, err)
			assert.Equal(t, c.issuer, id.Issuer)
		}
	})
}

// enduserRequests returns how many requests the Interaction saw.
func (o *op) enduserRequests() int {
	o.enduser.mu.Lock()
	defer o.enduser.mu.Unlock()

	return len(o.enduser.requests)
}

// TestMixUpWithAnAttackerProvider models RFC 9700 §4.4.1: a relying party
// with two connections — an honest provider H (ours) and a provider A the
// attacker controls — sharing one transaction store. The victim starts a
// login with A, whose authorization endpoint sends the user agent on to H.
// Whatever A rewrites, the code H issues for the victim never reaches A's
// token endpoint:
//   - (a) H registered the honest connection's redirect URI only, so A
//     cannot have the response sent to its own connection's callback: H
//     refuses, no code;
//   - (b) A uses the honest connection's redirect URI: the response lands on
//     the honest callback with the state of A's login, of another
//     connection — ErrTransactionMismatch;
//   - (c) A registered its own client at H with its connection's callback
//     (§4.4.2.2's residual risk): the response lands on A's callback with
//     iss = H — ErrIssuerParameter (RFC 9207 §2.4): compared with A's
//     issuer when A advertises RFC 9207, discarded as an iss A never
//     announced when it does not.
func TestMixUpWithAnAttackerProvider(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		clientID  string
		redirect  string
		deliver   string // the connection whose callback receives the response; "" when H refuses
		want      error
		attackIss bool // A advertises RFC 9207
	}{
		{"(a) honest registration, attacker's redirect URI", basicID, callback("attacker"), "", nil, false},
		{"(b) honest registration and redirect URI", basicID, callback("basic"), "basic", oidcclient.ErrTransactionMismatch, false},
		{"(c) attacker's registration at the honest provider, A advertising RFC 9207", "attacker-x", callback("attacker"), "attacker", oidcclient.ErrIssuerParameter, true},
		{"(c) attacker's registration at the honest provider, A silent on RFC 9207", "attacker-x", callback("attacker"), "attacker", oidcclient.ErrIssuerParameter, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			o := newOP(t)
			o.clients.add(registration{id: "attacker-x", secret: secret, method: "client_secret_basic", issuers: []string{o.base}, redirects: []string{callback("attacker")}})

			a := newAttackerASAdvertising(t, tc.attackIss, func(q url.Values) string {
				q.Set("client_id", tc.clientID)
				q.Set("redirect_uri", tc.redirect)

				return o.base + o.paths(o.base).Authorize + "?" + q.Encode()
			})

			store := clientmemory.New()
			shared := func(cfg *oidcclient.Config) { cfg.Store = store }
			honest := o.rp(t, o.basic(), shared)
			attacker := o.rp(t, conn("attacker", a.srv.URL, "rp-at-attacker", secret, oidcclient.AuthMethodClientSecretBasic), shared)

			ar, err := attacker.Begin(t.Context(), oidcclient.AuthOptions{})
			require.NoError(t, err)

			resp, err := o.browser().Get(ar.URL) // the user agent at A
			require.NoError(t, err)
			_ = resp.Body.Close()

			resp = o.authorize(t, redirected(t, resp).String()) // sent on to H

			if tc.deliver == "" {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "H refuses the redirect URI")
				assert.Empty(t, resp.Header.Get("Location"))
				assert.Empty(t, a.received())

				return
			}

			loc := redirected(t, resp)
			assert.Equal(t, o.base, loc.Query().Get("iss"))

			receiver := map[string]*oidcclient.Client{"basic": honest, "attacker": attacker}[tc.deliver]

			id, err := receiver.Complete(t.Context(), callbackOf(loc, ar.Binding))
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, id)
			assert.Empty(t, a.received(), "the attacker's token endpoint never receives the code")
			assert.Zero(t, o.hits(o.paths(o.base).Token))
		})
	}
}

// TestMixUpResidualWithoutRFC9207 characterizes the residual risk RFC 9700
// §4.4.2.2 names, and documents it: when the honest provider does not send
// iss (no RFC 9207) and the attacker registered a client at it with the
// attacker connection's callback, nothing tells the relying party the
// response came from H — the honest code reaches the attacker's token
// endpoint. Never register a connection's redirect URI at another provider;
// with providers that do not send iss, distinct redirect URIs are the only
// mix-up defense — Config.RequireIssParameter on the receiving connection
// closes the gap, for applications that work only with providers sending
// iss (TestRequireIssParameterOnTheReceivingConnectionClosesTheResidual).
func TestMixUpResidualWithoutRFC9207(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	o.clients.add(registration{id: "attacker-x", secret: secret, method: "client_secret_basic", issuers: []string{o.base}, redirects: []string{callback("attacker")}})

	// H without RFC 9207: iss stripped from its responses.
	o.faults.set(o.paths(o.base).Authorize, rule{location: func(u *url.URL) {
		q := u.Query()
		q.Del("iss")
		u.RawQuery = q.Encode()
	}})

	a := newAttackerAS(t, func(q url.Values) string {
		q.Set("client_id", "attacker-x")

		return o.base + o.paths(o.base).Authorize + "?" + q.Encode()
	})

	attacker := o.rp(t, conn("attacker", a.srv.URL, "rp-at-attacker", secret, oidcclient.AuthMethodClientSecretBasic))

	ar, err := attacker.Begin(t.Context(), oidcclient.AuthOptions{})
	require.NoError(t, err)

	resp, err := o.browser().Get(ar.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	loc := redirected(t, o.authorize(t, redirected(t, resp).String()))
	require.NotEmpty(t, loc.Query().Get("code"))
	require.Empty(t, loc.Query().Get("iss"))

	_, err = attacker.Complete(t.Context(), callbackOf(loc, ar.Binding))
	require.ErrorIs(t, err, oidcclient.ErrTokenEndpoint, "the attacker's token endpoint answered")
	assert.Equal(t, []string{loc.Query().Get("code")}, a.received(), "the honest code leaked to the attacker")
}

// TestRequireIssParameterOnTheReceivingConnectionClosesTheResidual closes
// the residual of TestMixUpResidualWithoutRFC9207: the same attack — H
// without iss, the attacker's client registered at H with the attacker
// connection's callback — against an attacker connection configured with
// Config.RequireIssParameter, as an application sets it on every tenant
// connection. The response without iss is refused there (RFC 9207 §2.4),
// before any token request: the honest code never reaches the attacker.
func TestRequireIssParameterOnTheReceivingConnectionClosesTheResidual(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	o.clients.add(registration{id: "attacker-x", secret: secret, method: "client_secret_basic", issuers: []string{o.base}, redirects: []string{callback("attacker")}})

	o.faults.set(o.paths(o.base).Authorize, rule{location: func(u *url.URL) {
		q := u.Query()
		q.Del("iss")
		u.RawQuery = q.Encode()
	}})

	a := newAttackerAS(t, func(q url.Values) string {
		q.Set("client_id", "attacker-x")

		return o.base + o.paths(o.base).Authorize + "?" + q.Encode()
	})

	attacker := o.rp(t, conn("attacker", a.srv.URL, "rp-at-attacker", secret, oidcclient.AuthMethodClientSecretBasic),
		func(cfg *oidcclient.Config) { cfg.RequireIssParameter = true })

	ar, err := attacker.Begin(t.Context(), oidcclient.AuthOptions{})
	require.NoError(t, err)

	resp, err := o.browser().Get(ar.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()

	loc := redirected(t, o.authorize(t, redirected(t, resp).String()))
	require.NotEmpty(t, loc.Query().Get("code"))
	require.Empty(t, loc.Query().Get("iss"))

	id, err := attacker.Complete(t.Context(), callbackOf(loc, ar.Binding))
	require.ErrorIs(t, err, oidcclient.ErrIssuerParameter)
	assert.Nil(t, id)
	assert.Empty(t, a.received(), "the honest code never reaches the attacker's token endpoint")
	assert.Zero(t, o.hits(o.paths(o.base).Token))
}

// TestMixUpBetweenIssuersOfOneProvider: the victim's request to tenant-a is
// diverted to tenant-b, which answers with its own iss: the client refuses
// the response (RFC 9207 §2.4). Defense in depth: tenant-a's token endpoint
// refuses a code tenant-b issued (issuer binding, OIDC Core §16.15), even
// with the right PKCE verifier and redirect URI — which tenant-b, its
// issuer, accepts. A response whose iss was stripped although the provider
// advertises RFC 9207 is refused too.
func TestMixUpBetweenIssuersOfOneProvider(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	connA := conn("shared-a", o.base+tenantA, sharedID, secret, oidcclient.AuthMethodClientSecretBasic)
	a := o.rp(t, connA)
	verifier, challenge := pkcePair(t)

	// divert sends a login begun at tenant-a to tenant-b, with a PKCE
	// challenge whose verifier the test holds.
	divert := func(t *testing.T) (*oidcclient.AuthRequest, *url.URL) {
		t.Helper()

		ar, err := a.Begin(t.Context(), oidcclient.AuthOptions{})
		require.NoError(t, err)

		diverted, err := url.Parse(ar.URL)
		require.NoError(t, err)

		diverted.Path = o.paths(o.base + tenantB).Authorize
		q := diverted.Query()
		q.Set("code_challenge", challenge)
		diverted.RawQuery = q.Encode()

		return ar, redirected(t, o.authorize(t, diverted.String()))
	}

	redeem := func(t *testing.T, issuer, code string) tokenResponse {
		t.Helper()

		return o.tokenRequest(t, issuer, sharedID, secret, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback("shared-a")}, "code_verifier": {verifier},
		})
	}

	ar, loc := divert(t)
	require.Equal(t, o.base+tenantB, loc.Query().Get("iss"))

	_, err := a.Complete(t.Context(), callbackOf(loc, ar.Binding))
	require.ErrorIs(t, err, oidcclient.ErrIssuerParameter)
	assert.Zero(t, o.hits(o.paths(o.base+tenantA).Token))

	raw := redeem(t, o.base+tenantA, loc.Query().Get("code"))
	assert.True(t, raw.isCode("invalid_grant"), "a code of tenant-b is refused at tenant-a: %s", raw.body)

	_, control := divert(t)
	assert.Equal(t, http.StatusOK, redeem(t, o.base+tenantB, control.Query().Get("code")).status, "the same redemption at tenant-b")

	t.Run("iss stripped while advertised", func(t *testing.T) {
		t.Parallel()

		o := newOP(t)
		o.faults.set(o.paths(o.base).Authorize, rule{location: func(u *url.URL) {
			q := u.Query()
			q.Del("iss")
			u.RawQuery = q.Encode()
		}})

		c := o.rp(t, o.basic())

		_, err := o.login(t, c, oidcclient.AuthOptions{})
		require.ErrorIs(t, err, oidcclient.ErrIssuerParameter)
		assert.Zero(t, o.hits(o.paths(o.base).Token))
	})
}

// TestIssuerResolverFailureNeverReachesTheClient pins RFC 9207 §2 at the
// provider: when its IssuerResolver fails at the authorization endpoint, no
// response could name the issuer, so none is sent — the user agent gets a
// bare 500, never a redirect to the relying party, and nothing is
// exchanged.
func TestIssuerResolverFailureNeverReachesTheClient(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.basic())

	o.resolver.failAuthorize.Store(true)

	ar, err := c.Begin(t.Context(), oidcclient.AuthOptions{})
	require.NoError(t, err)

	resp := o.authorize(t, ar.URL)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "never redirected")
	assert.Zero(t, o.hits(o.paths(o.base).Token))
}

// TestRefusalsRevealNoSession: a session of another realm, of another
// end-user (an id_token_hint designating someone else), a stale one and no
// session at all all read the same to the relying party — login_required
// with the same description — so a response never tells which session the
// browser holds (Core §16.15; the provider's prompt=none rule).
func TestRefusalsRevealNoSession(t *testing.T) {
	t.Parallel()

	o := newOP(t)
	c := o.rp(t, o.tenant(tenantB, tenantBID))

	first, err := o.login(t, c, oidcclient.AuthOptions{})
	require.NoError(t, err)

	minute := time.Minute
	silent := []string{"none"}

	cases := map[string]struct {
		setup func(*script)
		opts  oidcclient.AuthOptions
	}{
		"no session":               {func(s *script) { s.signedOut = true }, oidcclient.AuthOptions{Prompt: silent}},
		"session of another realm": {func(s *script) { s.realm = o.base + tenantA }, oidcclient.AuthOptions{Prompt: silent}},
		"session of another user":  {func(s *script) { s.subject = bob }, oidcclient.AuthOptions{Prompt: silent, IDTokenHint: first.Tokens.IDToken}},
		"stale session":            {func(s *script) { s.authAge = time.Hour }, oidcclient.AuthOptions{Prompt: silent, MaxAge: &minute}},
	}

	var seen []oidcclient.AuthorizationError

	for name, tc := range cases {
		o.enduser.set(func(s *script) {
			s.signedOut, s.realm, s.subject, s.authAge = false, "", alice, 0
			tc.setup(s)
		})

		_, err := o.login(t, c, tc.opts)

		var authErr *oidcclient.AuthorizationError
		require.ErrorAs(t, err, &authErr, name)
		assert.Equal(t, "login_required", authErr.Code, name)

		seen = append(seen, *authErr)
	}

	for _, e := range seen[1:] {
		assert.Equal(t, seen[0], e, "every refusal reads the same")
	}
}

// pkcePair returns a PKCE code verifier and its S256 challenge (RFC 7636
// §4.1, §4.2).
func pkcePair(t *testing.T) (string, string) {
	t.Helper()

	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)

	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))

	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}
