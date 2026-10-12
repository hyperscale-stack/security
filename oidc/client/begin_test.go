// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// b64url43 matches the base64url encoding of 32 bytes.
var b64url43 = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// spyStore records the transactions saved and can fail.
type spyStore struct {
	inner   oidcclient.TransactionStore
	mu      sync.Mutex
	saved   []oidcclient.Transaction
	saveErr error
}

func newSpyStore() *spyStore { return &spyStore{inner: memory.New()} }

func (s *spyStore) Save(ctx context.Context, tx *oidcclient.Transaction) error {
	s.mu.Lock()
	s.saved = append(s.saved, *tx)
	err := s.saveErr
	s.mu.Unlock()

	if err != nil {
		return err
	}

	return s.inner.Save(ctx, tx)
}

func (s *spyStore) Consume(ctx context.Context, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
	return s.inner.Consume(ctx, stateHash, bindingHash, now)
}

func (s *spyStore) last(t *testing.T) oidcclient.Transaction {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	require.NotEmpty(t, s.saved)

	return s.saved[len(s.saved)-1]
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}

// TestBeginParameters checks the authorization request of OpenID Connect
// Core §3.1.2.1 with PKCE S256 (RFC 7636 §4.3): exactly the expected
// parameters, openid first, response_mode only for form_post.
func TestBeginParameters(t *testing.T) {
	t.Parallel()

	for _, mode := range []oidcclient.ResponseMode{oidcclient.ResponseModeQuery, oidcclient.ResponseModeFormPost} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t, func(cfg *oidcclient.Config) {
				cfg.ResponseMode = mode
				cfg.Scopes = []string{"profile", "openid", "email", "profile"}
			})

			ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{})
			require.NoError(t, err)

			u, err := url.Parse(ar.URL)
			require.NoError(t, err)
			assert.Equal(t, op.srv.URL+"/authorize", u.Scheme+"://"+u.Host+u.Path)

			q := u.Query()
			want := []string{"client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri", "response_type", "scope", "state"}

			if mode == oidcclient.ResponseModeFormPost {
				want = append(want, "response_mode")
				assert.Equal(t, "form_post", q.Get("response_mode"))
			}

			got := make([]string, 0, len(q))
			for k, v := range q {
				got = append(got, k)
				assert.Len(t, v, 1, "parameter %s sent once", k)
			}

			assert.ElementsMatch(t, want, got)
			assert.Equal(t, "code", q.Get("response_type"))
			assert.Equal(t, testClientID, q.Get("client_id"))
			assert.Equal(t, testRedirectURL, q.Get("redirect_uri"))
			assert.Equal(t, "openid profile email", q.Get("scope"))
			assert.Equal(t, "S256", q.Get("code_challenge_method"))
			assert.Equal(t, ar.State, q.Get("state"))
			assert.Regexp(t, b64url43, q.Get("state"))
			assert.Regexp(t, b64url43, q.Get("nonce"))
			assert.Regexp(t, b64url43, q.Get("code_challenge"))
			assert.Regexp(t, b64url43, ar.Binding)
			assert.NotContains(t, ar.URL, ar.Binding, "the binding secret never leaves the RP and the user agent")
		})
	}
}

// TestBeginValuesAreUnique checks that state, nonce, challenge and binding
// are fresh for every login (RFC 6749 §10.10, Core §3.1.2.1, RFC 7636
// §7.1, RFC 9700 §2.1.1: transaction-specific).
func TestBeginValuesAreUnique(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)
	seen := map[string]bool{}

	for range 50 {
		ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{})
		require.NoError(t, err)

		u, err := url.Parse(ar.URL)
		require.NoError(t, err)

		for _, v := range []string{ar.State, ar.Binding, u.Query().Get("nonce"), u.Query().Get("code_challenge")} {
			require.False(t, seen[v], "value reused")
			seen[v] = true
		}
	}
}

// TestBeginPersistsTransaction checks the transaction saved: keyed by the
// state hash, bound to the connection, issuer, client, redirect URI and
// response mode, no secret, expiry from the configured TTL.
func TestBeginPersistsTransaction(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	store := newSpyStore()
	c := op.client(t, func(cfg *oidcclient.Config) {
		cfg.Store = store
		cfg.TransactionTTL = 15 * time.Minute
	})

	maxAge := 90 * time.Second
	ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{
		MaxAge:    &maxAge,
		ACRValues: []string{"urn:acr:gold", "urn:acr:silver"},
		AppState:  "return=/settings",
	})
	require.NoError(t, err)

	tx := store.last(t)
	assert.Equal(t, sha256Hex(ar.State), tx.StateHash)
	assert.Regexp(t, `^[0-9a-f]{64}$`, tx.BindingHash)
	assert.NotEqual(t, sha256Hex(ar.Binding), tx.BindingHash, "a keyed hash, not a plain digest of the secret")
	assert.Equal(t, testConnection, tx.ConnectionID)
	assert.Equal(t, op.issuer, tx.Issuer)
	assert.Equal(t, testClientID, tx.ClientID)
	assert.Equal(t, testRedirectURL, tx.RedirectURI)
	assert.Equal(t, oidcclient.ResponseModeQuery, tx.ResponseMode)
	assert.Equal(t, int64(90), tx.MaxAge)
	assert.Equal(t, "urn:acr:gold urn:acr:silver", tx.ACRValues)
	assert.Equal(t, "return=/settings", tx.AppState)
	assert.Equal(t, testNow, tx.CreatedAt)
	assert.Equal(t, testNow.Add(15*time.Minute), tx.ExpiresAt)
	assert.Equal(t, tx.ExpiresAt, ar.ExpiresAt)

	assert.Regexp(t, `^[0-9a-f]{64}$`, tx.Integrity)

	for _, secret := range []string{ar.Binding, ar.State} {
		assert.NotContains(t, tx.BindingHash+tx.StateHash+tx.AppState+tx.ACRValues+tx.Integrity, secret)
	}

	_, err = c.Begin(context.Background(), oidcclient.AuthOptions{})
	require.NoError(t, err)
	assert.Equal(t, oidcclient.NoMaxAge, store.last(t).MaxAge, "no max_age sent")
	assert.NotEqual(t, tx.Integrity, store.last(t).Integrity)
}

// TestBeginSubSecondClock checks that the transaction times are whole
// seconds whatever the clock, as the store contract requires.
func TestBeginSubSecondClock(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	store := newSpyStore()
	c := op.client(t, func(cfg *oidcclient.Config) {
		cfg.Store = store
		cfg.Now = func() time.Time { return testNow.Add(700 * time.Millisecond) }
	})

	_, err := c.Begin(context.Background(), oidcclient.AuthOptions{})
	require.NoError(t, err)
	assert.Equal(t, testNow, store.last(t).CreatedAt)
}

func TestBeginSaveFailure(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	store := newSpyStore()
	store.saveErr = errors.New("store down")
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = store })

	ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{})
	require.ErrorIs(t, err, store.saveErr)
	assert.Nil(t, ar, "no request without a stored transaction")
}

// TestBeginKeepsEndpointQuery checks RFC 6749 §3.1: the query of the
// authorization endpoint is retained when parameters are added.
func TestBeginKeepsEndpointQuery(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	op.set(func(op *fakeOP) {
		op.metadata["authorization_endpoint"] = op.srv.URL + "/authorize?tenant=acme&p=a%20b"
	})
	c := op.client(t)

	ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ar.URL, op.srv.URL+"/authorize?tenant=acme&p=a%20b&"), ar.URL)
}

// TestBeginHints checks the protocol hints passed through (Core
// §3.1.2.1), the connection selection being the application's.
func TestBeginHints(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)
	zero := time.Duration(0)
	ninety := 90*time.Second + 900*time.Millisecond

	cases := []struct {
		name string
		opts oidcclient.AuthOptions
		want map[string]string
	}{
		{"login hint", oidcclient.AuthOptions{LoginHint: "jane@example.com"}, map[string]string{"login_hint": "jane@example.com"}},
		{"id token hint", oidcclient.AuthOptions{IDTokenHint: "eyJ.x.y"}, map[string]string{"id_token_hint": "eyJ.x.y"}},
		{"prompt", oidcclient.AuthOptions{Prompt: []string{"login", "consent"}}, map[string]string{"prompt": "login consent"}},
		{"prompt none", oidcclient.AuthOptions{Prompt: []string{"none"}}, map[string]string{"prompt": "none"}},
		{"max age zero", oidcclient.AuthOptions{MaxAge: &zero}, map[string]string{"max_age": "0"}},
		{"max age whole seconds", oidcclient.AuthOptions{MaxAge: &ninety}, map[string]string{"max_age": "90"}},
		{"acr values", oidcclient.AuthOptions{ACRValues: []string{"urn:a", "urn:b"}}, map[string]string{"acr_values": "urn:a urn:b"}},
		{"ui locales", oidcclient.AuthOptions{UILocales: []string{"fr-CA", "en"}}, map[string]string{"ui_locales": "fr-CA en"}},
		{"display", oidcclient.AuthOptions{Display: "popup"}, map[string]string{"display": "popup"}},
		{"extra", oidcclient.AuthOptions{ExtraParams: map[string]string{"domain_hint": "acme.example", "kc_idp_hint": "x"}},
			map[string]string{"domain_hint": "acme.example", "kc_idp_hint": "x"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ar, err := c.Begin(context.Background(), tc.opts)
			require.NoError(t, err)

			u, err := url.Parse(ar.URL)
			require.NoError(t, err)

			for k, v := range tc.want {
				assert.Equal(t, []string{v}, u.Query()[k])
			}
		})
	}
}

// TestBeginRefusesInvalidOptions checks every option rule; nothing is
// stored for a refused request.
func TestBeginRefusesInvalidOptions(t *testing.T) {
	t.Parallel()

	negative := -time.Second
	huge := time.Duration(1<<31) * time.Second

	cases := map[string]oidcclient.AuthOptions{
		"prompt none with login":  {Prompt: []string{"none", "login"}},
		"prompt with space":       {Prompt: []string{"login consent"}},
		"empty prompt value":      {Prompt: []string{""}},
		"negative max age":        {MaxAge: &negative},
		"max age over 2^31-1":     {MaxAge: &huge},
		"acr value with space":    {ACRValues: []string{"urn:a urn:b"}},
		"empty acr value":         {ACRValues: []string{""}},
		"ui locale with space":    {UILocales: []string{"fr CA"}},
		"display with space":      {Display: "pop up"},
		"login hint too long":     {LoginHint: strings.Repeat("a", 1025)},
		"login hint with control": {LoginHint: "jane\r\n@example.com"},
		"id token hint too long":  {IDTokenHint: strings.Repeat("a", 65537)},
		"app state too long":      {AppState: strings.Repeat("a", 4097)},
		"app state invalid UTF-8": {AppState: "\xff"},
		"extra param empty name":  {ExtraParams: map[string]string{"": "x"}},
		"extra param name space":  {ExtraParams: map[string]string{"a b": "x"}},
		"extra param value long":  {ExtraParams: map[string]string{"x": strings.Repeat("v", 2049)}},
		"too many extra params":   {ExtraParams: manyParams(21)},
	}

	reserved := []string{
		"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge",
		"code_challenge_method", "response_mode", "request", "request_uri", "claims", "registration",
		"id_token_hint", "login_hint", "max_age", "prompt", "acr_values", "ui_locales", "display",
	}
	for _, name := range reserved {
		cases["reserved "+name] = oidcclient.AuthOptions{ExtraParams: map[string]string{name: "x"}}
	}

	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			store := newSpyStore()
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = store })

			ar, err := c.Begin(context.Background(), opts)
			require.ErrorIs(t, err, oidcclient.ErrInvalidAuthRequest)
			assert.Nil(t, ar)

			store.mu.Lock()
			assert.Empty(t, store.saved, "nothing stored for a refused request")
			store.mu.Unlock()
		})
	}
}

func manyParams(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m["p"+string(rune('a'+i))] = "x"
	}

	return m
}

// TestBeginChallengeMatchesVerifier checks, through a strict token
// endpoint, that the verifier sent at the token endpoint is the one whose
// S256 challenge was sent (RFC 7636 §4.2, §4.5) and that the verifier is a
// valid code_verifier (43 unreserved characters, §4.1).
func TestBeginChallengeMatchesVerifier(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	_, err := op.login(t, c)
	require.NoError(t, err)

	op.set(func(op *fakeOP) {
		require.Len(t, op.tokenRequests, 1)
		verifier := op.tokenRequests[0].form.Get("code_verifier")
		assert.Regexp(t, b64url43, verifier)

		sum := sha256.Sum256([]byte(verifier))
		for _, g := range op.grants {
			assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), g.challenge)
			assert.NotEqual(t, verifier, g.nonce, "the nonce travels in the front channel: it must not be the verifier")
			assert.NotEqual(t, g.state, g.nonce)
		}
	})
}
