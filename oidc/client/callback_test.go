// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompleteQuery(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)

	ar, code := op.begin(t, c, oidcclient.AuthOptions{AppState: "return=/home"})

	id, err := c.Complete(context.Background(), callbackFor(ar, code))
	require.NoError(t, err)

	assert.Equal(t, testConnection, id.ConnectionID)
	assert.Equal(t, op.issuer, id.Issuer)
	assert.Equal(t, testSubject, id.Subject)
	assert.Equal(t, []string{testClientID}, id.Audience)
	assert.Equal(t, testNow, id.IssuedAt)
	assert.Equal(t, testNow.Add(5*time.Minute), id.ExpiresAt)
	assert.True(t, id.AuthTime.IsZero())
	assert.Equal(t, "return=/home", id.AppState)
	assert.Equal(t, testAccessToken, id.Tokens.AccessToken)
	assert.Equal(t, "Bearer", id.Tokens.TokenType)
	assert.Equal(t, "rt-1", id.Tokens.RefreshToken)
	assert.Equal(t, "openid profile", id.Tokens.Scope)
	assert.Equal(t, testNow.Add(time.Hour), id.Tokens.Expiry)
	assert.NotEmpty(t, id.Tokens.IDToken)

	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}

	require.NoError(t, id.DecodeClaims(&claims))
	assert.Equal(t, "jane@example.com", claims.Email)
	assert.Equal(t, testSubject, claims.Sub)
	assert.Equal(t, 1, op.hitCount("/token"))
}

// TestCompleteRootRedirect checks a redirect URI without a path: its
// callback path is "/".
func TestCompleteRootRedirect(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.RedirectURL = "https://rp.example.com" })

	for _, received := range []string{"https://rp.example.com/", "https://rp.example.com"} {
		ar, code := op.begin(t, c, oidcclient.AuthOptions{})
		cb := callbackFor(ar, code)
		cb.URL = receivedOn(received)

		_, err := c.Complete(context.Background(), cb)
		require.NoError(t, err, received)
	}
}

func TestCompleteFormPost(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.ResponseMode = oidcclient.ResponseModeFormPost })

	ar, code := op.begin(t, c, oidcclient.AuthOptions{})
	cb := callbackFor(ar, code)
	cb.Mode = oidcclient.ResponseModeFormPost

	id, err := c.Complete(context.Background(), cb)
	require.NoError(t, err)
	assert.Equal(t, testSubject, id.Subject)

	op.set(func(op *fakeOP) {
		for _, g := range op.grants {
			assert.Equal(t, "form_post", g.responseMode)
		}
	})
}

// TestCompleteBinding checks the CSRF / login-CSRF / code-injection
// defense (RFC 6749 §10.12, RFC 9700 §4.7): only the user agent holding the
// transaction's binding completes it; a refused attempt leaves the
// transaction usable and redeems nothing.
func TestCompleteBinding(t *testing.T) {
	t.Parallel()

	cases := map[string]func(victim, attacker *oidcclient.AuthRequest) string{
		"missing":                 func(*oidcclient.AuthRequest, *oidcclient.AuthRequest) string { return "" },
		"malformed":               func(v, _ *oidcclient.AuthRequest) string { return v.Binding[:42] },
		"padded":                  func(v, _ *oidcclient.AuthRequest) string { return v.Binding + "=" },
		"non-canonical encoding":  func(v, _ *oidcclient.AuthRequest) string { return nonCanonical(v.Binding) },
		"another login's binding": func(_, a *oidcclient.AuthRequest) string { return a.Binding },
	}

	for name, bindingOf := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			store := &countingStore{TransactionStore: memory.New()}
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = store })

			victim, code := op.begin(t, c, oidcclient.AuthOptions{})
			attacker, _ := op.begin(t, c, oidcclient.AuthOptions{})

			cb := callbackFor(victim, code)
			cb.Binding = bindingOf(victim, attacker)

			id, err := c.Complete(context.Background(), cb)
			require.ErrorIs(t, err, oidcclient.ErrBindingMismatch)
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.Nil(t, id)
			assert.Zero(t, op.hitCount("/token"))

			if name != "another login's binding" {
				assert.Zero(t, store.consumes.Load(), "a malformed binding never reaches the store")
			}

			_, err = c.Complete(context.Background(), callbackFor(victim, code))
			require.NoError(t, err, "the victim's own browser still completes the login")
		})
	}
}

// countingStore counts the Consume calls.
type countingStore struct {
	oidcclient.TransactionStore
	consumes atomic.Int64
}

func (s *countingStore) Consume(ctx context.Context, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
	s.consumes.Add(1)

	return s.TransactionStore.Consume(ctx, stateHash, bindingHash, now)
}

// nonCanonical returns another base64url spelling of the same 32 bytes: the
// last character of 43 carries two unused bits.
func nonCanonical(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	last := strings.IndexByte(alphabet, s[len(s)-1])

	return s[:len(s)-1] + string(alphabet[last|1])
}

func TestCompleteReplay(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)
	ar, code := op.begin(t, c, oidcclient.AuthOptions{})

	_, err := c.Complete(context.Background(), callbackFor(ar, code))
	require.NoError(t, err)

	id, err := c.Complete(context.Background(), callbackFor(ar, code))
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	assert.Nil(t, id)
	assert.Equal(t, 1, op.hitCount("/token"), "a replayed callback never reaches the token endpoint")
}

// TestCompleteConcurrentCallbacks checks that one callback delivered 50
// times concurrently yields exactly one identity and one code redemption.
func TestCompleteConcurrentCallbacks(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t)
	ar, code := op.begin(t, c, oidcclient.AuthOptions{})

	var (
		wg      sync.WaitGroup
		wins    atomic.Int64
		notFnd  atomic.Int64
		start   = make(chan struct{})
		attempt = 50
	)

	for range attempt {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			id, err := c.Complete(context.Background(), callbackFor(ar, code))

			switch {
			case err == nil && id != nil:
				wins.Add(1)
			case errors.Is(err, oidcclient.ErrTransactionNotFound):
				notFnd.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), wins.Load())
	assert.Equal(t, int64(attempt-1), notFnd.Load())
	assert.Equal(t, 1, op.hitCount("/token"))
}

// lenientStore returns whatever transaction it is told to, ignoring the
// contract: it lets tests prove the Client's own checks.
type lenientStore struct {
	tx *oidcclient.Transaction
}

func (s *lenientStore) Save(context.Context, *oidcclient.Transaction) error { return nil }

func (s *lenientStore) Consume(context.Context, string, string, time.Time) (*oidcclient.Transaction, error) {
	tx := *s.tx

	return &tx, nil
}

func TestCompleteExpired(t *testing.T) {
	t.Parallel()

	t.Run("store refuses", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		c := op.client(t)
		ar, code := op.begin(t, c, oidcclient.AuthOptions{})

		op.clock.Advance(10 * time.Minute) // now == ExpiresAt

		_, err := c.Complete(context.Background(), callbackFor(ar, code))
		require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
		assert.Zero(t, op.hitCount("/token"))
	})

	t.Run("client refuses what a lenient store returns", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		store := newSpyStore()
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = store })
		ar, code := op.begin(t, c, oidcclient.AuthOptions{})

		tx := store.last(t)
		lenient := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = &lenientStore{tx: &tx} })

		op.clock.Advance(10 * time.Minute)

		_, err := lenient.Complete(context.Background(), callbackFor(ar, code))
		require.ErrorIs(t, err, oidcclient.ErrTransactionExpired)
		assert.Zero(t, op.hitCount("/token"))

		op.clock.Advance(-time.Second)

		_, err = lenient.Complete(context.Background(), callbackFor(ar, code))
		require.NoError(t, err, "one second before expiry")
	})
}

// TestCompleteTransactionMismatch checks that an intact transaction started
// by a Client of another connection, issuer, client, redirect URI or
// response mode is refused before the code is redeemed.
func TestCompleteTransactionMismatch(t *testing.T) {
	t.Parallel()

	other := newFakeOP(t)

	cases := map[string]struct {
		op     func(own *fakeOP) *fakeOP
		config func(*oidcclient.Config)
		mode   oidcclient.ResponseMode
	}{
		"connection": {config: func(cfg *oidcclient.Config) { cfg.ConnectionID = "other" }},
		"issuer":     {op: func(*fakeOP) *fakeOP { return other }},
		"client":     {config: func(cfg *oidcclient.Config) { cfg.ClientID = "other-client" }},
		"redirect": {config: func(cfg *oidcclient.Config) {
			cfg.RedirectURL = "https://rp.example.com/oidc/acme/callback?tenant=other"
		}},
		"response mode": {
			config: func(cfg *oidcclient.Config) { cfg.ResponseMode = oidcclient.ResponseModeFormPost },
			mode:   oidcclient.ResponseModeFormPost,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			store := newSpyStore()
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = store })
			ar, code := op.begin(t, c, oidcclient.AuthOptions{})
			tx := store.last(t)

			completing := op
			if tc.op != nil {
				completing = tc.op(op)
			}

			forged := completing.client(t, func(cfg *oidcclient.Config) {
				cfg.Store = &lenientStore{tx: &tx}
				if tc.config != nil {
					tc.config(cfg)
				}
			})

			cb := callbackFor(ar, code)
			if tc.mode != "" {
				cb.Mode = tc.mode
			}

			if name == "redirect" {
				cb.URL.RawQuery = "tenant=other&" + cb.URL.RawQuery
			}

			_, err := forged.Complete(context.Background(), cb)
			require.ErrorIs(t, err, oidcclient.ErrTransactionMismatch)
			assert.Zero(t, op.hitCount("/token"))
			assert.Zero(t, other.hitCount("/token"))
		})
	}
}

// tamperingStore stores transactions in memory and alters the one it
// returns, as an attacker with write access to a shared store could.
type tamperingStore struct {
	inner  oidcclient.TransactionStore
	mutate func(*oidcclient.Transaction)
}

func (s *tamperingStore) Save(ctx context.Context, tx *oidcclient.Transaction) error {
	return s.inner.Save(ctx, tx)
}

func (s *tamperingStore) Consume(ctx context.Context, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
	tx, err := s.inner.Consume(ctx, stateHash, bindingHash, now)
	if err == nil {
		s.mutate(tx)
	}

	return tx, err
}

// TestCompleteIntegrity checks the transaction integrity MAC: a transaction
// altered in the store — any field — fails the login before the code is
// redeemed.
func TestCompleteIntegrity(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*oidcclient.Transaction){
		"state hash":    func(tx *oidcclient.Transaction) { tx.StateHash = sha256Hex("another state") },
		"binding hash":  func(tx *oidcclient.Transaction) { tx.BindingHash = sha256Hex("another binding") },
		"connection":    func(tx *oidcclient.Transaction) { tx.ConnectionID += "x" },
		"issuer":        func(tx *oidcclient.Transaction) { tx.Issuer += "/x" },
		"client":        func(tx *oidcclient.Transaction) { tx.ClientID += "x" },
		"redirect":      func(tx *oidcclient.Transaction) { tx.RedirectURI += "?x=1" },
		"response mode": func(tx *oidcclient.Transaction) { tx.ResponseMode = oidcclient.ResponseModeFormPost },
		"max age":       func(tx *oidcclient.Transaction) { tx.MaxAge = 60 },
		"acr values":    func(tx *oidcclient.Transaction) { tx.ACRValues = "urn:acr:bronze" },
		"app state":     func(tx *oidcclient.Transaction) { tx.AppState = "return=https://evil.example/" },
		"created at":    func(tx *oidcclient.Transaction) { tx.CreatedAt = tx.CreatedAt.Add(-time.Second) },
		"expires at":    func(tx *oidcclient.Transaction) { tx.ExpiresAt = tx.ExpiresAt.Add(time.Hour) },
		"integrity":     func(tx *oidcclient.Transaction) { tx.Integrity = sha256Hex("forged") },
		"fields swapped": func(tx *oidcclient.Transaction) {
			tx.ACRValues, tx.AppState = tx.AppState, tx.ACRValues
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t, func(cfg *oidcclient.Config) {
				cfg.Store = &tamperingStore{inner: memory.New(), mutate: mutate}
			})
			ar, code := op.begin(t, c, oidcclient.AuthOptions{AppState: "return=/settings"})

			id, err := c.Complete(context.Background(), callbackFor(ar, code))
			require.ErrorIs(t, err, oidcclient.ErrTransactionIntegrity)
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.Nil(t, id)
			assert.Zero(t, op.hitCount("/token"))
		})
	}

	t.Run("intact transaction", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		c := op.client(t, func(cfg *oidcclient.Config) {
			cfg.Store = &tamperingStore{inner: memory.New(), mutate: func(*oidcclient.Transaction) {}}
		})
		ar, code := op.begin(t, c, oidcclient.AuthOptions{AppState: "return=/settings"})

		id, err := c.Complete(context.Background(), callbackFor(ar, code))
		require.NoError(t, err)
		assert.Equal(t, "return=/settings", id.AppState)
	})
}

// TestCompleteIntegrityStepUp replays the store-write attack of the code
// review: the step-up requirements of a login are stripped in the store
// while the provider authenticated more weakly than requested.
func TestCompleteIntegrityStepUp(t *testing.T) {
	t.Parallel()

	maxAge := 5 * time.Minute

	cases := map[string]struct {
		opts   oidcclient.AuthOptions
		claims func(map[string]any)
		strip  func(*oidcclient.Transaction)
		intact error
	}{
		"acr_values": {
			opts:   oidcclient.AuthOptions{ACRValues: []string{"urn:acr:gold"}},
			claims: func(c map[string]any) { c["acr"] = "urn:acr:bronze" },
			strip:  func(tx *oidcclient.Transaction) { tx.ACRValues = "" },
			intact: oidcclient.ErrIDTokenACR,
		},
		"max_age": {
			opts:   oidcclient.AuthOptions{MaxAge: &maxAge},
			claims: func(c map[string]any) { c["auth_time"] = testNow.Add(-24 * time.Hour).Unix() },
			strip:  func(tx *oidcclient.Transaction) { tx.MaxAge = oidcclient.NoMaxAge },
			intact: oidcclient.ErrIDTokenAuthTime,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, tampered := range []bool{false, true} {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.claimsHook = func(_ *grant, c map[string]any) { tc.claims(c) } })

				mutate := func(*oidcclient.Transaction) {}
				if tampered {
					mutate = tc.strip
				}

				c := op.client(t, func(cfg *oidcclient.Config) {
					cfg.Store = &tamperingStore{inner: memory.New(), mutate: mutate}
				})
				ar, code := op.begin(t, c, tc.opts)

				_, err := c.Complete(context.Background(), callbackFor(ar, code))
				if tampered {
					require.ErrorIs(t, err, oidcclient.ErrTransactionIntegrity)
				} else {
					require.ErrorIs(t, err, tc.intact)
				}
			}
		})
	}
}

// nilStore breaks the contract: no transaction and no error.
type nilStore struct{}

func (nilStore) Save(context.Context, *oidcclient.Transaction) error { return nil }

func (nilStore) Consume(context.Context, string, string, time.Time) (*oidcclient.Transaction, error) {
	return nil, nil //nolint:nilnil // the contract violation under test
}

func TestCompleteNilTransaction(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = nilStore{} })
	ar, code := op.begin(t, c, oidcclient.AuthOptions{})

	id, err := c.Complete(context.Background(), callbackFor(ar, code))
	require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound)
	assert.Nil(t, id)
	assert.Zero(t, op.hitCount("/token"))
}

// TestCompleteMixUp plays RFC 9700 §4.4.1 against a broker with two
// connections sharing one store: A (attacker-controlled OP) and H (honest
// OP, no RFC 9207). The victim starts a login on A; A sends the victim to H
// with A's state; H returns a code to H's redirect URI. Distinct redirect
// URIs (RFC 9700 §4.4.2.2) stop it before any code reaches a token
// endpoint.
func TestCompleteMixUp(t *testing.T) {
	t.Parallel()

	store := memory.New()
	attackerOP, honestOP := newFakeOP(t), newFakeOP(t)

	clientA := attackerOP.client(t, func(cfg *oidcclient.Config) {
		cfg.ConnectionID = "tenant-a"
		cfg.RedirectURL = "https://rp.example.com/oidc/tenant-a/callback"
		cfg.Store = store
	})
	clientH := honestOP.client(t, func(cfg *oidcclient.Config) {
		cfg.ConnectionID = "honest"
		cfg.RedirectURL = "https://rp.example.com/oidc/honest/callback"
		cfg.Store = store
	})

	victimA, err := clientA.Begin(context.Background(), oidcclient.AuthOptions{})
	require.NoError(t, err)

	// The attacker's OP redirects the victim to the honest OP with A's
	// state; the honest OP issues a code and redirects to H's callback.
	honestURL, err := clientH.Begin(context.Background(), oidcclient.AuthOptions{})
	require.NoError(t, err)

	honestCode := honestOP.authorize(t, strings.Replace(honestURL.URL, url.QueryEscape(honestURL.State), url.QueryEscape(victimA.State), 1))

	response := url.Values{"code": {honestCode}, "state": {victimA.State}}

	t.Run("delivered on H's callback", func(t *testing.T) {
		_, err := clientH.Complete(context.Background(), oidcclient.Callback{
			Mode: oidcclient.ResponseModeQuery, URL: receivedOn("https://rp.example.com/oidc/honest/callback"), Params: response, Binding: victimA.Binding,
		})
		require.ErrorIs(t, err, oidcclient.ErrTransactionMismatch)
	})

	t.Run("misrouted to A's client", func(t *testing.T) {
		_, err := clientA.Complete(context.Background(), oidcclient.Callback{
			Mode: oidcclient.ResponseModeQuery, URL: receivedOn("https://rp.example.com/oidc/honest/callback"), Params: response, Binding: victimA.Binding,
		})
		require.ErrorIs(t, err, oidcclient.ErrInvalidCallback, "a response received on another connection's path")
	})

	t.Run("with iss of H on A's callback", func(t *testing.T) {
		victim2, err := clientA.Begin(context.Background(), oidcclient.AuthOptions{})
		require.NoError(t, err)

		_, err = clientA.Complete(context.Background(), oidcclient.Callback{
			Mode: oidcclient.ResponseModeQuery, URL: receivedOn("https://rp.example.com/oidc/tenant-a/callback"), Binding: victim2.Binding,
			Params: url.Values{"code": {honestCode}, "state": {victim2.State}, "iss": {honestOP.issuer}},
		})
		require.ErrorIs(t, err, oidcclient.ErrIssuerParameter)
	})

	assert.Zero(t, attackerOP.hitCount("/token"))
	assert.Zero(t, honestOP.hitCount("/token"))
}

// TestCompleteCallbackURL checks RFC 9700 §4.4.2.2: the URL a response was
// received on must be the connection's redirect URI — scheme, host and
// port compared as URL parts, the path exactly, and the redirect URI's own
// query parameters present with their values.
func TestCompleteCallbackURL(t *testing.T) {
	t.Parallel()

	const redirect = "https://rp.example.com/oidc/acme/callback?tenant=acme"

	cases := []struct {
		received string
		ok       bool
	}{
		{"https://rp.example.com/oidc/acme/callback?tenant=acme", true},
		{"https://rp.example.com:443/oidc/acme/callback?tenant=acme", true},
		{"https://RP.Example.COM/oidc/acme/callback?tenant=acme", true},
		{"HTTPS://rp.example.com/oidc/acme/callback?tenant=acme", true},
		{"https://rp.example.com/oidc/acme/callback?other=1&tenant=acme", true},
		{"https://rp.example.com/oidc/acme/callback", false},
		{"https://rp.example.com/oidc/acme/callback?tenant=globex", false},
		{"https://rp.example.com/oidc/acme/callback?tenant=acme&tenant=globex", false},
		{"https://rp.example.com/oidc/acme/callback?tenant=", false},
		{"https://rp.example.com:80/oidc/acme/callback?tenant=acme", false},
		{"http://rp.example.com:443/oidc/acme/callback?tenant=acme", false},
		{"https://rp.example.com./oidc/acme/callback?tenant=acme", false},
		{"https://rp.example.com/oidc/ACME/callback?tenant=acme", false},
	}

	for _, tc := range cases {
		t.Run(tc.received, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.RedirectURL = redirect })
			ar, code := op.begin(t, c, oidcclient.AuthOptions{})

			cb := callbackFor(ar, code)
			cb.URL = receivedOn(tc.received)

			_, err := c.Complete(context.Background(), cb)
			if tc.ok {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, oidcclient.ErrInvalidCallback)
			assert.Zero(t, op.hitCount("/token"))
		})
	}
}

// TestCompleteLoopbackHTTPRedirect checks the default port of an http
// redirect URI (development on a loopback host).
func TestCompleteLoopbackHTTPRedirect(t *testing.T) {
	t.Parallel()

	cases := []struct {
		received string
		ok       bool
	}{
		{"http://localhost/cb", true},
		{"http://localhost:80/cb", true},
		{"http://localhost:443/cb", false},
		{"https://localhost/cb", false},
	}

	for _, tc := range cases {
		t.Run(tc.received, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.RedirectURL = "http://localhost/cb" })
			ar, code := op.begin(t, c, oidcclient.AuthOptions{})

			cb := callbackFor(ar, code)
			cb.URL = receivedOn(tc.received)

			_, err := c.Complete(context.Background(), cb)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, oidcclient.ErrInvalidCallback)
			}
		})
	}
}

// TestCompleteHostDistinctRedirectURIs replays the code review's probe:
// two connections sharing a store whose redirect URIs differ only by host
// (or only by query). A response received on B's URL handed to A's Client —
// by an application routing callbacks by state, which it must not — is
// refused.
func TestCompleteHostDistinctRedirectURIs(t *testing.T) {
	t.Parallel()

	pairs := map[string][2]string{
		"host":  {"https://a.rp.example.com/cb", "https://b.rp.example.com/cb"},
		"port":  {"https://rp.example.com:8443/cb", "https://rp.example.com:9443/cb"},
		"query": {"https://rp.example.com/cb?tenant=a", "https://rp.example.com/cb?tenant=b"},
	}

	for name, uris := range pairs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := memory.New()
			op := newFakeOP(t)
			clientA := op.client(t, func(cfg *oidcclient.Config) {
				cfg.ConnectionID, cfg.RedirectURL, cfg.Store = "a", uris[0], store
			})

			ar, code := op.begin(t, clientA, oidcclient.AuthOptions{})
			cb := callbackFor(ar, code)
			cb.URL = receivedOn(uris[1])

			_, err := clientA.Complete(context.Background(), cb)
			require.ErrorIs(t, err, oidcclient.ErrInvalidCallback)
			assert.Zero(t, op.hitCount("/token"))

			cb.URL = receivedOn(uris[0])
			_, err = clientA.Complete(context.Background(), cb)
			require.NoError(t, err, "the transaction was left untouched")
		})
	}
}

// TestCompleteRefusesMalformedCallbacks checks the callback shape — mode,
// URL, RFC 6749 §3.1 parameter uniqueness, syntax and sizes — before any
// transaction is touched.
func TestCompleteRefusesMalformedCallbacks(t *testing.T) {
	t.Parallel()

	cases := map[string]func(cb *oidcclient.Callback, ar *oidcclient.AuthRequest){
		"form_post into a query client": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Mode = oidcclient.ResponseModeFormPost },
		"unknown mode":                  func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Mode = "fragment" },
		"other path": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.URL = receivedOn("https://rp.example.com/oidc/other/callback")
		},
		"path prefix": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.URL = receivedOn(testRedirectURL + "/x") },
		"empty path": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.URL = receivedOn("https://rp.example.com")
		},
		"no URL":       func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.URL = nil },
		"relative URL": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.URL = &url.URL{Path: testCallbackPath} },
		"other host": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.URL = receivedOn("https://other.example.com" + testCallbackPath)
		},
		"sub-domain": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.URL = receivedOn("https://tenant.rp.example.com" + testCallbackPath)
		},
		"other port": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.URL = receivedOn("https://rp.example.com:8443" + testCallbackPath)
		},
		"other scheme": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.URL = receivedOn("http://rp.example.com" + testCallbackPath)
		},
		"duplicate state": func(cb *oidcclient.Callback, ar *oidcclient.AuthRequest) {
			cb.Params["state"] = []string{ar.State, ar.State}
		},
		"empty then real state": func(cb *oidcclient.Callback, ar *oidcclient.AuthRequest) {
			cb.Params["state"] = []string{"", ar.State}
		},
		"duplicate code":  func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params["code"] = []string{"a", "b"} },
		"duplicate iss":   func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params["iss"] = []string{"a", "b"} },
		"duplicate error": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params["error"] = []string{"a", "b"} },
		"missing state":   func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params.Del("state") },
		"short state":     func(cb *oidcclient.Callback, ar *oidcclient.AuthRequest) { cb.Params.Set("state", ar.State[:42]) },
		"long state":      func(cb *oidcclient.Callback, ar *oidcclient.AuthRequest) { cb.Params.Set("state", ar.State+"A") },
		"state not base64url": func(cb *oidcclient.Callback, ar *oidcclient.AuthRequest) {
			cb.Params.Set("state", "+"+ar.State[1:])
		},
		"missing code":      func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params.Del("code") },
		"empty code":        func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params.Set("code", "") },
		"code with control": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params.Set("code", "a\nb") },
		"code too long": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.Params.Set("code", strings.Repeat("c", 8193))
		},
		"error and code": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params.Set("error", "access_denied") },
		"error with quote": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.Params.Del("code")
			cb.Params.Set("error", `bad"code`)
		},
		"error too long": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.Params.Del("code")
			cb.Params.Set("error", strings.Repeat("e", 257))
		},
		"iss with control": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) { cb.Params.Set("iss", "https://a\n") },
		"iss too long": func(cb *oidcclient.Callback, _ *oidcclient.AuthRequest) {
			cb.Params.Set("iss", strings.Repeat("i", 2049))
		},
	}

	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t)
			ar, code := op.begin(t, c, oidcclient.AuthOptions{})

			cb := callbackFor(ar, code)
			breakIt(&cb, ar)

			id, err := c.Complete(context.Background(), cb)
			require.ErrorIs(t, err, oidcclient.ErrInvalidCallback)
			assert.Nil(t, id)
			assert.Zero(t, op.hitCount("/token"))

			_, err = c.Complete(context.Background(), callbackFor(ar, code))
			require.NoError(t, err, "the transaction was not touched")
		})
	}

	t.Run("query response into a form_post client", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		c := op.client(t, func(cfg *oidcclient.Config) { cfg.ResponseMode = oidcclient.ResponseModeFormPost })
		ar, code := op.begin(t, c, oidcclient.AuthOptions{})

		_, err := c.Complete(context.Background(), callbackFor(ar, code))
		require.ErrorIs(t, err, oidcclient.ErrInvalidCallback)
	})

	t.Run("unrecognized parameters are ignored", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		c := op.client(t)
		ar, code := op.begin(t, c, oidcclient.AuthOptions{})

		cb := callbackFor(ar, code)
		cb.Params["session_state"] = []string{"a", "b"}
		cb.Params.Set("tenant", "acme")

		_, err := c.Complete(context.Background(), cb)
		require.NoError(t, err, "RFC 6749 §4.1.2: the client MUST ignore unrecognized response parameters")
	})
}

// TestCompleteIssParameter checks RFC 9207 §2.4.
func TestCompleteIssParameter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		advertised bool
		iss        func(op *fakeOP) []string
		ok         bool
	}{
		{"advertised and equal", true, func(op *fakeOP) []string { return []string{op.issuer} }, true},
		{"advertised and missing", true, func(*fakeOP) []string { return nil }, false},
		{"advertised and empty", true, func(*fakeOP) []string { return []string{""} }, false},
		{"advertised and different", true, func(*fakeOP) []string { return []string{"https://other.example.com"} }, false},
		{"advertised, trailing slash", true, func(op *fakeOP) []string { return []string{op.issuer + "/"} }, false},
		{"not advertised and absent", false, func(*fakeOP) []string { return nil }, true},
		{"not advertised and empty", false, func(*fakeOP) []string { return []string{""} }, true},
		{"not advertised and equal", false, func(op *fakeOP) []string { return []string{op.issuer} }, true},
		{"not advertised and different", false, func(*fakeOP) []string { return []string{"https://other.example.com"} }, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.metadata["authorization_response_iss_parameter_supported"] = tc.advertised })
			c := op.client(t)
			ar, code := op.begin(t, c, oidcclient.AuthOptions{})

			cb := callbackFor(ar, code)
			if iss := tc.iss(op); iss != nil {
				cb.Params["iss"] = iss
			}

			_, err := c.Complete(context.Background(), cb)
			if tc.ok {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, oidcclient.ErrIssuerParameter)
			assert.Zero(t, op.hitCount("/token"))
		})
	}

	t.Run("error response without iss when advertised", func(t *testing.T) {
		t.Parallel()

		op := newFakeOP(t)
		op.set(func(op *fakeOP) { op.metadata["authorization_response_iss_parameter_supported"] = true })
		c := op.client(t)
		ar, _ := op.begin(t, c, oidcclient.AuthOptions{})

		_, err := c.Complete(context.Background(), oidcclient.Callback{
			Mode: oidcclient.ResponseModeQuery, URL: receivedOn(testRedirectURL), Binding: ar.Binding,
			Params: url.Values{"error": {"access_denied"}, "state": {ar.State}},
		})
		require.ErrorIs(t, err, oidcclient.ErrIssuerParameter, "RFC 9207 §2.4: an error is not trusted either")
	})
}

// TestCompleteAuthorizationError checks the error response of RFC 6749
// §4.1.2.1 / Core §3.1.2.6, returned once matched to its transaction.
func TestCompleteAuthorizationError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		params url.Values
		want   oidcclient.AuthorizationError
	}{
		{
			"full", url.Values{"error": {"login_required"}, "error_description": {"Login required"}, "error_uri": {"https://op.example.com/e"}},
			oidcclient.AuthorizationError{Code: "login_required", Description: "Login required", URI: "https://op.example.com/e"},
		},
		{"code only", url.Values{"error": {"access_denied"}}, oidcclient.AuthorizationError{Code: "access_denied"}},
		{
			"description outside charset dropped", url.Values{"error": {"access_denied"}, "error_description": {`say "no"`}},
			oidcclient.AuthorizationError{Code: "access_denied"},
		},
		{
			"uri outside charset dropped", url.Values{"error": {"access_denied"}, "error_uri": {"https://op.example.com/a b"}},
			oidcclient.AuthorizationError{Code: "access_denied"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			c := op.client(t)
			ar, _ := op.begin(t, c, oidcclient.AuthOptions{})

			params := tc.params
			params.Set("state", ar.State)

			id, err := c.Complete(context.Background(), oidcclient.Callback{
				Mode: oidcclient.ResponseModeQuery, URL: receivedOn(testRedirectURL), Params: params, Binding: ar.Binding,
			})
			require.ErrorIs(t, err, oidcclient.ErrAuthorizationFailed)
			assert.Nil(t, id)

			var authErr *oidcclient.AuthorizationError
			require.ErrorAs(t, err, &authErr)
			assert.Equal(t, tc.want, *authErr)
			assert.Equal(t, "oidcclient: authorization failed: "+tc.want.Code, err.Error())
			assert.Zero(t, op.hitCount("/token"))

			_, err = c.Complete(context.Background(), oidcclient.Callback{
				Mode: oidcclient.ResponseModeQuery, URL: receivedOn(testRedirectURL), Params: params, Binding: ar.Binding,
			})
			require.ErrorIs(t, err, oidcclient.ErrTransactionNotFound, "the transaction is over")
		})
	}
}

// TestCompleteNeverFetchesFromCallback checks that an issuer named in the
// callback is only compared, never contacted.
func TestCompleteNeverFetchesFromCallback(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	t.Cleanup(other.Close)

	op := newFakeOP(t)
	c := op.client(t)
	ar, code := op.begin(t, c, oidcclient.AuthOptions{})

	cb := callbackFor(ar, code)
	cb.Params.Set("iss", other.URL)

	_, err := c.Complete(context.Background(), cb)
	require.ErrorIs(t, err, oidcclient.ErrIssuerParameter)
	assert.Zero(t, hits.Load())
}
