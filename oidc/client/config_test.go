// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRejectsInvalidConfig checks every configuration rule; a refused
// configuration never reaches the network.
func TestNewRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	// Checked once every parallel case has run (a parent assertion after
	// the loop would run before them): every refusal comes before any
	// network access — the transaction keys' included.
	t.Cleanup(func() {
		assert.Zero(t, op.hitCount("/.well-known/openid-configuration"), "a refused configuration never reaches the network")
	})

	cases := map[string]func(*oidcclient.Config){
		"empty connection":              func(c *oidcclient.Config) { c.ConnectionID = "" },
		"connection with space":         func(c *oidcclient.Config) { c.ConnectionID = "acme okta" },
		"connection too long":           func(c *oidcclient.Config) { c.ConnectionID = strings.Repeat("c", 256) },
		"empty issuer":                  func(c *oidcclient.Config) { c.Issuer = "" },
		"http issuer":                   func(c *oidcclient.Config) { c.Issuer = strings.Replace(c.Issuer, "https://", "http://", 1) },
		"relative issuer":               func(c *oidcclient.Config) { c.Issuer = "/tenants/acme" },
		"issuer with query":             func(c *oidcclient.Config) { c.Issuer += "?tenant=acme" },
		"issuer with empty query":       func(c *oidcclient.Config) { c.Issuer += "?" },
		"issuer with fragment":          func(c *oidcclient.Config) { c.Issuer += "#x" },
		"issuer with userinfo":          func(c *oidcclient.Config) { c.Issuer = strings.Replace(c.Issuer, "https://", "https://u:p@", 1) },
		"issuer non-ASCII":              func(c *oidcclient.Config) { c.Issuer += "/é" },
		"issuer unparsable":             func(c *oidcclient.Config) { c.Issuer = "https://[::1" },
		"issuer opaque":                 func(c *oidcclient.Config) { c.Issuer = "https:idp.example.com" },
		"redirect unparsable":           func(c *oidcclient.Config) { c.RedirectURL = "https://[::1/cb" },
		"redirect opaque":               func(c *oidcclient.Config) { c.RedirectURL = "https:rp.example.com/cb" },
		"redirect malformed query":      func(c *oidcclient.Config) { c.RedirectURL += "?a=%zz" },
		"empty client":                  func(c *oidcclient.Config) { c.ClientID = "" },
		"client with control":           func(c *oidcclient.Config) { c.ClientID = "client\n1" },
		"no auth method":                func(c *oidcclient.Config) { c.AuthMethod = "" },
		"unsupported auth method":       func(c *oidcclient.Config) { c.AuthMethod = "private_key_jwt" },
		"basic without secret":          func(c *oidcclient.Config) { c.ClientSecret = "" },
		"post without secret":           func(c *oidcclient.Config) { c.AuthMethod = oidcclient.AuthMethodClientSecretPost; c.ClientSecret = "" },
		"none with secret":              func(c *oidcclient.Config) { c.AuthMethod = oidcclient.AuthMethodNone },
		"empty redirect":                func(c *oidcclient.Config) { c.RedirectURL = "" },
		"relative redirect":             func(c *oidcclient.Config) { c.RedirectURL = testCallbackPath },
		"http redirect":                 func(c *oidcclient.Config) { c.RedirectURL = "http://rp.example.com" + testCallbackPath },
		"redirect with fragment":        func(c *oidcclient.Config) { c.RedirectURL += "#x" },
		"redirect with userinfo":        func(c *oidcclient.Config) { c.RedirectURL = "https://u@rp.example.com/cb" },
		"redirect query with state":     func(c *oidcclient.Config) { c.RedirectURL += "?state=x" },
		"redirect query with code":      func(c *oidcclient.Config) { c.RedirectURL += "?code=x" },
		"redirect query with iss":       func(c *oidcclient.Config) { c.RedirectURL += "?iss=x" },
		"redirect query with error":     func(c *oidcclient.Config) { c.RedirectURL += "?error=x" },
		"redirect too long":             func(c *oidcclient.Config) { c.RedirectURL += strings.Repeat("a", 2048) },
		"scope with space":              func(c *oidcclient.Config) { c.Scopes = []string{"openid profile"} },
		"scope with quote":              func(c *oidcclient.Config) { c.Scopes = []string{`pro"file`} },
		"empty scope":                   func(c *oidcclient.Config) { c.Scopes = []string{""} },
		"fragment mode":                 func(c *oidcclient.Config) { c.ResponseMode = "fragment" },
		"unknown mode":                  func(c *oidcclient.Config) { c.ResponseMode = "web_message" },
		"no store":                      func(c *oidcclient.Config) { c.Store = nil },
		"negative ttl":                  func(c *oidcclient.Config) { c.TransactionTTL = -time.Second },
		"ttl over an hour":              func(c *oidcclient.Config) { c.TransactionTTL = time.Hour + time.Second },
		"sub-second ttl":                func(c *oidcclient.Config) { c.TransactionTTL = 1500 * time.Millisecond },
		"HS256 allowed":                 func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{"HS256"} },
		"none allowed":                  func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{"none"} },
		"unknown algorithm":             func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{"RS1"} },
		"empty trusted audience":        func(c *oidcclient.Config) { c.TrustedAudiences = []string{""} },
		"negative skew":                 func(c *oidcclient.Config) { c.ClockSkew = -time.Second },
		"skew over five minutes":        func(c *oidcclient.Config) { c.ClockSkew = 5*time.Minute + time.Second },
		"insecure cookies in form_post": func(c *oidcclient.Config) { c.InsecureCookies = true; c.ResponseMode = oidcclient.ResponseModeFormPost },
		"invalid outbound policy":       func(c *oidcclient.Config) { c.Outbound.MaxRedirects = -1 },
		"no transaction key":            func(c *oidcclient.Config) { c.TransactionKeys = nil },
		"short transaction key": func(c *oidcclient.Config) {
			c.TransactionKeys = [][]byte{make([]byte, oidcclient.MinTransactionKeySize-1)}
		},
		"empty transaction key after a valid one": func(c *oidcclient.Config) {
			c.TransactionKeys = [][]byte{testTransactionKey, nil}
		},
		"too many transaction keys": func(c *oidcclient.Config) {
			c.TransactionKeys = [][]byte{testTransactionKey, testTransactionKey, testTransactionKey, testTransactionKey, testTransactionKey}
		},
	}

	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, err := oidcclient.New(context.Background(), op.config(breakIt))
			require.ErrorIs(t, err, oidcclient.ErrInvalidConfig)
			assert.Nil(t, c)
		})
	}
}

// TestNewAcceptsBoundaries checks the accepted edges of the configuration.
func TestNewAcceptsBoundaries(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)

	cases := map[string]func(*oidcclient.Config){
		"loopback http redirect":      func(c *oidcclient.Config) { c.RedirectURL = "http://127.0.0.1:8080/cb" },
		"localhost http redirect":     func(c *oidcclient.Config) { c.RedirectURL = "http://localhost/cb" },
		"ipv6 loopback http redirect": func(c *oidcclient.Config) { c.RedirectURL = "http://[::1]:8080/cb" },
		"redirect with app query":     func(c *oidcclient.Config) { c.RedirectURL += "?tenant=acme" },
		"one hour ttl":                func(c *oidcclient.Config) { c.TransactionTTL = time.Hour },
		"five minutes skew":           func(c *oidcclient.Config) { c.ClockSkew = 5 * time.Minute },
		"public client":               func(c *oidcclient.Config) { c.AuthMethod = oidcclient.AuthMethodNone; c.ClientSecret = "" },
		"post client":                 func(c *oidcclient.Config) { c.AuthMethod = oidcclient.AuthMethodClientSecretPost },
		"form post":                   func(c *oidcclient.Config) { c.ResponseMode = oidcclient.ResponseModeFormPost },
		"single algorithm":            func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{oidcclient.ES256} },
		"insecure cookies query mode": func(c *oidcclient.Config) { c.InsecureCookies = true },
		"no explicit scopes":          func(c *oidcclient.Config) { c.Scopes = nil },
		"duplicated scopes":           func(c *oidcclient.Config) { c.Scopes = []string{"email", "openid", "email"} },
		"trusted audience":            func(c *oidcclient.Config) { c.TrustedAudiences = []string{"https://api.example.com"} },
		"four transaction keys": func(c *oidcclient.Config) {
			c.TransactionKeys = [][]byte{testTransactionKey, testTransactionKey, testTransactionKey, testTransactionKey}
		},
		"long transaction key": func(c *oidcclient.Config) { c.TransactionKeys = [][]byte{make([]byte, 64)} },
	}

	for name, tweak := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := oidcclient.New(context.Background(), op.config(tweak))
			require.NoError(t, err)
		})
	}
}

// TestNewCopiesConfigSlices checks that mutating the caller's slices after
// New does not change the Client.
func TestNewCopiesConfigSlices(t *testing.T) {
	t.Parallel()

	op := newFakeOP(t)
	scopes := []string{"openid", "profile"}
	c := op.client(t, func(cfg *oidcclient.Config) { cfg.Scopes = scopes })

	scopes[1] = "admin"

	ar, err := c.Begin(context.Background(), oidcclient.AuthOptions{})
	require.NoError(t, err)
	assert.Contains(t, ar.URL, "scope=openid+profile")
	assert.NotContains(t, ar.URL, "admin")

	audiences := []string{"https://api.example.com"}
	op.set(func(op *fakeOP) {
		op.claimsHook = func(_ *grant, claims map[string]any) {
			claims["aud"] = []string{testClientID, "https://api.example.com"}
		}
	})
	trusting := op.client(t, func(cfg *oidcclient.Config) { cfg.TrustedAudiences = audiences })
	audiences[0] = "https://other.example.com"

	_, err = op.login(t, trusting)
	require.NoError(t, err, "the Client kept its own copy of TrustedAudiences")

	plain := newFakeOP(t)
	key := bytes.Clone(testTransactionKey)
	keys := [][]byte{key}
	keyed := plain.client(t, func(cfg *oidcclient.Config) { cfg.TransactionKeys = keys })
	ar, code := plain.begin(t, keyed, oidcclient.AuthOptions{})

	key[0] ^= 0xff
	keys[0] = bytes.Repeat([]byte{0x33}, oidcclient.MinTransactionKeySize)

	_, err = keyed.Complete(context.Background(), callbackFor(ar, code))
	require.NoError(t, err, "the Client kept its own copy of TransactionKeys and of their bytes")
}
