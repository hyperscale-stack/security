// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() samlsp.Config {
	store := memory.New()

	return samlsp.Config{
		Connections:     newResolver(),
		Transactions:    store,
		ReplayCache:     store,
		TransactionKeys: testTransactionKeys,
	}
}

func TestNew_ValidatesConfig(t *testing.T) {
	t.Parallel()

	k := keys(t)

	cases := []struct {
		name   string
		mutate func(*samlsp.Config)
	}{
		{"missing connections", func(c *samlsp.Config) { c.Connections = nil }},
		{"missing transactions", func(c *samlsp.Config) { c.Transactions = nil }},
		{"missing replay cache", func(c *samlsp.Config) { c.ReplayCache = nil }},
		{"missing transaction keys", func(c *samlsp.Config) { c.TransactionKeys = nil }},
		{"empty transaction key list", func(c *samlsp.Config) { c.TransactionKeys = [][]byte{} }},
		{"transaction key of 31 bytes", func(c *samlsp.Config) { c.TransactionKeys = [][]byte{make([]byte, samlsp.MinTransactionKeySize-1)} }},
		{"nil transaction key", func(c *samlsp.Config) { c.TransactionKeys = [][]byte{nil} }},
		{"a short key after a good one", func(c *samlsp.Config) {
			c.TransactionKeys = [][]byte{make([]byte, 32), []byte("short")}
		}},
		{"five transaction keys", func(c *samlsp.Config) {
			c.TransactionKeys = [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)}
		}},
		{"TTL below 1s", func(c *samlsp.Config) { c.TransactionTTL = time.Millisecond }},
		{"TTL above max", func(c *samlsp.Config) { c.TransactionTTL = samlsp.MaxTransactionTTL + time.Second }},
		{"negative skew", func(c *samlsp.Config) { c.ClockSkew = -time.Second }},
		{"skew above max", func(c *samlsp.Config) { c.ClockSkew = samlsp.MaxClockSkew + time.Second }},
		{"response size too small", func(c *samlsp.Config) { c.MaxResponseSize = samlsp.MinMaxResponseSize - 1 }},
		{"response size too large", func(c *samlsp.Config) { c.MaxResponseSize = samlsp.MaxMaxResponseSize + 1 }},
		{"metadata cache too short", func(c *samlsp.Config) { c.MetadataCacheDuration = time.Second }},
		{"metadata cache too long", func(c *samlsp.Config) { c.MetadataCacheDuration = 31 * 24 * time.Hour }},
		{"cookie without __Host- prefix", func(c *samlsp.Config) { c.CookieName = "samlsp" }},
		{"cookie __Secure- prefix", func(c *samlsp.Config) { c.CookieName = "__Secure-samlsp" }},
		{"cookie prefix only", func(c *samlsp.Config) { c.CookieName = "__Host-" }},
		{"cookie with space", func(c *samlsp.Config) { c.CookieName = "__Host-a b" }},
		{"cookie with semicolon", func(c *samlsp.Config) { c.CookieName = "__Host-a;b" }},
		{"cookie too long", func(c *samlsp.Config) { c.CookieName = "__Host-" + strings.Repeat("a", 60) }},
		{"certificate without key", func(c *samlsp.Config) { c.SigningCertificate = k.sp.cert }},
		{"additional certificate without key", func(c *samlsp.Config) {
			c.AdditionalSigningCertificates = []*x509.Certificate{k.spNext.cert}
		}},
		{"key without certificate", func(c *samlsp.Config) { c.SigningKey = k.sp.signer }},
		{"certificate of another key", func(c *samlsp.Config) {
			c.SigningKey, c.SigningCertificate = k.sp.signer, k.idpA.cert
		}},
		{"ECDSA signing key", func(c *samlsp.Config) {
			c.SigningKey, c.SigningCertificate = k.idpEC.signer, k.idpEC.cert
		}},
		{"weak RSA signing key", func(c *samlsp.Config) {
			c.SigningKey, c.SigningCertificate = k.weakRSA.signer, k.weakRSA.cert
		}},
		{"too many additional certificates", func(c *samlsp.Config) {
			c.SigningKey, c.SigningCertificate = k.sp.signer, k.sp.cert
			c.AdditionalSigningCertificates = []*x509.Certificate{k.idpA.cert, k.idpB.cert, k.attacker.cert, k.spNext.cert, k.expired.cert}
		}},
		{"nil additional certificate", func(c *samlsp.Config) {
			c.SigningKey, c.SigningCertificate = k.sp.signer, k.sp.cert
			c.AdditionalSigningCertificates = []*x509.Certificate{nil}
		}},
		{"ECDSA additional certificate", func(c *samlsp.Config) {
			c.SigningKey, c.SigningCertificate = k.sp.signer, k.sp.cert
			c.AdditionalSigningCertificates = []*x509.Certificate{k.idpEC.cert}
		}},
		{"weak additional certificate", func(c *samlsp.Config) {
			c.SigningKey, c.SigningCertificate = k.sp.signer, k.sp.cert
			c.AdditionalSigningCertificates = []*x509.Certificate{k.weakRSA.cert}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			tc.mutate(&cfg)

			sp, err := samlsp.New(cfg)
			require.ErrorIs(t, err, samlsp.ErrInvalidConfig)
			assert.Nil(t, sp)

			for _, key := range cfg.TransactionKeys {
				if len(key) > 0 {
					assert.NotContains(t, err.Error(), string(key), "an error never echoes a key")
				}
			}
		})
	}
}

func TestNew_AcceptsBoundsAndDefaults(t *testing.T) {
	t.Parallel()

	k := keys(t)

	cases := []struct {
		name   string
		mutate func(*samlsp.Config)
	}{
		{"defaults", func(*samlsp.Config) {}},
		{"maximum bounds", func(c *samlsp.Config) {
			c.TransactionTTL = samlsp.MaxTransactionTTL
			c.ClockSkew = samlsp.MaxClockSkew
			c.MaxResponseSize = samlsp.MaxMaxResponseSize
			c.MetadataCacheDuration = 30 * 24 * time.Hour
		}},
		{"minimum bounds", func(c *samlsp.Config) {
			c.TransactionTTL = time.Second
			c.MaxResponseSize = samlsp.MinMaxResponseSize
			c.MetadataCacheDuration = time.Minute
		}},
		{"custom cookie", func(c *samlsp.Config) { c.CookieName = "__Host-tenant-sso" }},
		{"four transaction keys of the minimum size", func(c *samlsp.Config) {
			c.TransactionKeys = [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)}
		}},
		{"signing key with rollover certificates", func(c *samlsp.Config) {
			c.SigningKey, c.SigningCertificate = k.sp.signer, k.sp.cert
			c.AdditionalSigningCertificates = []*x509.Certificate{k.spNext.cert}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			tc.mutate(&cfg)

			sp, err := samlsp.New(cfg)
			require.NoError(t, err)
			require.NotNil(t, sp)
		})
	}
}
