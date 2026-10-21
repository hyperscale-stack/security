// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"strings"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validTransaction() *oidcclient.Transaction {
	now := time.Unix(1_800_000_000, 0).UTC()

	return &oidcclient.Transaction{
		StateHash:    strings.Repeat("a", 64),
		BindingHash:  strings.Repeat("b", 64),
		ConnectionID: "acme-okta",
		Issuer:       "https://idp.example.com",
		ClientID:     "client 1",
		RedirectURI:  "https://rp.example.com/callback?x=1",
		ResponseMode: oidcclient.ResponseModeQuery,
		MaxAge:       oidcclient.NoMaxAge,
		ACRValues:    "urn:a urn:b",
		AppState:     "é",
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Minute),
		Integrity:    strings.Repeat("c", 64),
	}
}

func TestTransactionValidate(t *testing.T) {
	t.Parallel()

	require.NoError(t, validTransaction().Validate())

	var nilTx *oidcclient.Transaction
	require.ErrorIs(t, nilTx.Validate(), oidcclient.ErrInvalidTransaction)

	cases := map[string]func(*oidcclient.Transaction){
		"state hash too short":    func(tx *oidcclient.Transaction) { tx.StateHash = strings.Repeat("a", 63) },
		"state hash not hex":      func(tx *oidcclient.Transaction) { tx.StateHash = strings.Repeat("g", 64) },
		"state hash upper case":   func(tx *oidcclient.Transaction) { tx.StateHash = strings.Repeat("A", 64) },
		"binding hash too long":   func(tx *oidcclient.Transaction) { tx.BindingHash = strings.Repeat("b", 65) },
		"empty integrity":         func(tx *oidcclient.Transaction) { tx.Integrity = "" },
		"integrity too short":     func(tx *oidcclient.Transaction) { tx.Integrity = strings.Repeat("c", 63) },
		"integrity upper case":    func(tx *oidcclient.Transaction) { tx.Integrity = strings.Repeat("C", 64) },
		"empty connection":        func(tx *oidcclient.Transaction) { tx.ConnectionID = "" },
		"connection with space":   func(tx *oidcclient.Transaction) { tx.ConnectionID = "acme okta" },
		"connection non-ASCII":    func(tx *oidcclient.Transaction) { tx.ConnectionID = "acmé" },
		"connection too long":     func(tx *oidcclient.Transaction) { tx.ConnectionID = strings.Repeat("c", 256) },
		"empty issuer":            func(tx *oidcclient.Transaction) { tx.Issuer = "" },
		"issuer with space":       func(tx *oidcclient.Transaction) { tx.Issuer = "https://idp example" },
		"issuer too long":         func(tx *oidcclient.Transaction) { tx.Issuer = strings.Repeat("i", 2049) },
		"empty client":            func(tx *oidcclient.Transaction) { tx.ClientID = "" },
		"client with control":     func(tx *oidcclient.Transaction) { tx.ClientID = "a\tb" },
		"client too long":         func(tx *oidcclient.Transaction) { tx.ClientID = strings.Repeat("c", 2049) },
		"empty redirect":          func(tx *oidcclient.Transaction) { tx.RedirectURI = "" },
		"redirect with space":     func(tx *oidcclient.Transaction) { tx.RedirectURI = "https://rp/ cb" },
		"redirect too long":       func(tx *oidcclient.Transaction) { tx.RedirectURI = strings.Repeat("r", 2049) },
		"empty response mode":     func(tx *oidcclient.Transaction) { tx.ResponseMode = "" },
		"fragment response mode":  func(tx *oidcclient.Transaction) { tx.ResponseMode = "fragment" },
		"max age below NoMaxAge":  func(tx *oidcclient.Transaction) { tx.MaxAge = -2 },
		"max age over 2^31-1":     func(tx *oidcclient.Transaction) { tx.MaxAge = 1 << 31 },
		"acr values with control": func(tx *oidcclient.Transaction) { tx.ACRValues = "a\nb" },
		"acr values too long":     func(tx *oidcclient.Transaction) { tx.ACRValues = strings.Repeat("a", 2049) },
		"app state too long":      func(tx *oidcclient.Transaction) { tx.AppState = strings.Repeat("a", 4097) },
		"app state invalid UTF-8": func(tx *oidcclient.Transaction) { tx.AppState = "a\xffb" },
		"zero created":            func(tx *oidcclient.Transaction) { tx.CreatedAt = time.Time{} },
		"zero expiry":             func(tx *oidcclient.Transaction) { tx.ExpiresAt = time.Time{} },
		"expiry equals creation":  func(tx *oidcclient.Transaction) { tx.ExpiresAt = tx.CreatedAt },
		"sub-second created":      func(tx *oidcclient.Transaction) { tx.CreatedAt = tx.CreatedAt.Add(time.Nanosecond) },
		"sub-second expiry":       func(tx *oidcclient.Transaction) { tx.ExpiresAt = tx.ExpiresAt.Add(time.Millisecond) },
	}

	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tx := validTransaction()
			breakIt(tx)
			require.ErrorIs(t, tx.Validate(), oidcclient.ErrInvalidTransaction)
		})
	}

	t.Run("boundaries accepted", func(t *testing.T) {
		t.Parallel()

		tx := validTransaction()
		tx.ConnectionID = strings.Repeat("c", 255)
		tx.Issuer = strings.Repeat("i", 2048)
		tx.ClientID = strings.Repeat("c", 2048)
		tx.RedirectURI = strings.Repeat("r", 2048)
		tx.ResponseMode = oidcclient.ResponseModeFormPost
		tx.MaxAge = 1<<31 - 1
		tx.ACRValues = strings.Repeat("a", 2048)
		tx.AppState = strings.Repeat("é", 2048)
		assert.NoError(t, tx.Validate())

		tx.MaxAge = 0
		assert.NoError(t, tx.Validate())
	})
}

// TestValidateStoreKey accepts exactly 64 lowercase hex digits; every
// refusal matches ErrInvalidTransaction.
func TestValidateStoreKey(t *testing.T) {
	t.Parallel()

	require.NoError(t, oidcclient.ValidateStoreKey(strings.Repeat("0123456789abcdef", 4)))

	for name, key := range map[string]string{
		"empty":          "",
		"63 digits":      strings.Repeat("a", 63),
		"65 digits":      strings.Repeat("a", 65),
		"upper-case":     strings.Repeat("A", 64),
		"non-hex":        strings.Repeat("g", 64),
		"trailing space": strings.Repeat("a", 63) + " ",
		"NUL":            strings.Repeat("a", 63) + "\x00",
		"multi-byte":     strings.Repeat("a", 62) + "é",
	} {
		assert.ErrorIs(t, oidcclient.ValidateStoreKey(key), oidcclient.ErrInvalidTransaction, name)
	}
}
