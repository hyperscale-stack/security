// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestIntegrityKnownAnswer pins the construction of Transaction.Integrity
// — HMAC-SHA256 keyed by HMAC-SHA256(binding secret,
// "oidcclient/integrity/v1"), over the netstrings of every other field in
// declaration order — against a value computed independently (Python
// hmac). Changing it breaks the logins in flight during a rolling upgrade.
func TestIntegrityKnownAnswer(t *testing.T) {
	t.Parallel()

	secret := make([]byte, secretSize)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	created := time.Unix(1_800_000_000, 0).UTC()
	tx := &Transaction{
		StateHash:    strings.Repeat("a", 64),
		BindingHash:  strings.Repeat("b", 64),
		ConnectionID: "acme",
		Issuer:       "https://idp.example.com",
		ClientID:     "client 1",
		RedirectURI:  "https://rp.example.com/cb",
		ResponseMode: ResponseModeFormPost,
		MaxAge:       300,
		ACRValues:    "urn:acr:gold",
		AppState:     "return=/settings é",
		CreatedAt:    created,
		ExpiresAt:    created.Add(10 * time.Minute),
	}

	assert.Equal(t, "0a844561159c48e2c84945b9ecf665fe14468f21c87b6dc8a695cf56b9599299", integrityFor(secret, tx))

	tx.ACRValues, tx.AppState = tx.AppState, tx.ACRValues
	assert.Equal(t, "7f374773acb8413151a4cc590cff1c15377d0b636460b79df81dbedaff6841ef", integrityFor(secret, tx))

	tx.Integrity = "ignored"
	assert.Equal(t, "7f374773acb8413151a4cc590cff1c15377d0b636460b79df81dbedaff6841ef", integrityFor(secret, tx),
		"the MAC never covers itself")
}
