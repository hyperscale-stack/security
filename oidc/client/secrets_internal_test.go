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

// byteRange returns the bytes from, from+1, …, from+n-1.
func byteRange(from byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = from + byte(i)
	}

	return b
}

// TestIntegrityKnownAnswer pins the construction of Transaction.Integrity
// — HMAC-SHA256 keyed by HMAC-SHA256(server key, "oidcclient/integrity/v2"
// ‖ binding secret), over the netstrings of every other field in
// declaration order — against values computed independently (Python
// hmac). Changing it fails the logins in flight during a rolling upgrade.
func TestIntegrityKnownAnswer(t *testing.T) {
	t.Parallel()

	secret := byteRange(1, secretSize)
	serverKey := byteRange(0x40, MinTransactionKeySize)

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

	assert.Equal(t, "d2d062cf6729d3221a024c755a114a32f3a35b23f12b38e09357cf178ae52934", integrityFor(serverKey, secret, tx))
	assert.Equal(t, "ed450b7be24c46bef974f064bbc9aa5e9b15db52ea57e22a0b068399dfec677a",
		integrityFor(byteRange(0x60, MinTransactionKeySize), secret, tx), "another server key, another MAC")

	tx.ACRValues, tx.AppState = tx.AppState, tx.ACRValues
	assert.Equal(t, "745d4a2df21eb698212cf6db6658ce0398839a3dbff679b224598a1a2ef2baae", integrityFor(serverKey, secret, tx))

	tx.Integrity = "ignored"
	assert.Equal(t, "745d4a2df21eb698212cf6db6658ce0398839a3dbff679b224598a1a2ef2baae", integrityFor(serverKey, secret, tx),
		"the MAC never covers itself")
}
