// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlinterop_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
)

// testTransactionKeys are the transaction keys of the interoperability
// tests (samlsp.Config.TransactionKeys; a constant, test only).
var testTransactionKeys = [][]byte{[]byte("samlsp interop transaction key, 32+ bytes, test only")}

// withIntegrity returns rec protected under the first test key with the
// documented MAC (samlsp.TransactionRecord.Integrity): the Keycloak
// captures pin the records a ServiceProvider saved, before records carried
// a MAC, and a capture's MAC depends on the key it was taken with.
func withIntegrity(rec samlsp.TransactionRecord) samlsp.TransactionRecord {
	kdf := hmac.New(sha256.New, testTransactionKeys[0])
	_, _ = kdf.Write([]byte("samlsp/transaction-integrity/v1"))

	mac := hmac.New(sha256.New, kdf.Sum(nil))

	for _, f := range []string{rec.ID, rec.BindingHash, rec.Payload, strconv.FormatInt(rec.ExpiresAt.Unix(), 10)} {
		_, _ = mac.Write([]byte(strconv.Itoa(len(f)) + ":" + f + ","))
	}

	rec.Integrity = hex.EncodeToString(mac.Sum(nil))

	return rec
}
