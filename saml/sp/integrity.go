// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// labelTransactionIntegrity derives the MAC key of the transactions from a
// transaction key, so that a key reused elsewhere (against the advice of
// Config.TransactionKeys) never yields the same MACs.
const labelTransactionIntegrity = "samlsp/transaction-integrity/v1"

// integrityFor is the TransactionRecord.Integrity of rec stored under id:
// hex(HMAC-SHA256(k, fields)), k = HMAC-SHA256(serverKey,
// labelTransactionIntegrity), over the ID, the binding hash, the payload and
// the expiry in Unix seconds, each as a netstring (length ":" value ",") so
// that no two records encode alike.
//
// Unlike oidcclient, the browser's binding is not mixed into k: in SAML the
// binding cookie is per browser rather than per login, the ID already makes
// every MAC specific to its login, and a MAC checked under the presented
// cookie would turn a wrong-browser POST (ErrBrowserBindingMismatch) into an
// integrity failure.
func integrityFor(serverKey []byte, id string, rec *TransactionRecord) string {
	kdf := hmac.New(sha256.New, serverKey)
	_, _ = kdf.Write([]byte(labelTransactionIntegrity))

	mac := hmac.New(sha256.New, kdf.Sum(nil))

	for _, field := range []string{id, rec.BindingHash, rec.Payload, strconv.FormatInt(rec.ExpiresAt.Unix(), 10)} {
		_, _ = mac.Write([]byte(strconv.Itoa(len(field)) + ":" + field + ","))
	}

	return hex.EncodeToString(mac.Sum(nil))
}

// verifyIntegrity reports whether rec.Integrity is the MAC of rec stored
// under id under one of the keys, comparing in constant time.
func verifyIntegrity(keys [][]byte, id string, rec *TransactionRecord) bool {
	for _, key := range keys {
		if hmac.Equal([]byte(integrityFor(key, id, rec)), []byte(rec.Integrity)) {
			return true
		}
	}

	return false
}
