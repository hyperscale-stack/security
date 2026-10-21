// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
)

// secretSize is the size of the state and of the binding secret: 256 bits,
// beyond the 2^-128 guessing bound of RFC 6749 §10.10.
const secretSize = 32

// encodedSecretLength is the base64url length of a secret.
const encodedSecretLength = 43

// Labels of the values derived from the binding secret. Each derived value
// is HMAC-SHA256(binding secret, label): independent pseudorandom values
// under one 256-bit key. labelIntegrity is the exception: it derives the
// integrity MAC key under a server-held transaction key (integrityKey).
const (
	labelNonce     = "oidcclient/nonce/v1"
	labelVerifier  = "oidcclient/code_verifier/v1"
	labelBinding   = "oidcclient/binding/v1"
	labelIntegrity = "oidcclient/integrity/v2"
)

// newSecret returns 256 bits from crypto/rand, base64url-encoded without
// padding (43 characters of the RFC 7636 §4.1 unreserved set).
func newSecret() string {
	b := make([]byte, secretSize)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (it aborts the program instead)

	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeSecret returns the bytes of a secret newSecret produced; anything
// else — wrong length, characters outside base64url, non-canonical
// trailing bits — is refused.
func decodeSecret(s string) ([]byte, bool) {
	if len(s) != encodedSecretLength {
		return nil, false
	}

	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, false
	}

	return b, true
}

func derive(secret []byte, label string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))

	return mac.Sum(nil)
}

// nonceFor is the nonce of the login whose binding secret is secret
// (OpenID Connect Core §15.5.2: a nonce derived from an HttpOnly cookie
// value).
func nonceFor(secret []byte) string {
	return base64.RawURLEncoding.EncodeToString(derive(secret, labelNonce))
}

// verifierFor is the PKCE code_verifier of the login: 43 characters of
// pseudorandom output under a 256-bit key (RFC 7636 §4.1, §7.1).
func verifierFor(secret []byte) string {
	return base64.RawURLEncoding.EncodeToString(derive(secret, labelVerifier))
}

// challengeFor is the S256 code_challenge of verifier (RFC 7636 §4.2).
func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// bindingHashFor is the Transaction.BindingHash of secret.
func bindingHashFor(secret []byte) string {
	return hex.EncodeToString(derive(secret, labelBinding))
}

// stateHashFor is the Transaction.StateHash of state.
func stateHashFor(state string) string {
	sum := sha256.Sum256([]byte(state))

	return hex.EncodeToString(sum[:])
}

// integrityKey is the MAC key of a transaction: HMAC-SHA256 keyed by the
// server-held transaction key over labelIntegrity then the 32-byte binding
// secret. Both secrets are needed: the binding secret ties the MAC to its
// login, the server key keeps whoever holds that secret — the user agent
// of the login included — from computing the MAC.
func integrityKey(serverKey, secret []byte) []byte {
	mac := hmac.New(sha256.New, serverKey)
	mac.Write([]byte(labelIntegrity))
	mac.Write(secret)

	return mac.Sum(nil)
}

// integrityFor is the Transaction.Integrity of tx under the transaction
// key serverKey and the binding secret: HMAC-SHA256 keyed by
// integrityKey(serverKey, secret), over every other field of tx, each as a
// netstring (length, ':', value, ',') so that no two transactions encode
// alike.
func integrityFor(serverKey, secret []byte, tx *Transaction) string {
	mac := hmac.New(sha256.New, integrityKey(serverKey, secret))

	for _, field := range []string{
		tx.StateHash, tx.BindingHash, tx.ConnectionID, tx.Issuer, tx.ClientID, tx.RedirectURI,
		string(tx.ResponseMode), strconv.FormatInt(tx.MaxAge, 10), tx.ACRValues, tx.AppState,
		strconv.FormatInt(tx.CreatedAt.Unix(), 10), strconv.FormatInt(tx.ExpiresAt.Unix(), 10),
	} {
		mac.Write([]byte(strconv.Itoa(len(field)) + ":" + field + ","))
	}

	return hex.EncodeToString(mac.Sum(nil))
}

// verifyIntegrity reports whether tx.Integrity is the MAC of tx under one
// of the transaction keys, comparing in constant time.
func verifyIntegrity(keys []Secret, secret []byte, tx *Transaction) bool {
	for _, key := range keys {
		if hmac.Equal([]byte(integrityFor([]byte(key.Reveal()), secret, tx)), []byte(tx.Integrity)) {
			return true
		}
	}

	return false
}
