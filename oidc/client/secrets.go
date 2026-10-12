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
)

// secretSize is the size of the state and of the binding secret: 256 bits,
// beyond the 2^-128 guessing bound of RFC 6749 §10.10.
const secretSize = 32

// encodedSecretLength is the base64url length of a secret.
const encodedSecretLength = 43

// Labels of the values derived from the binding secret. Each derived value
// is HMAC-SHA256(binding secret, label): independent pseudorandom values
// under one 256-bit key.
const (
	labelNonce    = "oidcclient/nonce/v1"
	labelVerifier = "oidcclient/code_verifier/v1"
	labelBinding  = "oidcclient/binding/v1"
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
