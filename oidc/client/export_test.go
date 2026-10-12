// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

// ForgeIntegrity computes the Transaction.Integrity of tx the way the
// package does, with key as the server-held transaction key and binding
// as the login's binding secret: what an attacker holding the binding of a
// login it runs itself can compute with a key of its choosing. Tests only.
func ForgeIntegrity(key []byte, binding string, tx *Transaction) string {
	secret, ok := decodeSecret(binding)
	if !ok {
		panic("oidcclient: ForgeIntegrity: malformed binding")
	}

	return integrityFor(key, secret, tx)
}
