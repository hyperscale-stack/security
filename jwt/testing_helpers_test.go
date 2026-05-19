// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/stretchr/testify/require"
)

// genRSA generates a fresh 2048-bit RSA key pair for tests. RSA is the
// slowest of the supported algorithms; use sparingly.
func genRSA(t *testing.T) (jwtsec.PrivateKey, jwtsec.PublicKey) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return jwtsec.PrivateKey{KeyID: "rsa-1", Algorithm: jwtsec.RS256, Key: priv},
		jwtsec.PublicKey{KeyID: "rsa-1", Algorithm: jwtsec.RS256, Key: &priv.PublicKey}
}

// genECDSA generates a fresh P-256 key pair.
func genECDSA(t *testing.T) (jwtsec.PrivateKey, jwtsec.PublicKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return jwtsec.PrivateKey{KeyID: "ec-1", Algorithm: jwtsec.ES256, Key: priv},
		jwtsec.PublicKey{KeyID: "ec-1", Algorithm: jwtsec.ES256, Key: &priv.PublicKey}
}

// genEd25519 generates a fresh Ed25519 key pair.
func genEd25519(t *testing.T) (jwtsec.PrivateKey, jwtsec.PublicKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return jwtsec.PrivateKey{KeyID: "ed-1", Algorithm: jwtsec.EdDSA, Key: priv},
		jwtsec.PublicKey{KeyID: "ed-1", Algorithm: jwtsec.EdDSA, Key: pub}
}

// fixedClock is a [security.Clock] returning a static time, used to make
// expiry / not-before / issued-at tests deterministic.
type fixedClock struct{ now time.Time }

func newFixedClock(now time.Time) fixedClock { return fixedClock{now: now} }

func (c fixedClock) Now() time.Time { return c.now }
