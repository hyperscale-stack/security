// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	jwtsec "github.com/hyperscale-stack/security/jwt"
)

// Example shows the canonical sign-then-verify flow used by an
// authorization server emitting RFC 9068-style JWT access tokens.
func Example() {
	// Operator: generate an ES256 key pair once at provisioning time.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signing := jwtsec.PrivateKey{KeyID: "k-1", Algorithm: jwtsec.ES256, Key: priv}
	verify := jwtsec.PublicKey{KeyID: "k-1", Algorithm: jwtsec.ES256, Key: &priv.PublicKey}

	// Authorization server side.
	signer := jwtsec.NewSigner(signing)

	token, err := signer.Sign(context.Background(), &jwtsec.StandardClaims{
		Issuer:   "https://auth.example",
		Subject:  "alice",
		Audience: jwtsec.Audience{"api"},
		Scope:    "read:mail",
	})
	if err != nil {
		fmt.Println("sign:", err)

		return
	}

	// Resource server side (e.g. behind an httpsec.Middleware).
	verifier := jwtsec.NewVerifier(
		jwtsec.NewStaticJWKS([]jwtsec.PublicKey{verify}),
		jwtsec.WithIssuer("https://auth.example"),
		jwtsec.WithAudience("api"),
	)

	claims, err := verifier.Verify(context.Background(), token, nil)
	if err != nil {
		fmt.Println("verify:", err)

		return
	}

	fmt.Println("sub:", claims.Subject, "scope:", claims.Scope)
	// Output:
	// sub: alice scope: read:mail
}
