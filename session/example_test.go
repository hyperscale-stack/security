// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/hyperscale-stack/security/session"
)

// Example demonstrates the cookie-session life cycle: Login writes an
// encrypted cookie, Get replays it, Rotate changes the ID after a
// privilege change, and Logout clears it.
func Example() {
	// A session key is 32 bytes or more from a cryptographic source — in
	// production, read it from your secret store (e.g. a base64 value made
	// with `openssl rand -base64 32`), never a passphrase. Keep the previous
	// key after the new one to rotate without signing everyone out.
	key := make([]byte, session.MinKeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	codec, err := session.NewCodec(key)
	if err != nil {
		panic(err)
	}

	mgr := session.NewManager(codec,
		session.WithSecure(false), // demo runs over plain HTTP
	)

	// --- login -----------------------------------------------------------
	login := newCarrier()

	s, err := mgr.Login(context.Background(), login, principal{sub: "alice"})
	if err != nil {
		panic(err)
	}

	fmt.Println("logged in:", s.GetString("sub"))

	// --- subsequent request reads the cookie -----------------------------
	got, err := mgr.Get(context.Background(), login.replay())
	if err != nil {
		panic(err)
	}

	fmt.Println("session sub:", got.GetString("sub"))
	fmt.Println("csrf present:", session.CSRFToken(got) != "")

	// --- rotate after a privilege change ---------------------------------
	rotated, err := mgr.Rotate(context.Background(), login.replay())
	if err != nil {
		panic(err)
	}

	fmt.Println("id changed on rotate:", rotated.ID != s.ID)

	// Output:
	// logged in: alice
	// session sub: alice
	// csrf present: true
	// id changed on rotate: true
}
