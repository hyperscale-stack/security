// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security/session"
)

// Example demonstrates the cookie-session life cycle: Login writes an
// encrypted cookie, Get replays it, Rotate changes the ID after a
// privilege change, and Logout clears it.
func Example() {
	codec, err := session.NewCodec([]byte("a-32-byte-or-longer-secret-key!!"))
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
