// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"testing"

	"github.com/hyperscale-stack/security/session"
)

// FuzzManagerGet: whatever two cookies of the session's name a client sends,
// Get never panics, only a cookie the key sealed opens, and two copies of
// one cookie never make a session.
func FuzzManagerGet(f *testing.F) {
	codec, err := session.NewCodec(testKey)
	if err != nil {
		f.Fatal(err)
	}

	mgr := session.NewManager(codec)
	name := mgr.CookieName()

	login := newCarrier()
	if _, err := mgr.Login(context.Background(), login, nil); err != nil {
		f.Fatal(err)
	}

	valid := login.replay().cookies[name]

	f.Add(valid, "")
	f.Add("", valid)
	f.Add(valid, valid)
	f.Add(valid, "garbage")
	f.Add("AgAAAA", "Ag")

	f.Fuzz(func(t *testing.T, a, b string) {
		c := newCarrier()
		c.cookies[name] = a
		c.more = map[string][]string{name: {b}}

		s, err := mgr.Get(context.Background(), c)
		if err != nil {
			return
		}

		// Every fuzz worker seals its own seed cookie with the same key,
		// so only structural properties are checked: an opened session
		// was sealed (an ID, a CSRF token, a deadline), and two cookies
		// never both count.
		if s == nil || s.ID == "" || s.CSRFToken == "" || s.ExpiresAt.IsZero() {
			t.Fatalf("opened a session that was never sealed: %q %q", a, b)
		}

		if a != "" && a == b {
			t.Fatalf("two copies of one cookie made a session: %q", a)
		}
	})
}
