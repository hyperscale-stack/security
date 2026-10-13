// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
)

// The IdP session end survives the cookie round trip as a json.Number, and a
// value that is present but unreadable ends the local session (fail closed):
// before, an unexpected type silently kept the session alive.
func TestSAMLSessionEndedFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	a := &app{now: func() time.Time { return now }}

	for name, c := range map[string]struct {
		value any
		set   bool
		ended bool
	}{
		"no IdP session end":         {set: false, ended: false},
		"future, as set at login":    {value: now.Add(time.Minute).Unix(), set: true, ended: false},
		"future, after a round trip": {value: json.Number("1792000000"), set: true, ended: false},
		"past, after a round trip":   {value: json.Number("1700000000"), set: true, ended: true},
		"exactly now":                {value: now.Unix(), set: true, ended: true},
		"unreadable string":          {value: "tomorrow", set: true, ended: true},
		"unreadable float":           {value: 1.792e9, set: true, ended: true},
		"out-of-range number":        {value: json.Number("99999999999999999999"), set: true, ended: true},
	} {
		s := &session.Session{Values: map[string]any{}}
		if c.set {
			s.Values["saml_session_end"] = c.value
		}

		assert.Equal(t, c.ended, a.samlSessionEnded(s), name)
	}
}
