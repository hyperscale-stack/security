// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestIsNil(t *testing.T) {
	t.Parallel()

	type (
		ptr   *int
		fn    func()
		dict  map[string]int
		list  []int
		queue chan int
		name  string
	)

	x := 1

	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"untyped nil", nil, true},
		{"nil pointer", ptr(nil), true},
		{"nil func", fn(nil), true},
		{"nil map", dict(nil), true},
		{"nil slice", list(nil), true},
		{"nil channel", queue(nil), true},
		{"nil unsafe pointer", unsafe.Pointer(nil), true},
		{"pointer", &x, false},
		{"func", fn(func() {}), false},
		{"map", dict{}, false},
		{"slice", list{}, false},
		{"channel", make(queue), false},
		{"string", name(""), false},
		{"struct", struct{}{}, false},
		{"zero int", 0, false},
	}

	for _, c := range cases {
		assert.Equal(t, c.want, isNil(c.v), c.name)
	}
}
