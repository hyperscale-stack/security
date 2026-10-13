// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"reflect"
	"slices"
)

// nilableKinds are the kinds whose zero value is a nil a method call can
// dereference.
var nilableKinds = []reflect.Kind{
	reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer,
}

// isNil reports whether v is nil or a typed nil — an interface holding a
// nil pointer, map, slice, function or channel, the classic
// `var out *T; return out, nil`. A typed nil satisfies an interface but
// panics on the first method that dereferences it: the contract checks
// treat it as nil, so it fails closed instead.
func isNil(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)

	return slices.Contains(nilableKinds, rv.Kind()) && rv.IsNil()
}
