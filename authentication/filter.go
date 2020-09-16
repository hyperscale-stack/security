// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import "net/http"

// Filter interface
type Filter interface {
	OnFilter(r *http.Request) *http.Request
}
