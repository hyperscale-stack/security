// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import "net/http"

// Filter is the legacy credential extractor interface.
//
// Deprecated: use [security.Extractor] together with the new HTTP middleware
// in github.com/hyperscale-stack/security/http. Scheduled for removal at the
// end of Phase 7 of the architecture refactor.
type Filter interface {
	OnFilter(r *http.Request) *http.Request
}
