// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import "encoding/json"

// ClaimsRequest is the parsed claims request parameter (OpenID Connect Core
// §5.5): the claims individually requested for the ID Token and for
// UserInfo.
type ClaimsRequest struct {
	// IDToken lists the claims requested in the ID Token.
	IDToken []ClaimRequest
	// UserInfo lists the claims requested from UserInfo.
	UserInfo []ClaimRequest
}

// ClaimRequest is one individually requested claim (Core §5.5.1).
type ClaimRequest struct {
	// Name is the claim name, case-sensitive; a language-tagged name
	// ("family_name#ja-Kana-JP", Core §5.2) is a distinct claim.
	Name string
	// Essential marks an essential claim. The provider releases essential
	// and voluntary claims alike — not returning one is never an error
	// (Core §5.5.1) — except an essential acr with values, which the
	// authentication MUST satisfy (Core §5.5.1.1).
	Essential bool
	// Values are the acceptable values, from "value" and "values", as
	// compact JSON; empty accepts any value. A claim whose value matches
	// none of them is not released (Core §5.5.1).
	Values []json.RawMessage
}
