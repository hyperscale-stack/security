// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"

	"github.com/hyperscale-stack/security/authentication/credential"
)

// AccessTokenFilter struct.
type AccessTokenFilter struct {
}

// NewAccessTokenFilter constructor.
func NewAccessTokenFilter() Filter {
	return &AccessTokenFilter{}
}

// OnFilter implements Filter.
func (f *AccessTokenFilter) OnFilter(r *http.Request) *http.Request {
	ctx := r.Context()

	creds := r.URL.Query().Get("access_token")
	if creds == "" {
		return r
	}

	token := credential.NewTokenCredential(creds)

	return r.WithContext(credential.ToContext(ctx, token))
}
