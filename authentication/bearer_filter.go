// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"net/http"

	"github.com/hyperscale-stack/security/authentication/credential"
	"github.com/hyperscale-stack/security/http/header"
)

var _ Filter = (*BearerFilter)(nil)

// BearerFilter struct.
type BearerFilter struct {
}

// NewBearerFilter constructor.
func NewBearerFilter() Filter {
	return &BearerFilter{}
}

// OnFilter implements Filter.
func (f *BearerFilter) OnFilter(r *http.Request) *http.Request {
	ctx := r.Context()

	auth := r.Header.Get("Authorization")
	if auth == "" {
		return r
	}

	creds, ok := header.ExtractAuthorizationValue("Bearer", auth)
	if !ok {
		return r
	}

	token := credential.NewTokenCredential(creds)

	return r.WithContext(credential.ToContext(ctx, token))
}
