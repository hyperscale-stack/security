// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authentication

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/hyperscale-stack/security/http/header"
	"github.com/rs/zerolog"
)

// HTTPBasicFilter struct
type HTTPBasicFilter struct {
}

// NewHTTPBasicFilter constructor
func NewHTTPBasicFilter() Filter {
	return &HTTPBasicFilter{}
}

func (f HTTPBasicFilter) decodeCreds(creds string) (string, string, error) {
	c, err := base64.StdEncoding.DecodeString(creds)
	if err != nil {
		return "", "", err
	}

	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return "", "", errors.New("bad username/password format")
	}

	return cs[:s], cs[s+1:], nil
}

// OnFilter implements Filter
func (f *HTTPBasicFilter) OnFilter(r *http.Request) *http.Request {
	ctx := r.Context()

	log := zerolog.Ctx(ctx)

	auth := r.Header.Get("Authorization")
	if auth == "" {
		return r
	}

	creds, ok := header.ExtractAuthorizationValue("Basic", auth)
	if !ok {
		return r
	}

	username, password, err := f.decodeCreds(creds)
	if err != nil {
		log.Error().Err(err).Msg("deocde http basic auth failed")
		return r
	}

	token := NewUsernamePasswordAuthentication(username, password)

	return r.WithContext(ToContext(ctx, token))
}
