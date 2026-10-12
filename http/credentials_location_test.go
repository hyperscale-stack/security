// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/stretchr/testify/assert"
)

// headerExtractor reads Authorization through the carrier, like the basic
// and bearer extractors do.
type headerExtractor struct{}

func (headerExtractor) Extract(_ context.Context, c security.Carrier) (security.Authentication, error) {
	if v := c.Get("Authorization"); v == "Bearer letmein" {
		return newAuth("pending"), nil
	}

	return nil, nil
}

// Audit CORE-02 (probes TestZZAuditBasicCredentialsFromQueryAndCookie and
// TestZZAuditBearerTokenFromQueryAndCookie): credentials were accepted from
// the query string and from a cookie named Authorization.
func TestMiddlewareIgnoresCredentialsOutsideHeaderFields(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "x", result: newAuth("alice").verified()}),
		headerExtractor{},
	)
	handler := httpsec.Middleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	inQuery := httptest.NewRequest(http.MethodGet, "/?Authorization="+url.QueryEscape("Bearer letmein"), nil)

	inCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	inCookie.Header.Set("Cookie", `Authorization="Bearer letmein"`)

	inHeader := httptest.NewRequest(http.MethodGet, "/", nil)
	inHeader.Header.Set("Authorization", "Bearer letmein")

	for name, c := range map[string]struct {
		req  *http.Request
		want int
	}{
		"query string":  {inQuery, http.StatusUnauthorized},
		"cookie":        {inCookie, http.StatusUnauthorized},
		"header (ctrl)": {inHeader, http.StatusNoContent},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, c.req)

		assert.Equal(t, c.want, rec.Code, name)
	}
}
