// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCarrierWithContext(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	carrier := httpsec.NewCarrier(httptest.NewRecorder(), req)

	type ctxKey struct{}

	enriched := req.WithContext(context.WithValue(req.Context(), ctxKey{}, "v"))
	next := carrier.WithContext(enriched)

	assert.Equal(t, "v", next.Request().Context().Value(ctxKey{}))
	// The original carrier is left untouched.
	assert.Nil(t, carrier.Request().Context().Value(ctxKey{}))
}

// TestWithChallengeScheme checks that the option changes the scheme
// advertised in the WWW-Authenticate header on a 401.
func TestWithChallengeScheme(t *testing.T) {
	t.Parallel()

	engine := security.NewEngine(security.NewManager())

	handler := httpsec.Middleware(engine, httpsec.WithChallengeScheme("Basic"))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Basic")
}
