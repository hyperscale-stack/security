// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
)

// BenchmarkMiddleware measures the overhead introduced by the
// Engine -> Carrier -> ErrorMapper pipeline on a hot path. It does NOT
// exercise the OTel exporter so numbers reflect the no-export case.
func BenchmarkMiddleware(b *testing.B) {
	authed := newAuth("alice").verified()
	engine := security.NewEngine(
		security.NewManager(&scriptedAuthn{name: "x", result: authed}),
		scriptedExtractor{auth: newAuth("alice")},
	)

	mw := httpsec.Middleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		mw.ServeHTTP(rec, req)
	}
}
