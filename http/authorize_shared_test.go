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
	"github.com/hyperscale-stack/security/voter"
	"github.com/stretchr/testify/assert"
)

// Audit CORE-01: one decision manager shared by two routes granted the ADMIN
// route to a USER, the attribute only selecting the voter family.
func TestAuthorizeSharedDecisionManagerAcrossRoutes(t *testing.T) {
	t.Parallel()

	shared := security.NewAffirmativeDecisionManager(voter.HasRole("USER"), voter.HasRole("ADMIN"))
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	mux := http.NewServeMux()
	mux.Handle("/admin", httpsec.Authorize(shared, security.Role("ADMIN"))(ok))
	mux.Handle("/user", httpsec.Authorize(shared, security.Role("USER"))(ok))

	for path, want := range map[string]int{"/admin": http.StatusForbidden, "/user": http.StatusNoContent} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(security.WithAuthentication(req.Context(), newAuth("bob", "ROLE_USER").verified()))

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		assert.Equal(t, want, rec.Code, path)
	}
}
