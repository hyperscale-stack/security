// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryResponsesResetTheFragment pins RFC 9700 §4.1.3: "Browsers
// reattach URL fragments to Location redirection URLs only if the URL in the
// Location header does not already contain a fragment. Therefore, servers
// MAY prevent browsers from reattaching fragments to redirection URLs by
// attaching an arbitrary fragment identifier, for example #_". Every
// authorization response answered in the query — a code, an error, a POST's
// 303 — ends with "#_", the registered query kept; the implicit response,
// answered in the fragment, has exactly one.
func TestQueryResponsesResetTheFragment(t *testing.T) {
	t.Parallel()

	const registered = "https://app.example/cb?x=1"

	query := func(pairs ...string) url.Values {
		q := boundsQuery()
		q.Set("redirect_uri", registered)

		for i := 0; i < len(pairs); i += 2 {
			q.Set(pairs[i], pairs[i+1])
		}

		return q
	}

	post := func(q url.Values) *http.Request {
		req := httptest.NewRequest(http.MethodPost, authorizePath, strings.NewReader(q.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return req
	}

	cases := map[string]struct {
		req    *http.Request
		status int
		want   string // the parameter the response carries
	}{
		"code":                      {httptest.NewRequest(http.MethodGet, authorizePath+"?"+query().Encode(), nil), http.StatusFound, "code"},
		"error":                     {httptest.NewRequest(http.MethodGet, authorizePath+"?"+query("scope", "admin").Encode(), nil), http.StatusFound, "error"},
		"unsupported response type": {httptest.NewRequest(http.MethodGet, authorizePath+"?"+query("response_type", "magic").Encode(), nil), http.StatusFound, "error"},
		"POST":                      {post(query()), http.StatusSeeOther, "code"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := redirectEnv(t, registered)

			rec := serve(env.authorizeHandler(approve), tc.req)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())

			location := rec.Header().Get("Location")
			assert.True(t, strings.HasPrefix(location, registered+"&"), location)
			assert.True(t, strings.HasSuffix(location, "#_"), location)
			assert.Equal(t, 1, strings.Count(location, "#"), location)

			loc := mustLocation(t, rec)
			assert.Equal(t, "_", loc.Fragment)
			assert.Equal(t, "1", loc.Query().Get("x"))
			assert.NotEmpty(t, loc.Query().Get(tc.want))
		})
	}

	t.Run("implicit", func(t *testing.T) {
		t.Parallel()

		env := redirectEnv(t, registered)

		location := authorizeTo(env, registered, "token").Header().Get("Location")
		assert.Equal(t, 1, strings.Count(location, "#"), location)
		assert.False(t, strings.HasSuffix(location, "#_"), location)

		loc, err := url.Parse(location)
		require.NoError(t, err)

		fragment, err := url.ParseQuery(loc.Fragment)
		require.NoError(t, err)
		assert.NotEmpty(t, fragment.Get("access_token"))
	})
}
