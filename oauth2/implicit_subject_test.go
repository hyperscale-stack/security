// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
)

// TestImplicitFlowNeverMintsATokenNamingItsClient pins RFC 9700 §4.15.1 for
// the implicit flow, as the resource-owner grants of /token do: a token
// whose subject equals the client's ID would pass for the client's own
// client_credentials token (RFC 9068 §2.2), so an approval naming the
// client as resource owner mints nothing — a server_error redirected in the
// fragment, naming the issuer and echoing the state, nothing saved, the
// cause ErrSubjectIsClient for the hook — while any other subject gets its
// token.
func TestImplicitFlowNeverMintsATokenNamingItsClient(t *testing.T) {
	t.Parallel()

	env := redirectEnv(t, redirectURI)

	q := boundsQuery()
	q.Set("response_type", "token")

	rec := serve(env.authorizeHandler(consentWith(&oauth2.Consent{Approved: true, Subject: "machine"}, nil)), boundsGet(q))
	params := redirectParams(t, rec, true)
	assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
	assert.Equal(t, testIssuer, params.Get("iss"))
	assert.Equal(t, "bounds-state", params.Get("state"))
	assert.False(t, params.Has("access_token"))
	assert.Zero(t, env.store.writes.Load(), "nothing saved")
	assert.True(t, env.sink.matches(oauth2.ErrSubjectIsClient), "the cause reaches the hook")

	rec = serve(env.authorizeHandler(consentWith(&oauth2.Consent{Approved: true, Subject: "alice"}, nil)), boundsGet(q))
	assert.NotEmpty(t, redirectParams(t, rec, true).Get("access_token"))
}

// boundsGet is a GET of the /authorize handler of a boundsEnv with q.
func boundsGet(q url.Values) *http.Request {
	return httptest.NewRequest(http.MethodGet, authorizePath+"?"+q.Encode(), nil)
}
