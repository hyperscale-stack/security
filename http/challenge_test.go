// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperscale-stack/security"
	httpsec "github.com/hyperscale-stack/security/http"
	"github.com/stretchr/testify/assert"
)

const (
	bearerAPI       = `Bearer realm="api"`
	invalidToken    = `Bearer realm="api", error="invalid_token", error_description="The access token is invalid or has expired."`
	insufficient    = `Bearer realm="api", error="insufficient_scope", error_description="The request requires higher privileges than provided by the access token."`
	invalidRequest  = `Bearer realm="api", error="invalid_request", error_description="The request is malformed."`
	basicAPI        = `Basic realm="api", charset="UTF-8"`
	bearerTokenSent = "Bearer some-token"
)

// mapped runs the default mapper of scheme on err for a request that carried
// the given Authorization field ("" for none).
func mapped(scheme string, err error, authorization string) (int, []string) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	rec := httptest.NewRecorder()
	httpsec.DefaultErrorMapper(scheme, "").Map(rec, req, err)

	return rec.Code, rec.Header().Values("WWW-Authenticate")
}

func challenge(values ...string) []string { return values }

// Audit CORE-10 / CORE-I6: RFC 6750 §3 and §3.1, RFC 7617 §2 and §2.1,
// RFC 9068 §4, RFC 9110 §11.6.1, §15.5.2, §15.5.4, §15.6.1, §15.6.4.
func TestDefaultErrorMapperAnswers(t *testing.T) {
	t.Parallel()

	refused := func(causes ...error) error {
		return fmt.Errorf("%w: %w", security.ErrAuthenticatorRefused, errors.Join(causes...))
	}

	cases := []struct {
		name          string
		scheme        string
		err           error
		authorization string
		status        int
		challenge     []string
	}{
		{"invalid request, bearer", "Bearer", security.ErrInvalidRequest, bearerTokenSent, http.StatusBadRequest, challenge(invalidRequest)},
		{"invalid request, no token", "Bearer", security.ErrInvalidRequest, "", http.StatusBadRequest, challenge(bearerAPI)},
		// A malformed Bearer credential is a bearer attempt (audit F-17).
		{"invalid request, bearer scheme alone", "Bearer", security.ErrInvalidRequest, "Bearer", http.StatusBadRequest, challenge(invalidRequest)},
		{"invalid request, bearer and tab", "Bearer", security.ErrInvalidRequest, "Bearer\tabc", http.StatusBadRequest, challenge(invalidRequest)},
		{"invalid request, basic credentials", "Bearer", security.ErrInvalidRequest, "Basic dTpw", http.StatusBadRequest, challenge(bearerAPI)},
		{"unavailable", "Bearer", security.ErrUnavailable, bearerTokenSent, http.StatusServiceUnavailable, challenge(bearerAPI)},
		{"unavailable joined with a verdict", "Bearer", refused(security.ErrTokenNotFound, security.ErrUnavailable), bearerTokenSent, http.StatusServiceUnavailable, challenge(bearerAPI)},
		{"expired token", "Bearer", security.ErrTokenExpired, bearerTokenSent, http.StatusUnauthorized, challenge(invalidToken)},
		{"token not found", "Bearer", security.ErrTokenNotFound, bearerTokenSent, http.StatusUnauthorized, challenge(invalidToken)},
		{"bad signature (invalid credentials)", "Bearer", fmt.Errorf("jwt: invalid signature: %w", security.ErrInvalidCredentials), bearerTokenSent, http.StatusUnauthorized, challenge(invalidToken)},
		{"lowercase bearer header", "Bearer", security.ErrInvalidCredentials, "bearer some-token", http.StatusUnauthorized, challenge(invalidToken)},
		{"credential failure without a bearer token", "Bearer", security.ErrInvalidCredentials, "Basic dTpw", http.StatusUnauthorized, challenge(bearerAPI)},
		{"refusal masked by a bail-out", "Bearer", refused(security.ErrUnsupportedCredential, security.ErrInvalidCredentials), bearerTokenSent, http.StatusUnauthorized, challenge(invalidToken)},
		{"authentication required", "Bearer", security.ErrAuthenticationRequired, "", http.StatusUnauthorized, challenge(bearerAPI)},
		{"unsupported credential", "Bearer", security.ErrUnsupportedCredential, "Digest x", http.StatusUnauthorized, challenge(bearerAPI)},
		{"access denied, bearer", "Bearer", security.ErrAccessDenied, bearerTokenSent, http.StatusForbidden, challenge(insufficient)},
		{"insufficient scope, bearer", "Bearer", security.ErrInsufficientScope, bearerTokenSent, http.StatusForbidden, challenge(insufficient)},
		{"access denied without a bearer token", "Bearer", security.ErrAccessDenied, "", http.StatusForbidden, challenge(bearerAPI)},
		{"anonymous denial", "Bearer", fmt.Errorf("%w: %w", security.ErrAuthenticationRequired, security.ErrAccessDenied), "", http.StatusUnauthorized, challenge(bearerAPI)},
		{"no extractor", "Bearer", security.ErrNoExtractor, "", http.StatusInternalServerError, challenge(bearerAPI)},
		{"no sentinel", "Bearer", errors.New("boom"), bearerTokenSent, http.StatusInternalServerError, challenge(bearerAPI)},
		{"refusal without a sentinel", "Bearer", refused(errors.New("boom")), bearerTokenSent, http.StatusInternalServerError, challenge(bearerAPI)},
		{"lowercase scheme keeps the codes", "bearer", security.ErrTokenExpired, bearerTokenSent, http.StatusUnauthorized,
			challenge(`bearer realm="api", error="invalid_token", error_description="The access token is invalid or has expired."`)},
		{"basic, invalid credentials", "Basic", security.ErrInvalidCredentials, "Basic dTpw", http.StatusUnauthorized, challenge(basicAPI)},
		{"basic, authentication required", "Basic", security.ErrAuthenticationRequired, "", http.StatusUnauthorized, challenge(basicAPI)},
		{"basic, access denied", "Basic", security.ErrAccessDenied, "Basic dTpw", http.StatusForbidden, challenge(basicAPI)},
		{"basic, invalid request", "Basic", security.ErrInvalidRequest, "Basic dTpw", http.StatusBadRequest, nil},
		{"basic, unavailable", "Basic", security.ErrUnavailable, "Basic dTpw", http.StatusServiceUnavailable, nil},
		{"basic, no sentinel", "Basic", errors.New("boom"), "Basic dTpw", http.StatusInternalServerError, nil},
		{"basic, bearer token sent", "Basic", security.ErrInvalidCredentials, bearerTokenSent, http.StatusUnauthorized, challenge(basicAPI)},
		{"custom scheme", "Negotiate", security.ErrInvalidCredentials, bearerTokenSent, http.StatusUnauthorized, challenge(`Negotiate realm="api"`)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			status, got := mapped(c.scheme, c.err, c.authorization)

			assert.Equal(t, c.status, status)
			assert.Equal(t, c.challenge, got)
		})
	}
}

func TestDefaultErrorMapperDefaultsSchemeAndRealm(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		scheme, realm, want string
	}{
		{"", "", bearerAPI},
		{"Basic", "", basicAPI},
		{"basic", "", `basic realm="api", charset="UTF-8"`},
		{"Bearer", "hyperscale", `Bearer realm="hyperscale"`},
		{"Bearer", "a \"quoted\" \\ realm\twith tab", `Bearer realm="a \"quoted\" \\ realm` + "\t" + `with tab"`},
	} {
		rec := httptest.NewRecorder()
		httpsec.DefaultErrorMapper(c.scheme, c.realm).Map(rec, httptest.NewRequest(http.MethodGet, "/", nil), security.ErrAuthenticationRequired)

		assert.Equal(t, c.want, rec.Header().Get("WWW-Authenticate"))
	}
}

// Audit CORE-10: the realm was rendered with Go's %q (\x01, é escapes
// that RFC 9110 §5.6.4 recipients decode as "x01", "u00e9").
func TestDefaultErrorMapperRefusesAnInvalidChallengeConfiguration(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		scheme, realm, want string
	}{
		{"Bea rer", "", `httpsec: challenge scheme "Bea rer" is not an RFC 9110 token`},
		{"Bearer,", "", `httpsec: challenge scheme "Bearer," is not an RFC 9110 token`},
		{"Basic", "café", `httpsec: realm "café" is not printable ASCII (RFC 9110 §5.6.4 quoted-string)`},
		{"Basic", "a\x01", `httpsec: realm "a\x01" is not printable ASCII (RFC 9110 §5.6.4 quoted-string)`},
		{"Basic", "a\r\nX-Injected: 1", `httpsec: realm "a\r\nX-Injected: 1" is not printable ASCII (RFC 9110 §5.6.4 quoted-string)`},
		{"Basic", "a\x7f", `httpsec: realm "a\x7f" is not printable ASCII (RFC 9110 §5.6.4 quoted-string)`},
	} {
		assert.PanicsWithValue(t, c.want, func() { httpsec.DefaultErrorMapper(c.scheme, c.realm) })
		assert.PanicsWithValue(t, c.want, func() {
			httpsec.Middleware(security.NewEngine(security.NewManager()),
				httpsec.WithChallengeScheme(c.scheme), httpsec.WithRealm(c.realm))
		}, "Middleware fails at construction, not per request")
	}
}
