// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingGrant answers every exchange with err.
type failingGrant struct{ err error }

func (failingGrant) Type() string { return "urn:test:failing" }

func (g failingGrant) Handle(context.Context, oauth2.GrantRequest) (*oauth2.GrantResponse, error) {
	return nil, g.err
}

// tokenErrorBody decodes an RFC 6749 §5.2 body, keeping every member.
func tokenErrorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	return body
}

// TestTokenErrorsStayWithinTheRFC6749Charset: a grant answering an *Error
// whose code falls outside the RFC 6749 §5.2 error charset is answered
// server_error; a description or error_uri outside theirs is dropped from
// the body, the code kept. The hook sees the error the grant returned.
func TestTokenErrorsStayWithinTheRFC6749Charset(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                  string
		err                   *oauth2.Error
		wantCode, wantDesc    string
		wantURI               string
		wantStatus            int
		wantHookCode          string
		wantHookReachesOrigin bool
	}{
		{
			name: "code with a double quote", err: &oauth2.Error{Code: `bad"code`, Description: "x"},
			wantCode: oauth2.CodeServerError, wantDesc: "internal server error", wantStatus: http.StatusInternalServerError,
			wantHookCode: oauth2.CodeServerError, wantHookReachesOrigin: true,
		},
		{
			name: "empty code", err: &oauth2.Error{Description: "x"},
			wantCode: oauth2.CodeServerError, wantDesc: "internal server error", wantStatus: http.StatusInternalServerError,
			wantHookCode: oauth2.CodeServerError, wantHookReachesOrigin: true,
		},
		{
			name: "non-ASCII code", err: &oauth2.Error{Code: "invalid_grànt"},
			wantCode: oauth2.CodeServerError, wantDesc: "internal server error", wantStatus: http.StatusInternalServerError,
			wantHookCode: oauth2.CodeServerError, wantHookReachesOrigin: true,
		},
		{
			name: "description with a double quote", err: &oauth2.Error{Code: oauth2.CodeInvalidGrant, Description: `the "grant"`},
			wantCode: oauth2.CodeInvalidGrant, wantStatus: http.StatusBadRequest, wantHookCode: oauth2.CodeInvalidGrant,
		},
		{
			name: "non-ASCII description", err: &oauth2.Error{Code: oauth2.CodeInvalidGrant, Description: "subvention refusée"},
			wantCode: oauth2.CodeInvalidGrant, wantStatus: http.StatusBadRequest, wantHookCode: oauth2.CodeInvalidGrant,
		},
		{
			name:     "valid description and error_uri",
			err:      &oauth2.Error{Code: oauth2.CodeInvalidGrant, Description: "grant expired", URI: "https://docs.example/errors#grant"},
			wantCode: oauth2.CodeInvalidGrant, wantDesc: "grant expired", wantURI: "https://docs.example/errors#grant",
			wantStatus: http.StatusBadRequest, wantHookCode: oauth2.CodeInvalidGrant,
		},
		{
			name: "error_uri with a space", err: &oauth2.Error{Code: oauth2.CodeInvalidGrant, URI: "https://docs.example/a b"},
			wantCode: oauth2.CodeInvalidGrant, wantStatus: http.StatusBadRequest, wantHookCode: oauth2.CodeInvalidGrant,
		},
		{
			// Every character fits, but the escape is malformed: not a URI.
			name: "error_uri that is no URI", err: &oauth2.Error{Code: oauth2.CodeInvalidGrant, URI: "https://docs.example/%zz"},
			wantCode: oauth2.CodeInvalidGrant, wantStatus: http.StatusBadRequest, wantHookCode: oauth2.CodeInvalidGrant,
		},
		{
			name: "code with a backslash", err: &oauth2.Error{Code: `in\valid`},
			wantCode: oauth2.CodeServerError, wantDesc: "internal server error", wantStatus: http.StatusInternalServerError,
			wantHookCode: oauth2.CodeServerError, wantHookReachesOrigin: true,
		},
	}

	// The charset boundaries: a backslash (%x5C), DEL (%x7F) and the control
	// characters below %x20 are outside %x20-21 / %x23-5B / %x5D-7E.
	for name, desc := range map[string]string{
		"backslash": `a\b`, "DEL": "a\x7fb", "line feed": "a\nb", "carriage return": "a\rb",
		"tab": "a\tb", "control": "a\x01b", "NUL": "a\x00b",
	} {
		cases = append(cases, struct {
			name                  string
			err                   *oauth2.Error
			wantCode, wantDesc    string
			wantURI               string
			wantStatus            int
			wantHookCode          string
			wantHookReachesOrigin bool
		}{
			name: "description with a " + name, err: &oauth2.Error{Code: oauth2.CodeInvalidGrant, Description: desc},
			wantCode: oauth2.CodeInvalidGrant, wantStatus: http.StatusBadRequest, wantHookCode: oauth2.CodeInvalidGrant,
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sink := &errorSink{}
			cfg := hookServerConfig(memory.New())
			cfg.Grants = []oauth2.Grant{failingGrant{err: tc.err}}
			cfg.OnError = sink.hook

			srv, err := oauth2.NewServer(cfg)
			require.NoError(t, err)

			rec := httptest.NewRecorder()
			srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token", url.Values{"grant_type": {"urn:test:failing"}}, true))

			require.Equal(t, tc.wantStatus, rec.Code)

			body := tokenErrorBody(t, rec)
			assert.Equal(t, tc.wantCode, body["error"])

			if tc.wantDesc == "" {
				assert.NotContains(t, body, "error_description")
			} else {
				assert.Equal(t, tc.wantDesc, body["error_description"])
			}

			if tc.wantURI == "" {
				assert.NotContains(t, body, "error_uri")
			} else {
				assert.Equal(t, tc.wantURI, body["error_uri"])
			}

			hooked := sink.collected()
			require.Len(t, hooked, 1)
			assert.Equal(t, tc.wantHookCode, oauth2.IsCode(hooked[0]))
			assert.Equal(t, tc.wantHookReachesOrigin, errors.Is(hooked[0], tc.err) && oauth2.IsCode(hooked[0]) != tc.err.Code)
		})
	}
}

// TestAuthorizeErrorDescriptionsEchoNothing: the descriptions of a refused
// scope or response type neither quote nor echo the request — they stay in
// the RFC 6749 §4.1.2.1 charset whatever the client sent.
func TestAuthorizeErrorDescriptionsEchoNothing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, param, value, wantCode string
	}{
		{"scope", "scope", `read "évil"`, oauth2.CodeInvalidScope},
		{"plain scope", "scope", "admin", oauth2.CodeInvalidScope},
		{"response type", "response_type", `"magic" é`, oauth2.CodeUnsupportedResponseType},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newAuthorizeServer(t, oauth2.Profile20BCP)

			q := authorizeQuery()
			q.Set(tc.param, tc.value)

			rec := runAuthorize(srv, q, approve)
			require.Equal(t, http.StatusFound, rec.Code)

			params := mustLocation(t, rec).Query()
			assert.Equal(t, tc.wantCode, params.Get("error"))

			desc := params.Get("error_description")
			assert.NotEmpty(t, desc)
			assert.Regexp(t, errorDescriptionCharset, desc)

			for _, word := range strings.Fields(tc.value) {
				assert.NotContains(t, desc, strings.Trim(word, `"`), "the description echoes the request")
			}
		})
	}
}

// TestRevokeAndIntrospectErrorsShareTheWireRules: the other JSON error
// writers apply the same rules (the unauthenticated introspection caller
// path writes through them).
func TestRevokeAndIntrospectErrorsShareTheWireRules(t *testing.T) {
	t.Parallel()

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Storage: memory.New(), ClientStore: &staticClientStore{}, IssuerResolver: oauth2.StaticIssuer("", ""),
		ClientAuth: []oauth2.ClientAuthenticator{clientauth.NewBasic()},
	})
	require.NoError(t, err)

	for _, h := range []http.Handler{srv.RevokeHandler(), srv.IntrospectHandler()} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		require.Equal(t, http.StatusBadRequest, rec.Code)

		body := tokenErrorBody(t, rec)
		assert.Equal(t, oauth2.CodeInvalidRequest, body["error"])
		assert.Regexp(t, errorDescriptionCharset, body["error_description"])
	}
}

// TestTokenFailureWithAPlainErrorIsServerError: a grant failing with an
// error that is no *Error answers server_error; the hook gets the cause.
func TestTokenFailureWithAPlainErrorIsServerError(t *testing.T) {
	t.Parallel()

	cause := errors.New("ledger down")
	sink := &errorSink{}
	cfg := hookServerConfig(memory.New())
	cfg.Grants = []oauth2.Grant{failingGrant{err: cause}}
	cfg.OnError = sink.hook

	srv, err := oauth2.NewServer(cfg)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token", url.Values{"grant_type": {"urn:test:failing"}}, true))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, oauth2.CodeServerError, tokenErrorBody(t, rec)["error"])

	hooked := sink.collected()
	require.Len(t, hooked, 1)
	assert.ErrorIs(t, hooked[0], cause)
}
