// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decide is a ConsentFunc answering decision, whatever the request.
func decide(decision *oauth2.Consent, err error) oauth2.ConsentFunc {
	return func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		return decision, err
	}
}

// refusalParams runs /authorize — the code flow, or the implicit one —
// on a fresh server answering consent, and returns the redirect parameters,
// the store and the errors the hook saw.
func refusalParams(t *testing.T, implicit bool, consent oauth2.ConsentFunc) (url.Values, *writeCountingStore, *errorSink) {
	t.Helper()

	sink := &errorSink{}
	srv, store := responseModeServer(t, oauth2.StaticIssuer("https://auth.example", "api"), sink)

	q := authorizeQuery()
	cfg := oauth2.AuthorizeConfig{}

	if implicit {
		q = implicitQuery()
		cfg = oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}
	}

	rec := runAuthorizeCfg(srv, cfg, q, consent)
	require.Equal(t, http.StatusFound, rec.Code)

	loc := mustLocation(t, rec)
	if !implicit {
		return loc.Query(), store, sink
	}

	params, err := url.ParseQuery(loc.Fragment)
	require.NoError(t, err)

	return params, store, sink
}

// TestConsentRefusalIsRedirected: a decision refusing with an
// authorization-endpoint error — RFC 6749 §4.1.2.1 or OpenID Connect Core
// §3.1.2.6 — is redirected as is, in the flow's response mode, with its
// description and error_uri when they fit the charset, and the state.
func TestConsentRefusalIsRedirected(t *testing.T) {
	t.Parallel()

	refusals := []*oauth2.Error{
		oauth2.ErrLoginRequired,
		oauth2.ErrConsentRequired,
		oauth2.ErrInteractionRequired,
		oauth2.ErrAccountSelectionRequired,
		oauth2.ErrRequestNotSupported,
		oauth2.ErrRequestURINotSupported,
		oauth2.ErrRegistrationNotSupported,
		oauth2.ErrInvalidRequestURI,
		oauth2.ErrInvalidRequestObject,
		oauth2.ErrAccessDenied.WithDescription("the user cancelled"),
		{Code: oauth2.CodeTemporarilyUnavailable, Description: "try again later", URI: "https://docs.example/errors#busy"},
	}

	for _, refusal := range refusals {
		for _, implicit := range []bool{false, true} {
			t.Run(refusal.Code, func(t *testing.T) {
				t.Parallel()

				params, store, sink := refusalParams(t, implicit,
					decide(&oauth2.Consent{Approved: false, Refusal: refusal}, nil))

				assert.Equal(t, refusal.Code, params.Get("error"))
				assert.Equal(t, refusal.Description, params.Get("error_description"))
				assert.Equal(t, refusal.URI, params.Get("error_uri"))
				assert.NotEmpty(t, params.Get("state"))
				assert.False(t, params.Has("code"))
				assert.False(t, params.Has("access_token"))
				assert.Zero(t, store.writes.Load())
				assert.Equal(t, []string{refusal.Code}, sink.codes())
			})
		}
	}
}

// TestConsentRefusalCodesAreRestricted: a refusal with a code the
// authorization endpoint does not define — a token-endpoint code, an
// unregistered one, a malformed one — is answered server_error; the hook
// still reaches it as the cause.
func TestConsentRefusalCodesAreRestricted(t *testing.T) {
	t.Parallel()

	for _, refusal := range []*oauth2.Error{
		oauth2.ErrInvalidGrant,
		oauth2.ErrInvalidClient,
		oauth2.ErrUnsupportedGrantType,
		{Code: "custom_refusal"},
		{Code: `login_required"`},
		{},
	} {
		t.Run(refusal.Code, func(t *testing.T) {
			t.Parallel()

			params, _, sink := refusalParams(t, false, decide(&oauth2.Consent{Refusal: refusal}, nil))

			assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
			assert.Equal(t, oauth2.ErrServerError.Description, params.Get("error_description"))

			hooked := sink.collected()
			require.Len(t, hooked, 1)
			assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(hooked[0]))
			assert.ErrorIs(t, hooked[0], refusal)
		})
	}
}

// TestConsentRefusalDescriptionIsSanitized: a description or an error_uri
// outside the RFC 6749 §4.1.2.1 charset is left out — the code still
// travels, so a localized message cannot break prompt=none.
func TestConsentRefusalDescriptionIsSanitized(t *testing.T) {
	t.Parallel()

	cases := []*oauth2.Error{
		oauth2.ErrLoginRequired.WithDescription("connexion requise, réessayez"),
		oauth2.ErrLoginRequired.WithDescription(`a "quoted" reason`),
		{Code: oauth2.CodeLoginRequired, URI: "https://docs.example/a b"},
		{Code: oauth2.CodeLoginRequired, URI: "https://docs.example/\"x\""},
	}

	for _, refusal := range cases {
		t.Run(refusal.Description+refusal.URI, func(t *testing.T) {
			t.Parallel()

			params, _, sink := refusalParams(t, false, decide(&oauth2.Consent{Refusal: refusal}, nil))

			assert.Equal(t, oauth2.CodeLoginRequired, params.Get("error"))
			assert.False(t, params.Has("error_description"))
			assert.False(t, params.Has("error_uri"))

			hooked := sink.collected()
			require.Len(t, hooked, 1)
			assert.Same(t, refusal, hooked[0], "the hook sees the refusal as returned")
		})
	}
}

// TestConsentDecisionContradictionFailsClosed: a decision approving the
// request and refusing it is answered server_error, with nothing issued.
func TestConsentDecisionContradictionFailsClosed(t *testing.T) {
	t.Parallel()

	for _, implicit := range []bool{false, true} {
		params, store, sink := refusalParams(t, implicit, decide(&oauth2.Consent{
			Approved: true, Subject: "alice", Refusal: oauth2.ErrLoginRequired,
		}, nil))

		assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
		assert.Zero(t, store.writes.Load())

		hooked := sink.collected()
		require.Len(t, hooked, 1)
		assert.ErrorIs(t, hooked[0], oauth2.ErrLoginRequired)
	}
}

// TestConsentFuncErrorsStayServerErrors: a ConsentFunc failing — even with
// an *oauth2.Error, a protocol code included — is answered server_error,
// as before: a refusal is a decision, not a failure. The cause reaches the
// hook.
func TestConsentFuncErrorsStayServerErrors(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		oauth2.ErrLoginRequired,
		oauth2.ErrAccessDenied,
		errors.New("session backend down"),
	} {
		params, _, sink := refusalParams(t, false, decide(nil, err))

		assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
		assert.Equal(t, "consent handler failed", params.Get("error_description"))

		hooked := sink.collected()
		require.Len(t, hooked, 1)
		assert.Equal(t, oauth2.CodeServerError, oauth2.IsCode(hooked[0]))
		assert.ErrorIs(t, hooked[0], err)
	}
}

// TestApprovedConsentNeedsAValidSubject: an approval names the resource
// owner — non-empty, at most 255 bytes (OpenID Connect Core §2, and the
// SQL store's subject column) — or nothing is issued and the request is
// answered server_error.
func TestApprovedConsentNeedsAValidSubject(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, subject string
		ok            bool
	}{
		{"empty", "", false},
		{"255 bytes", strings.Repeat("s", 255), true},
		{"256 bytes", strings.Repeat("s", 256), false},
		{"255 bytes ending with a multi-byte rune", strings.Repeat("s", 253) + "é", true},
		{"256 bytes ending with a multi-byte rune", strings.Repeat("s", 254) + "é", false},
	}

	for _, tc := range cases {
		for _, implicit := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				params, store, sink := refusalParams(t, implicit,
					decide(&oauth2.Consent{Approved: true, Subject: tc.subject}, nil))

				if tc.ok {
					assert.False(t, params.Has("error"))
					assert.Equal(t, int32(1), store.writes.Load())

					return
				}

				assert.Equal(t, oauth2.CodeServerError, params.Get("error"))
				assert.Zero(t, store.writes.Load())
				assert.Equal(t, []string{oauth2.CodeServerError}, sink.codes())
			})
		}
	}
}

// TestOpenIDConnectRefusalSentinels pins the OpenID Connect Core §3.1.2.6
// sentinels: their codes, a description within the RFC 6749 charset, and
// the core sentinel each wraps.
func TestOpenIDConnectRefusalSentinels(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  *oauth2.Error
		code string
		core error
	}{
		{oauth2.ErrInteractionRequired, "interaction_required", security.ErrAccessDenied},
		{oauth2.ErrLoginRequired, "login_required", security.ErrAccessDenied},
		{oauth2.ErrAccountSelectionRequired, "account_selection_required", security.ErrAccessDenied},
		{oauth2.ErrConsentRequired, "consent_required", security.ErrAccessDenied},
		{oauth2.ErrInvalidRequestURI, "invalid_request_uri", security.ErrInvalidCredentials},
		{oauth2.ErrInvalidRequestObject, "invalid_request_object", security.ErrInvalidCredentials},
		{oauth2.ErrRequestNotSupported, "request_not_supported", security.ErrUnsupportedCredential},
		{oauth2.ErrRequestURINotSupported, "request_uri_not_supported", security.ErrUnsupportedCredential},
		{oauth2.ErrRegistrationNotSupported, "registration_not_supported", security.ErrUnsupportedCredential},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.code, tc.err.Code)
		assert.Equal(t, tc.code, oauth2.IsCode(tc.err))
		assert.Regexp(t, errorDescriptionCharset, tc.err.Description)
		assert.NotEmpty(t, tc.err.Description)
		assert.ErrorIs(t, tc.err, tc.core)
		assert.Equal(t, http.StatusBadRequest, tc.err.HTTPStatus())
	}
}
