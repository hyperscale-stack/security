// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/pkce"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unreservedAlphabet is the RFC 3986 §2.3 unreserved set PKCE values are
// drawn from (RFC 7636 §4.1).
const unreservedAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// errorDescriptionCharset is the error_description syntax of RFC 6749
// §4.1.2.1 and §5.2: %x20-21 / %x23-5B / %x5D-7E, so no '"' and no '\'.
var errorDescriptionCharset = regexp.MustCompile(`^[\x20\x21\x23-\x5B\x5D-\x7E]*$`)

// s256 derives the S256 code_challenge of verifier.
func s256(t *testing.T, verifier string) string {
	t.Helper()

	c, ok := pkce.Challenge(pkce.MethodS256, verifier)
	require.True(t, ok)

	return c
}

// authorizePKCE runs /authorize (authorizeQuery defaults) with the given
// PKCE parameters — an empty challenge or method omits the parameter — and
// returns the redirect target.
func authorizePKCE(t *testing.T, srv *oauth2.Server, challenge, method string, consent oauth2.ConsentFunc) *url.URL {
	t.Helper()

	q := authorizeQuery()
	q.Del("code_challenge")
	q.Del("code_challenge_method")

	if challenge != "" {
		q.Set("code_challenge", challenge)
	}

	if method != "" {
		q.Set("code_challenge_method", method)
	}

	rec := runAuthorize(srv, q, consent)
	require.Equal(t, http.StatusFound, rec.Code)

	return mustLocation(t, rec)
}

// authorizeError checks that loc is an RFC 6749 §4.1.2.1 error redirect to
// the registered redirect URI and returns its error code and description.
func authorizeError(t *testing.T, loc *url.URL) (code, desc string) {
	t.Helper()

	q := loc.Query()

	assert.Equal(t, redirectURI, loc.Scheme+"://"+loc.Host+loc.Path)
	assert.Equal(t, "xyz-state", q.Get("state"))
	assert.False(t, q.Has("code"), "an error redirect carries no code")

	desc = q.Get("error_description")
	assert.Regexp(t, errorDescriptionCharset, desc)

	return q.Get("error"), desc
}

// exchangeCode redeems code at /token (client_secret_basic) with verifier.
func exchangeCode(srv *oauth2.Server, code, verifier string) *httptest.ResponseRecorder {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}

	rec := httptest.NewRecorder()
	srv.TokenHandler().ServeHTTP(rec, formRequest("/oauth2/token", form, true))

	return rec
}

// tokenError decodes an RFC 6749 §5.2 error body into its error code and
// description.
func tokenError(t *testing.T, rec *httptest.ResponseRecorder) (code, desc string) {
	t.Helper()

	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Regexp(t, errorDescriptionCharset, body.ErrorDescription)

	return body.Error, body.ErrorDescription
}

// TestAuthorizeRejectsMalformedS256Challenge covers challenges no S256
// transformation can produce (RFC 7636 §4.2, Appendix A): a code bound to
// one could never be redeemed, so /authorize refuses it before consent.
func TestAuthorizeRejectsMalformedS256Challenge(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)
	c := pkceChallenge

	cases := []struct {
		name      string
		challenge string
	}{
		{"42 chars", c[:42]},
		{"44 chars", c + "A"},
		{"padded", c + "="},
		{"standard alphabet plus", strings.Replace(c, "-", "+", 1)},
		{"standard alphabet slash", c[:10] + "/" + c[11:]},
		{"LF in place of a character", c[:20] + "\n" + c[21:]},
		{"trailing CRLF in place of a character", c[:41] + "\r\n"},
		{"trailing LF", c + "\n"},
		{"tilde", c[:10] + "~" + c[11:]},
		{"dot", c[:10] + "." + c[11:]},
		{"non-canonical trailing bits", c[:42] + "N"},
		{"non-ASCII", c[:41] + "é"},
		{"64 chars", strings.Repeat("a", 64)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			consented := false
			loc := authorizePKCE(t, srv, tc.challenge, "S256",
				func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
					consented = true

					return approve(w, r, ar)
				})

			code, desc := authorizeError(t, loc)
			assert.Equal(t, oauth2.CodeInvalidRequest, code)
			assert.Equal(t, "malformed S256 code_challenge", desc)
			assert.False(t, consented, "the ConsentFunc MUST NOT see a malformed challenge")
		})
	}
}

// TestAuthorizeRejectsMalformedPlainChallenge covers plain challenges that
// are not a valid code verifier (RFC 7636 §4.2), with the method explicit
// and absent (RFC 7636 §4.3 defaults it to plain).
func TestAuthorizeRejectsMalformedPlainChallenge(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20)

	methods := []struct {
		name   string
		method string
	}{
		{"plain", "plain"},
		{"absent method", ""},
	}

	challenges := []struct {
		name      string
		challenge string
	}{
		{"42 chars", strings.Repeat("a", 42)},
		{"129 chars", strings.Repeat("a", 129)},
		{"plus", strings.Repeat("a", 42) + "+"},
		{"embedded space", pkceVerifier[:20] + " " + pkceVerifier[20:]},
		{"trailing LF", pkceVerifier + "\n"},
		{"non-ASCII", strings.Repeat("a", 41) + "é"},
	}

	for _, m := range methods {
		for _, tc := range challenges {
			t.Run(m.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				code, desc := authorizeError(t, authorizePKCE(t, srv, tc.challenge, m.method, approve))
				assert.Equal(t, oauth2.CodeInvalidRequest, code)
				assert.Equal(t, "malformed plain code_challenge", desc)
			})
		}
	}
}

// TestAuthorizeAcceptsWellFormedChallenges is a regression guard: valid
// challenges still reach the ConsentFunc unchanged, the method as sent.
func TestAuthorizeAcceptsWellFormedChallenges(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		profile   oauth2.Profile
		challenge string
		method    string
	}{
		{"plain, 43 chars", oauth2.Profile20, strings.Repeat("a", 43), "plain"},
		{"plain, 128 chars", oauth2.Profile20, strings.Repeat("a", 128), "plain"},
		{"plain, the whole unreserved alphabet", oauth2.Profile20, unreservedAlphabet, "plain"},
		{"absent method", oauth2.Profile20, pkceVerifier, ""},
		{"S256 under Profile20", oauth2.Profile20, pkceChallenge, "S256"},
		// /authorize cannot see the verifier: S256("x") is well-formed.
		{"S256 of a one-character verifier", oauth2.Profile20BCP, s256(t, "x"), "S256"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen *oauth2.AuthorizeRequest
			loc := authorizePKCE(t, newAuthorizeServer(t, tc.profile), tc.challenge, tc.method,
				func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
					seen = ar

					return approve(w, r, ar)
				})

			assert.NotEmpty(t, loc.Query().Get("code"))
			assert.Empty(t, loc.Query().Get("error"))
			require.NotNil(t, seen)
			assert.Equal(t, tc.challenge, seen.CodeChallenge)
			assert.Equal(t, tc.method, seen.CodeChallengeMethod)
		})
	}
}

// TestAuthorizePKCEChecksKeepTheirPrecedence: presence, method and profile
// are checked before the challenge syntax, so a request breaking several
// rules keeps the error of the first one. The descriptions are pinned
// verbatim: they hold no '"' or '\' and never echo the method.
func TestAuthorizePKCEChecksKeepTheirPrecedence(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	cases := []struct {
		name      string
		challenge string
		method    string
		want      string
	}{
		{"missing challenge", "", "S256", "code_challenge is required"},
		{"plain with a malformed challenge", "short", "plain", "code_challenge_method plain is refused by the active profile"},
		{"absent method with a malformed challenge", "short", "", "code_challenge_method plain is refused by the active profile"},
		{"hostile unsupported method with a malformed challenge", "short", `S512"\`, "unsupported code_challenge_method"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			code, desc := authorizeError(t, authorizePKCE(t, srv, tc.challenge, tc.method, approve))
			assert.Equal(t, oauth2.CodeInvalidRequest, code)
			assert.Equal(t, tc.want, desc)
			assert.NotContains(t, desc, "S512", "the method is never echoed")
		})
	}
}

// TestAuthorizeCodeFlowRejectsOneCharacterVerifier reproduces issue #79
// through the real handlers. S256("x") is a well-formed challenge, so only
// /token can refuse the one-character verifier behind it.
func TestAuthorizeCodeFlowRejectsOneCharacterVerifier(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	code := authorizePKCE(t, srv, s256(t, "x"), "S256", approve).Query().Get("code")
	require.NotEmpty(t, code)

	rec := exchangeCode(srv, code, "x")
	require.Equal(t, http.StatusBadRequest, rec.Code)

	errCode, desc := tokenError(t, rec)
	assert.Equal(t, oauth2.CodeInvalidGrant, errCode)
	assert.Equal(t, "malformed code_verifier", desc)
}

// TestAuthorizeCodeFlowMalformedVerifierBurnsTheCode: the code is consumed
// before the verifier is checked, so a malformed verifier burns it like a
// wrong one. Retrying the same code with the right verifier is refused; it
// would succeed had the code survived.
func TestAuthorizeCodeFlowMalformedVerifierBurnsTheCode(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	rec := runAuthorize(srv, authorizeQuery(), approve)
	require.Equal(t, http.StatusFound, rec.Code)

	code := mustLocation(t, rec).Query().Get("code")
	require.NotEmpty(t, code)

	malformed := exchangeCode(srv, code, pkceVerifier+" ")
	require.Equal(t, http.StatusBadRequest, malformed.Code)

	errCode, desc := tokenError(t, malformed)
	assert.Equal(t, oauth2.CodeInvalidGrant, errCode)
	assert.Equal(t, "malformed code_verifier", desc)

	retry := exchangeCode(srv, code, pkceVerifier)
	require.Equal(t, http.StatusBadRequest, retry.Code)
	assert.Equal(t, oauth2.CodeInvalidGrant, decodeError(t, retry))
}

// TestAuthorizeCodeFlowEnforcesVerifierSyntax sends the verifiers whose form
// encoding matters — a space travels as "+", a literal "+" as "%2B" — bound
// to their own S256 challenge, so only the syntax check can refuse them.
func TestAuthorizeCodeFlowEnforcesVerifierSyntax(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		verifier string
	}{
		{"trailing space", pkceVerifier + " "},
		{"standard base64 plus", strings.Repeat("a", 42) + "+"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newAuthorizeServer(t, oauth2.Profile20BCP)

			code := authorizePKCE(t, srv, s256(t, tc.verifier), "S256", approve).Query().Get("code")
			require.NotEmpty(t, code)

			rec := exchangeCode(srv, code, tc.verifier)
			require.Equal(t, http.StatusBadRequest, rec.Code)

			errCode, desc := tokenError(t, rec)
			assert.Equal(t, oauth2.CodeInvalidGrant, errCode)
			assert.Equal(t, "malformed code_verifier", desc)
		})
	}
}
