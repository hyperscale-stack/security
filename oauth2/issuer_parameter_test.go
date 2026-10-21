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
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuer = "https://auth.example"

// redirectParams returns the parameters of an authorization response:
// the query of a code-flow redirect, the fragment of an implicit one.
func redirectParams(t *testing.T, rec *httptest.ResponseRecorder, fragment bool) url.Values {
	t.Helper()

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())

	loc := mustLocation(t, rec)
	if !fragment {
		return loc.Query()
	}

	params, err := url.ParseQuery(loc.Fragment)
	require.NoError(t, err)

	return params
}

func consentWith(c *oauth2.Consent, err error) oauth2.ConsentFunc {
	return func(http.ResponseWriter, *http.Request, *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		return c, err
	}
}

// TestAuthorizationResponsesNameTheIssuer pins RFC 9207 §2: every
// authorization response of the code flow — the code and every redirected
// error, whatever its origin — carries iss, the issuer identifier the
// request resolved to.
func TestAuthorizationResponsesNameTheIssuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		query   func() url.Values
		consent oauth2.ConsentFunc
		want    string // the error code, "" for a code
	}{
		{"code issued", authorizeQuery, approve, ""},
		{"unsupported response_type", func() url.Values {
			q := authorizeQuery()
			q.Set("response_type", "id_token")

			return q
		}, approve, oauth2.CodeUnsupportedResponseType},
		{"scope not allowed", func() url.Values {
			q := authorizeQuery()
			q.Set("scope", "admin")

			return q
		}, approve, oauth2.CodeInvalidScope},
		{"PKCE missing", func() url.Values {
			q := authorizeQuery()
			q.Del("code_challenge")
			q.Del("code_challenge_method")

			return q
		}, approve, oauth2.CodeInvalidRequest},
		{"denied", authorizeQuery, consentWith(&oauth2.Consent{}, nil), oauth2.CodeAccessDenied},
		{"refused", authorizeQuery, consentWith(&oauth2.Consent{Refusal: oauth2.ErrLoginRequired}, nil), oauth2.CodeLoginRequired},
		{"consent failure", authorizeQuery, consentWith(nil, errors.New("boom")), oauth2.CodeServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newAuthorizeServer(t, oauth2.Profile20BCP)
			params := redirectParams(t, runAuthorize(srv, tc.query(), tc.consent), false)

			assert.Equal(t, testIssuer, params.Get("iss"))
			assert.Len(t, params["iss"], 1, "iss is sent once")
			assert.Equal(t, tc.want, params.Get("error"))
			assert.Equal(t, "xyz-state", params.Get("state"))

			if tc.want == "" {
				assert.NotEmpty(t, params.Get("code"))
			}
		})
	}
}

// TestExtensionRefusalNamesTheIssuer: an error an Extension hook returns
// is an authorization response too (RFC 9207 §2).
func TestExtensionRefusalNamesTheIssuer(t *testing.T) {
	t.Parallel()

	ext := &fakeExtension{
		validate: func(context.Context, *http.Request, *oauth2.AuthorizeRequest) (any, error) {
			return nil, oauth2.ErrRequestNotSupported
		},
	}
	env := newExtensionEnv(t, ext)

	params := redirectParams(t, env.authorize(oidcQuery(), approve), false)
	assert.Equal(t, oauth2.CodeRequestNotSupported, params.Get("error"))
	assert.Equal(t, testIssuer, params.Get("iss"))
}

// TestImplicitResponsesNameTheIssuer: the legacy implicit flow carries iss
// in the fragment, on success and on error.
func TestImplicitResponsesNameTheIssuer(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20)
	cfg := oauth2.AuthorizeConfig{AllowImplicit: true, ImplicitTokens: implicitTokens()}

	issued := redirectParams(t, runAuthorizeCfg(srv, cfg, implicitQuery(), approve), true)
	assert.NotEmpty(t, issued.Get("access_token"))
	assert.Equal(t, testIssuer, issued.Get("iss"))

	denied := redirectParams(t, runAuthorizeCfg(srv, cfg, implicitQuery(), consentWith(&oauth2.Consent{}, nil)), true)
	assert.Equal(t, oauth2.CodeAccessDenied, denied.Get("error"))
	assert.Equal(t, testIssuer, denied.Get("iss"))
}

// TestIssuerParameterIsFormEncoded: iss travels form-encoded and decodes
// back to the issuer identifier exactly (RFC 9207 §2.4: simple string
// comparison), path and reserved characters included.
func TestIssuerParameterIsFormEncoded(t *testing.T) {
	t.Parallel()

	const issuer = "https://auth.example/tenant-a&b=c/"

	srv, _ := newRealmServer(t, oauth2.StaticIssuer(issuer, "api"))
	params := redirectParams(t, authorizeAt(srv, "auth.example", authorizeQuery(), approve), false)

	assert.Equal(t, issuer, params.Get("iss"))
}

// TestMetadataAdvertisesTheIssuerParameter pins RFC 9207 §2.3 and §3: the
// RFC 8414 document sets authorization_response_iss_parameter_supported.
func TestMetadataAdvertisesTheIssuerParameter(t *testing.T) {
	t.Parallel()

	srv := newAuthorizeServer(t, oauth2.Profile20BCP)

	rec := httptest.NewRecorder()
	srv.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	assert.Equal(t, true, doc["authorization_response_iss_parameter_supported"])
	assert.Equal(t, testIssuer, doc["issuer"], "the iss parameter equals the metadata issuer (RFC 9207 §2.3)")
}
