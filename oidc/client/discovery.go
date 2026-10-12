// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// wellKnownPath is appended to the issuer to locate the discovery
// document (OpenID Connect Discovery 1.0 §4).
const wellKnownPath = "/.well-known/openid-configuration"

// mediaJSON is the JSON media type.
const mediaJSON = "application/json"

// authorizationEndpoint names the metadata member of the authorization
// endpoint.
const authorizationEndpoint = "authorization_endpoint"

// reservedRequestParams are the authorization request parameters the
// Client sends or does not support: an authorization endpoint query or an
// AuthOptions.ExtraParams entry may not use them, in any spelling paramKey
// equates (RFC 6749 §3.1: no parameter twice; a request object could
// override state, nonce or PKCE).
var reservedRequestParams = []string{
	paramResponseType, paramClientID, paramRedirectURI, paramScope, paramState, paramNonce, paramCodeChallenge,
	paramCodeChallengeMethod, paramResponseMode, "request", "request_uri", "claims", "registration",
	"id_token_hint", "login_hint", "max_age", "prompt", "acr_values", "ui_locales", "display",
}

// reservedParamKeys are the paramKeys of reservedRequestParams.
var reservedParamKeys = paramKeys(reservedRequestParams)

// paramKey is the comparison key of a request parameter name: two names
// with one key are one parameter to some server. Case is folded (Unicode
// simple folding: ASP.NET compares names case-insensitively, and .NET
// upper-cases 'ſ' to 'S'), and '.', ' ' and '[' read as '_', the characters
// PHP rewrites so in parameter names. ExtraParams names cannot hold a space
// or '[' (isParamName); a provider's endpoint query can.
func paramKey(name string) string {
	return foldKey(strings.Map(func(r rune) rune {
		switch r {
		case '.', ' ', '[':
			return '_'
		default:
			return r
		}
	}, name))
}

// paramKeys returns the set of the paramKeys of names.
func paramKeys(names []string) map[string]struct{} {
	keys := make(map[string]struct{}, len(names))
	for _, name := range names {
		keys[paramKey(name)] = struct{}{}
	}

	return keys
}

// isReservedParam reports whether key is the paramKey of a parameter the
// Client sends or does not support.
func isReservedParam(key string) bool {
	_, ok := reservedParamKeys[key]

	return ok
}

// providerMetadata holds the members of the discovery document the Client
// uses (Discovery §3, RFC 8414 §2, RFC 9207 §3); others are ignored.
type providerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`

	// authURL is AuthorizationEndpoint, parsed by validate, and authParams
	// the paramKeys of its query.
	authURL    *url.URL
	authParams map[string]struct{}
}

// discover retrieves and validates the metadata of issuer: one terminating
// "/" removed before the well-known suffix (§4.1), a 200 application/json
// response (§4.2), a strict JSON object whose issuer is byte-for-byte issuer
// (§4.3).
func discover(ctx context.Context, client *http.Client, issuer string, allowHTTP bool) (*providerMetadata, error) {
	body, err := fetchJSON(ctx, client, strings.TrimSuffix(issuer, "/")+wellKnownPath, mediaJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}

	var md providerMetadata
	if err := decodeStrict(body, &md); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMetadata, err)
	}

	if md.Issuer == "" {
		return nil, fmt.Errorf("%w: issuer missing", ErrInvalidMetadata)
	}

	if md.Issuer != issuer {
		return nil, fmt.Errorf("%w: got %q", ErrIssuerMismatch, md.Issuer)
	}

	if err := md.validate(allowHTTP); err != nil {
		return nil, err
	}

	return &md, nil
}

// validate checks the REQUIRED members (Discovery §3; an empty array is an
// omitted member, §4.2) and the endpoint URLs.
func (md *providerMetadata) validate(allowHTTP bool) error {
	endpoints := []struct {
		name, value string
		required    bool
	}{
		{authorizationEndpoint, md.AuthorizationEndpoint, true},
		{"token_endpoint", md.TokenEndpoint, true},
		{"jwks_uri", md.JWKSURI, true},
		{"userinfo_endpoint", md.UserInfoEndpoint, false},
	}

	for _, ep := range endpoints {
		u, err := validateEndpoint(ep.name, ep.value, ep.required, allowHTTP)
		if err != nil {
			return err
		}

		if ep.name == authorizationEndpoint {
			md.authURL = u
		}
	}

	// response_types_supported and id_token_signing_alg_values_supported,
	// also REQUIRED, are enforced by negotiate.
	if len(md.SubjectTypesSupported) == 0 {
		return fmt.Errorf("%w: subject_types_supported missing", ErrInvalidMetadata)
	}

	params, err := endpointParams(md.authURL)
	if err != nil {
		return err
	}

	md.authParams = params

	return nil
}

// validateEndpoint checks an endpoint URL — absolute https (Discovery §3),
// visible ASCII, no userinfo, no fragment; a query is allowed — and returns
// it parsed (nil for an absent optional endpoint).
func validateEndpoint(name, raw string, required, allowHTTP bool) (*url.URL, error) {
	if raw == "" {
		if required {
			return nil, fmt.Errorf("%w: %s missing", ErrInvalidMetadata, name)
		}

		return nil, nil
	}

	if !isASCII(raw, visibleASCII, maxURILength) {
		return nil, fmt.Errorf("%w: %s is not a URL", ErrInvalidMetadata, name)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidMetadata, name, err)
	}

	switch {
	case u.Scheme != schemeHTTPS && (u.Scheme != schemeHTTP || !allowHTTP):
		return nil, fmt.Errorf("%w: %s must use https", ErrInvalidMetadata, name)
	case u.Host == "" || u.Opaque != "":
		return nil, fmt.Errorf("%w: %s must be an absolute URL", ErrInvalidMetadata, name)
	case u.User != nil || strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%w: %s must not carry userinfo or a fragment", ErrInvalidMetadata, name)
	}

	return u, nil
}

// endpointParams returns the paramKeys of the authorization endpoint's
// query. The Client keeps that query (RFC 6749 §3.1), so it refuses one
// that uses a parameter the Client sends, or uses one name twice — in any
// spelling paramKey equates: the request would include a parameter more
// than once, which §3.1 forbids.
func endpointParams(u *url.URL) (map[string]struct{}, error) {
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: authorization_endpoint query: %w", ErrInvalidMetadata, err)
	}

	keys := make(map[string]struct{}, len(query))

	for _, name := range slices.Sorted(maps.Keys(query)) {
		key := paramKey(name)
		_, repeated := keys[key]

		switch {
		case isReservedParam(key):
			return nil, fmt.Errorf("%w: authorization_endpoint query sets %q", ErrInvalidMetadata, name)
		case repeated || len(query[name]) > 1:
			return nil, fmt.Errorf("%w: authorization_endpoint query repeats %q", ErrInvalidMetadata, name)
		}

		keys[key] = struct{}{}
	}

	return keys, nil
}

// negotiate checks that the provider offers what cfg needs and returns the
// effective ID Token algorithms. A capability is refused when its member
// lists values without it; an omitted member is not taken as a refusal —
// an OP really lacking the capability fails at run time — except for PKCE
// on a public client (decision D5): nonce does not protect a public
// client's code (RFC 9700 §4.5.3.2), so S256 must be advertised (§2.1.1,
// §4.7.1).
func (md *providerMetadata) negotiate(cfg Config) ([]Algorithm, error) {
	listed := func(values []string, want string) bool { return len(values) == 0 || slices.Contains(values, want) }

	switch {
	case !slices.Contains(md.ResponseTypesSupported, responseTypeCode):
		return nil, fmt.Errorf("%w: the code response type is not supported", ErrInvalidMetadata)
	case !listed(md.ResponseModesSupported, string(cfg.ResponseMode)):
		return nil, fmt.Errorf("%w: response mode %s is not supported", ErrInvalidMetadata, cfg.ResponseMode)
	case !listed(md.GrantTypesSupported, grantAuthorizationCode):
		return nil, fmt.Errorf("%w: the authorization_code grant is not supported", ErrInvalidMetadata)
	case !listed(md.TokenEndpointAuthMethodsSupported, string(cfg.AuthMethod)):
		return nil, fmt.Errorf("%w: %s client authentication is not supported", ErrInvalidMetadata, cfg.AuthMethod)
	case !listed(md.CodeChallengeMethodsSupported, methodS256):
		return nil, fmt.Errorf("%w: PKCE S256 is not supported", ErrInvalidMetadata)
	case cfg.AuthMethod == AuthMethodNone && !slices.Contains(md.CodeChallengeMethodsSupported, methodS256):
		return nil, fmt.Errorf("%w: a public client requires the provider to advertise PKCE S256", ErrInvalidMetadata)
	}

	algs := make([]Algorithm, 0, len(cfg.Algorithms))

	for _, alg := range cfg.Algorithms {
		if slices.Contains(md.IDTokenSigningAlgValuesSupported, string(alg)) {
			algs = append(algs, alg)
		}
	}

	if len(algs) == 0 {
		return nil, fmt.Errorf("%w: no ID Token signature algorithm in common", ErrInvalidMetadata)
	}

	return algs, nil
}

// fetchJSON GETs rawURL and returns its body, requiring a 200 response of
// one of the media types.
func fetchJSON(ctx context.Context, client *http.Client, rawURL string, mediaTypes ...string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept", mediaJSON)

	// The URL comes from the trusted configuration or the provider's
	// metadata, and client enforces the outbound policy at connect time.
	resp, err := client.Do(req) //nolint:gosec // G107/G704: SSRF handled by the outbound policy
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	if !hasMediaType(resp.Header.Get("Content-Type"), mediaTypes...) {
		return nil, fmt.Errorf("unexpected content type %q", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return body, nil
}

// hasMediaType reports whether a Content-Type header names one of the
// media types (parameters such as charset ignored, case-insensitive).
func hasMediaType(header string, mediaTypes ...string) bool {
	mediaType, _, err := mime.ParseMediaType(header)

	return err == nil && slices.Contains(mediaTypes, mediaType)
}
