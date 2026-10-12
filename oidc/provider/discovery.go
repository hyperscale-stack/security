// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/pkce"
)

// protocolClaims are the claims the provider itself supplies, published
// first in claims_supported.
var protocolClaims = []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "at_hash"}

// DiscoveryHandler returns the handler of the OpenID Provider Configuration
// document (OpenID Connect Discovery 1.0 §3, §4) of the request's issuer —
// served at [Paths].Discovery, and optionally at [Paths].Metadata (a valid
// RFC 8414 document too). It is derived from the server's configuration —
// issuer, RoutePrefix, grants, client authentication methods, profile — and
// from the issuer's keys, and advertises only what is served:
//   - response_types_supported ["code"], response_modes_supported ["query"]
//     (omitted, it would mean query and fragment), subject_types_supported
//     ["public"];
//   - request_parameter_supported and request_uri_parameter_supported
//     false (omitted, the latter would mean true), claims_parameter_supported
//     true, authorization_response_iss_parameter_supported true (RFC 9207);
//   - offline_access among the scopes only when a refresh_token grant is
//     registered; acr_values_supported only when configured;
//   - no registration_endpoint, no encryption, request-object, signed
//     UserInfo or session-management metadata.
//
// Endpoint URLs are the trimmed issuer, the RoutePrefix and the endpoint
// name, and jwks_uri the trimmed issuer and "/.well-known/jwks.json" — the
// formulas of the oauth2 RFC 8414 document, with which every common member
// agrees (RFC 9068 §4). The issuer is published verbatim; relying parties
// require it to equal the URL they fetched the document from (Discovery
// §4.3). It answers GET and HEAD, a resolver, issuer or key-ring failure
// with a bare 500.
func (p *Provider) DiscoveryHandler() http.Handler {
	return http.HandlerFunc(p.serveDiscovery)
}

func (p *Provider) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	if !allowGetHead(w, r) {
		return
	}

	issuer, err := p.resolveIssuer(r)
	if err != nil {
		p.failInternal(w, r, err)

		return
	}

	snap, err := p.keys(r.Context(), issuer)
	if err != nil {
		p.failInternal(w, r, err)

		return
	}

	body, err := json.Marshal(p.discoveryDocument(issuer, snap))
	if err != nil {
		p.failInternal(w, r, fmt.Errorf("oidcprovider: discovery: %w", err))

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", metadataMaxAge)
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(body)
}

// discoveryDocument is the published OpenID Provider metadata.
type discoveryDocument struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ACRValuesSupported                         []string `json:"acr_values_supported,omitempty"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	AuthorizationResponseISSParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (p *Provider) discoveryDocument(issuer string, snap *keySnapshot) discoveryDocument {
	sc := p.server.Config()
	base := strings.TrimSuffix(issuer, "/")
	routes := base + sc.RoutePrefix

	return discoveryDocument{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      routes + "/authorize",
		TokenEndpoint:                              routes + "/token",
		UserInfoEndpoint:                           routes + "/userinfo",
		JWKSURI:                                    base + jwksSuffix,
		RevocationEndpoint:                         routes + "/revoke",
		IntrospectionEndpoint:                      routes + "/introspect",
		ScopesSupported:                            p.scopesSupported(),
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        grantTypes(sc.Grants),
		SubjectTypesSupported:                      []string{"public"},
		IDTokenSigningAlgValuesSupported:           algorithmNames(snap),
		TokenEndpointAuthMethodsSupported:          authMethods(sc.ClientAuth),
		CodeChallengeMethodsSupported:              pkceMethods(sc.Profile),
		ClaimsSupported:                            p.claimsSupported,
		ACRValuesSupported:                         p.cfg.ACRValuesSupported,
		ClaimsParameterSupported:                   true,
		RequestParameterSupported:                  false,
		RequestURIParameterSupported:               false,
		AuthorizationResponseISSParameterSupported: true,
	}
}

// scopesSupported lists openid, the claim scopes (Core §5.4) and, when a
// refresh_token grant can honor it, offline_access (Core §11).
func (p *Provider) scopesSupported() []string {
	scopes := []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeAddress, ScopePhone}
	if p.refresh {
		scopes = append(scopes, ScopeOfflineAccess)
	}

	return scopes
}

func grantTypes(grants []oauth2.Grant) []string {
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		out = appendUnique(out, g.Type())
	}

	return out
}

func authMethods(auths []oauth2.ClientAuthenticator) []string {
	out := make([]string, 0, len(auths))
	for _, a := range auths {
		out = appendUnique(out, a.Method())
	}

	return out
}

func algorithmNames(snap *keySnapshot) []string {
	out := make([]string, 0, len(snap.algorithms))
	for _, a := range snap.algorithms {
		out = append(out, a.String())
	}

	return out
}

// pkceMethods lists the PKCE methods the profile accepts — the oauth2
// metadata's rule.
func pkceMethods(profile oauth2.Profile) []string {
	if profile.AllowsPKCEPlain() {
		return []string{pkce.MethodS256.String(), pkce.MethodPlain.String()}
	}

	return []string{pkce.MethodS256.String()}
}
