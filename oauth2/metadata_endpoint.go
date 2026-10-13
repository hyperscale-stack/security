// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/hyperscale-stack/security/oauth2/pkce"
)

// MetadataHandler returns the http.Handler for the RFC 8414 authorization
// server metadata document, to mount at
// /.well-known/oauth-authorization-server followed by the path of the
// issuer, if any (RFC 8414 §3). It answers GET and HEAD (RFC 8414 §3.1);
// any other method gets 405 with Allow: GET, HEAD.
//
// The document is built for the issuer the request resolves to, from the
// server itself, so adding a grant or changing the issuer is reflected:
//
//   - endpoint URLs are the issuer + [ServerConfig.RoutePrefix] +
//     "/<name>", consistent with wherever the handlers are mounted;
//   - jwks_uri is the issuer, a trailing "/" removed, followed by
//     "/.well-known/jwks.json" — where oidc/provider mounts its key set;
//     the oauth2 module alone serves none;
//   - grant_types_supported lists the registered grants, sorted;
//   - response_types_supported and response_modes_supported are "code" and
//     "query" — plus "token", "fragment" and the "implicit" grant type once
//     a [Server.AuthorizeHandler] enabling [AuthorizeConfig.AllowImplicit]
//     was built: they reflect the handlers built so far;
//   - token_endpoint_auth_methods_supported and
//     revocation_endpoint_auth_methods_supported list the
//     [ServerConfig.ClientAuth] methods, and
//     introspection_endpoint_auth_methods_supported the same but "none" —
//     /introspect answers confidential clients only — omitted when no
//     method is left.
func (s *Server) MetadataHandler() http.Handler {
	return http.HandlerFunc(s.serveMetadata)
}

func (s *Server) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "oauth2: metadata requires GET or HEAD", http.StatusMethodNotAllowed)

		return
	}

	issuer, _, err := s.resolveIssuer(r.Context(), r)
	if err != nil {
		s.writeOAuthError(r.Context(), w, err)

		return
	}

	base := strings.TrimSuffix(issuer, "/")
	routes := base + s.cfg.RoutePrefix
	methods := s.clientAuthMethods()

	// response_modes_supported names the modes /authorize answers in:
	// omitting it would mean ["query", "fragment"] (RFC 8414 §2), and the
	// handler refuses fragment for the code flow.
	doc := metadataDoc{
		Issuer:                            issuer,
		AuthorizationEndpoint:             routes + "/authorize",
		TokenEndpoint:                     routes + "/token",
		RevocationEndpoint:                routes + "/revoke",
		IntrospectionEndpoint:             routes + "/introspect",
		JWKSURI:                           base + "/.well-known/jwks.json",
		GrantTypesSupported:               s.grantTypes(),
		ResponseTypesSupported:            []string{responseTypeCode},
		ResponseModesSupported:            []string{responseModeQuery},
		TokenEndpointAuthMethodsSupported: methods,
		// Omitted, the revocation list would mean client_secret_basic alone
		// (RFC 8414 §2).
		RevocationEndpointAuthMethodsSupported:    methods,
		IntrospectionEndpointAuthMethodsSupported: confidentialMethods(methods),
		CodeChallengeMethodsSupported:             s.pkceMethods(),
		// Every authorization response names the issuer (RFC 9207 §2.3, §3).
		AuthorizationResponseISSParameterSupported: true,
	}

	if s.implicit.Load() {
		doc.ResponseTypesSupported = append(doc.ResponseTypesSupported, responseTypeToken)
		doc.ResponseModesSupported = append(doc.ResponseModesSupported, responseModeFragment)
		doc.GrantTypesSupported = append(doc.GrantTypesSupported, GrantTypeImplicit)
		slices.Sort(doc.GrantTypesSupported)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=300")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(doc); err != nil {
		_ = err
	}
}

// metadataDoc is the subset of RFC 8414 we publish. Adding new fields is
// trivial and binary-compatible: clients ignore unknown keys.
type metadataDoc struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// RevocationEndpointAuthMethodsSupported is never empty: NewServer
	// requires a ClientAuthenticator.
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported,omitempty"`
	// AuthorizationResponseISSParameterSupported is RFC 9207 §3; omitted, it
	// would mean false.
	AuthorizationResponseISSParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// grantTypes lists the registered grant types, sorted: map order would
// change from one response to the next.
func (s *Server) grantTypes() []string {
	return slices.Sorted(maps.Keys(s.dispatch))
}

func (s *Server) clientAuthMethods() []string {
	out := make([]string, 0, len(s.cfg.ClientAuth))
	for _, m := range s.cfg.ClientAuth {
		out = append(out, m.Method())
	}

	return out
}

// clientAuthMethodNone is the client authentication method of a public
// client, which authenticates nothing (RFC 7591 §2).
const clientAuthMethodNone = "none"

// confidentialMethods is methods without "none": the methods by which a
// confidential client may authenticate.
func confidentialMethods(methods []string) []string {
	out := make([]string, 0, len(methods))

	for _, m := range methods {
		if m != clientAuthMethodNone {
			out = append(out, m)
		}
	}

	return out
}

func (s *Server) pkceMethods() []string {
	if s.cfg.Profile.AllowsPKCEPlain() {
		return []string{pkce.MethodS256.String(), pkce.MethodPlain.String()}
	}

	return []string{pkce.MethodS256.String()}
}

// normalizeRoutePrefix cleans a user-supplied [ServerConfig.RoutePrefix]:
// an empty value defaults to "/oauth2", a missing leading slash is added,
// and a trailing slash is trimmed. The result is either "" (root mount) or
// a clean "/path".
func normalizeRoutePrefix(prefix string) string {
	if prefix == "" {
		return "/oauth2"
	}

	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}

	return strings.TrimRight(prefix, "/")
}
