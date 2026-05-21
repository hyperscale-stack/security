// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hyperscale-stack/security/oauth2/pkce"
)

// MetadataHandler returns the http.Handler for RFC 8414's
// /.well-known/oauth-authorization-server discovery document. The
// payload is derived from the active ServerConfig so adding a grant or
// changing the issuer is automatically reflected.
//
// Endpoint URLs are built as issuer + ServerConfig.RoutePrefix + "/<name>",
// so the document stays consistent with wherever the handlers are mounted.
// The jwks_uri keeps the host-root .well-known location per RFC 8615.
func (s *Server) MetadataHandler() http.Handler {
	return http.HandlerFunc(s.serveMetadata)
}

func (s *Server) serveMetadata(w http.ResponseWriter, r *http.Request) {
	issuer, _, err := s.resolveIssuer(r.Context(), r)
	if err != nil {
		writeOAuthError(w, err)

		return
	}

	base := strings.TrimSuffix(issuer, "/")
	routes := base + s.cfg.RoutePrefix

	doc := metadataDoc{
		Issuer:                            issuer,
		AuthorizationEndpoint:             routes + "/authorize",
		TokenEndpoint:                     routes + "/token",
		RevocationEndpoint:                routes + "/revoke",
		IntrospectionEndpoint:             routes + "/introspect",
		JWKSURI:                           base + "/.well-known/jwks.json",
		GrantTypesSupported:               s.grantTypes(),
		ResponseTypesSupported:            []string{responseTypeCode},
		TokenEndpointAuthMethodsSupported: s.clientAuthMethods(),
		CodeChallengeMethodsSupported:     s.pkceMethods(),
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
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
}

func (s *Server) grantTypes() []string {
	out := make([]string, 0, len(s.dispatch))
	for t := range s.dispatch {
		out = append(out, t)
	}

	return out
}

func (s *Server) clientAuthMethods() []string {
	out := make([]string, 0, len(s.cfg.ClientAuth))
	for _, m := range s.cfg.ClientAuth {
		out = append(out, m.Method())
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
