// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"net/http"
	"strings"
)

// MetadataHandler returns the http.Handler for RFC 8414's
// /.well-known/oauth-authorization-server discovery document. The
// payload is derived from the active ServerConfig so adding a grant or
// changing the issuer is automatically reflected.
//
// Endpoint URLs in the document use the request's URL as a prefix. This
// works for the simple "mount under /oauth2" topology; deployments that
// expose endpoints under different paths can override by writing their
// own handler that calls [Server.Metadata] and adjusts the URLs.
func (s *Server) MetadataHandler() http.Handler {
	return http.HandlerFunc(s.serveMetadata)
}

func (s *Server) serveMetadata(w http.ResponseWriter, r *http.Request) {
	issuer, _, err := s.resolveIssuer(r.Context(), r)
	if err != nil {
		writeOAuthError(w, err)

		return
	}

	prefix := strings.TrimSuffix(issuer, "/")

	doc := metadataDoc{
		Issuer:                            issuer,
		AuthorizationEndpoint:             prefix + "/oauth2/authorize",
		TokenEndpoint:                     prefix + "/oauth2/token",
		RevocationEndpoint:                prefix + "/oauth2/revoke",
		IntrospectionEndpoint:             prefix + "/oauth2/introspect",
		JWKSURI:                           prefix + "/.well-known/jwks.json",
		GrantTypesSupported:               s.grantTypes(),
		ResponseTypesSupported:            []string{"code"},
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
		return []string{"S256", "plain"}
	}

	return []string{"S256"}
}
