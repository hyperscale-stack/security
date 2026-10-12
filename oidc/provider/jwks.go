// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"fmt"
	"net/http"

	jwtsec "github.com/hyperscale-stack/security/jwt"
)

// metadataMaxAge is the Cache-Control max-age of the JWK Set and of the
// discovery document, in seconds — the oauth2 metadata's. A key must be
// published at least that long before it signs (see [KeyRing]).
const metadataMaxAge = "max-age=300"

// JWKSHandler returns the handler of the JWK Set (RFC 7517 §5) the
// discovery document's jwks_uri points to ([Paths].JWKS): the public halves
// of the request issuer's signing keys, then its published keys, each with
// its kid, alg and use "sig". It answers GET and HEAD. A key-source failure
// or an invalid ring answers a bare 500 — never a partial set — and no
// private or symmetric key can be published (OIDC Discovery §3): the ring
// refuses them, and so does the serialization.
func (p *Provider) JWKSHandler() http.Handler {
	return http.HandlerFunc(p.serveJWKS)
}

func (p *Provider) serveJWKS(w http.ResponseWriter, r *http.Request) {
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

	body, err := jwtsec.MarshalJWKS(snap.verification)
	if err != nil {
		p.failInternal(w, r, fmt.Errorf("oidcprovider: jwks: %w", err))

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", metadataMaxAge)
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write(body)
}
