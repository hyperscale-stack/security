// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"encoding/json"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// MarshalJWKS serializes keys as an RFC 7517 §5 JWK Set of public signature
// keys — the document an authorization server or OpenID Provider serves at
// its jwks_uri. Every key needs a kid, unique in the set (RFC 7517 §4.5,
// OIDC Core §10.1), and must pass [PublicKey.Validate]; it is published
// with its "alg" and "use": "sig" (RFC 7517 §4.2, §4.4). A private or
// symmetric key, an invalid key, a missing or duplicated kid fail the
// whole call with [ErrInvalidKey]: nothing is published (OIDC Discovery 1.0
// §3: the JWK Set "MUST NOT contain private or symmetric key values"). No
// keys yield an empty set.
func MarshalJWKS(keys []PublicKey) ([]byte, error) {
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(keys))}
	seen := make(map[string]struct{}, len(keys))

	for i, k := range keys {
		if k.KeyID == "" {
			return nil, fmt.Errorf("%w: key %d has no kid", ErrInvalidKey, i)
		}

		if _, dup := seen[k.KeyID]; dup {
			return nil, fmt.Errorf("%w: key %d repeats a kid", ErrInvalidKey, i)
		}

		seen[k.KeyID] = struct{}{}

		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("jwt: key %d: %w", i, err)
		}

		set.Keys = append(set.Keys, k.toJOSE())
	}

	out, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("jwt: marshal jwks: %w", err)
	}

	return out, nil
}
