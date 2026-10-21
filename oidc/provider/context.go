// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperscale-stack/security/oauth2"
)

// contextVersion is the version of the grant context format.
const contextVersion = 1

// errContext reports an unreadable grant context.
var errContext = errors.New("oidcprovider: unreadable grant context")

// grantContext is what the provider records with a grant it approved, as
// the grant's opaque ExtensionData, carried unchanged by the code and every
// token derived from it (OpenID Connect Core §12.2; the oauth2 stores
// refuse a rotation changing it). An OpenID grant's holds the
// authentication event and the claims released; a plain OAuth 2.0 grant's
// holds its Plain mark only (plainContext). A grant without context was
// approved by another ConsentFunc.
type grantContext struct {
	V int `json:"v"`
	// AuthTime is the authentication time, Unix seconds: positive for an
	// OpenID grant, absent from a plain one.
	AuthTime int64    `json:"auth_time,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	// Offline records consented offline access (Core §11).
	Offline  bool          `json:"oa,omitempty"`
	IDToken  []storedClaim `json:"id_token,omitempty"`
	UserInfo []storedClaim `json:"userinfo,omitempty"`
	// Plain marks a plain OAuth 2.0 grant (no openid) the provider approved:
	// its end-user is checked at every exchange, and it gets no ID Token.
	Plain bool `json:"plain,omitempty"`
}

// plainContext is the ExtensionData of a plain OAuth 2.0 grant the provider
// approved: grantContext{Plain: true}, encoded.
const plainContext = `{"v":1,"plain":true}`

// storedClaim is a released claim request, as recorded.
type storedClaim struct {
	Name      string            `json:"n"`
	Essential bool              `json:"e,omitempty"`
	Values    []json.RawMessage `json:"v,omitempty"`
}

// storedClaims returns the stored form of claim requests.
func storedClaims(list []ClaimRequest) []storedClaim {
	if len(list) == 0 {
		return nil
	}

	out := make([]storedClaim, 0, len(list))
	for _, c := range list {
		out = append(out, storedClaim(c))
	}

	return out
}

// encode returns the ExtensionData of c: at most
// oauth2.MaxExtensionDataLength bytes. The bounds on the claims request and
// on the authentication event keep a realistic context well below; an
// escape-heavy event ("<" encodes as \u003c) with a large claims request
// can exceed it, and fails the authorization closed.
func (c grantContext) encode() (string, error) {
	c.V = contextVersion

	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("oidcprovider: encode grant context: %w", err)
	}

	if len(data) > oauth2.MaxExtensionDataLength {
		return "", errors.New("oidcprovider: grant context over its budget")
	}

	return string(data), nil
}

// decodeContext reads the ExtensionData of a grant: (zero, false, nil) for
// a grant without context — a plain OAuth 2.0 grant another ConsentFunc
// approved —, an error for a context that is not exactly one this version
// wrote (unknown version or member, an OpenID context without
// authentication time, a plain one with any other member, trailing data):
// fail closed.
func decodeContext(data string) (grantContext, bool, error) {
	if data == "" {
		return grantContext{}, false, nil
	}

	dec := json.NewDecoder(bytes.NewReader([]byte(data)))
	dec.DisallowUnknownFields()

	var c grantContext
	if err := dec.Decode(&c); err != nil {
		return grantContext{}, false, fmt.Errorf("%w: %w", errContext, err)
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return grantContext{}, false, errContext
	}

	if c.V != contextVersion || !c.wellFormed() {
		return grantContext{}, false, errContext
	}

	return c, true, nil
}

// wellFormed reports whether c is a context this version writes: an OpenID
// one with its authentication time, or a plain one with its mark alone.
func (c grantContext) wellFormed() bool {
	if !c.Plain {
		return c.AuthTime > 0
	}

	return c.AuthTime == 0 && c.ACR == "" && c.AMR == nil && !c.Offline && c.IDToken == nil && c.UserInfo == nil
}
