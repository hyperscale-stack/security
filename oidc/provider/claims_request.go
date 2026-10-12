// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/hyperscale-stack/security/oauth2"
)

// ClaimsRequest is the parsed claims request parameter (OpenID Connect Core
// §5.5): the claims individually requested for the ID Token and for
// UserInfo.
type ClaimsRequest struct {
	// IDToken lists the claims requested in the ID Token.
	IDToken []ClaimRequest
	// UserInfo lists the claims requested from UserInfo.
	UserInfo []ClaimRequest
}

// ClaimRequest is one individually requested claim (Core §5.5.1).
type ClaimRequest struct {
	// Name is the claim name, case-sensitive; a language-tagged name
	// ("family_name#ja-Kana-JP", Core §5.2) is a distinct claim.
	Name string
	// Essential marks an essential claim. The provider releases essential
	// and voluntary claims alike — not returning one is never an error
	// (Core §5.5.1) — except an essential acr with values, which the
	// authentication MUST satisfy (Core §5.5.1.1).
	Essential bool
	// Values are the acceptable values, from "value" and "values", as
	// compact JSON; empty accepts any value. A claim whose value matches
	// none of them is not released (Core §5.5.1).
	Values []json.RawMessage
}

// Bounds on the claims request parameter. Its stored form shares the
// grant's ExtensionData budget (oauth2.MaxExtensionDataLength) with the
// authentication event.
const (
	maxClaimsParameterLength = 4096
	maxClaimsPerMember       = 32
	maxClaimValues           = 16
	maxClaimValueLength      = 255
	maxStoredClaimsLength    = 3072
)

// errClaimsParameter answers every malformed or oversized claims parameter;
// its description never echoes the request.
var errClaimsParameter = oauth2.ErrInvalidRequest.WithDescription("the claims parameter is malformed or too large")

// Why the strict JSON walk refuses a document.
var (
	errNotObject       = errors.New("not a JSON object")
	errDuplicateMember = errors.New("a repeated member name")
	errClaimShape      = errors.New("a claim request is neither null nor an object")
)

// clone returns a deep copy of r.
func (r ClaimsRequest) clone() ClaimsRequest {
	return ClaimsRequest{IDToken: cloneClaims(r.IDToken), UserInfo: cloneClaims(r.UserInfo)}
}

func cloneClaims(list []ClaimRequest) []ClaimRequest {
	if list == nil {
		return nil
	}

	out := make([]ClaimRequest, len(list))
	for i, c := range list {
		values := make([]json.RawMessage, len(c.Values))
		for j, v := range c.Values {
			values[j] = slices.Clone(v)
		}

		if c.Values == nil {
			values = nil
		}

		out[i] = ClaimRequest{Name: c.Name, Essential: c.Essential, Values: values}
	}

	return out
}

// parseClaimsParameter parses the claims parameter strictly: one JSON
// object of valid UTF-8, member names exact (case-sensitive) and unique at
// every level the provider interprets, userinfo and id_token objects whose
// members are null or an object of essential (boolean), value and values
// (array); unknown members are ignored (Core §5.5, §5.5.1). sub and acr
// values must be strings. Bounds: 4096 bytes, 32 claims per member, 16
// values of 255 bytes, a stored form of 3072 bytes. Empty: no request.
func parseClaimsParameter(raw string) (ClaimsRequest, error) {
	if raw == "" {
		return ClaimsRequest{}, nil
	}

	if len(raw) > maxClaimsParameterLength || !utf8.ValidString(raw) {
		return ClaimsRequest{}, errClaimsParameter
	}

	var out ClaimsRequest

	err := walkObject([]byte(raw), func(name string, value json.RawMessage) error {
		var err error

		switch name {
		case "id_token":
			out.IDToken, err = parseClaimsMember(value)
		case "userinfo":
			out.UserInfo, err = parseClaimsMember(value)
		}

		return err
	})
	if err != nil || out.validate() != nil {
		return ClaimsRequest{}, errClaimsParameter
	}

	return out, nil
}

// walkObject reads the JSON object doc — nothing may follow it — and calls
// member for each member, refusing a repeated name.
func walkObject(doc []byte, member func(name string, value json.RawMessage) error) error {
	dec := json.NewDecoder(bytes.NewReader(doc))

	tok, err := dec.Token()
	if err != nil {
		return err //nolint:wrapcheck // mapped to errClaimsParameter
	}

	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errNotObject
	}

	seen := map[string]struct{}{}

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err //nolint:wrapcheck // mapped to errClaimsParameter
		}

		name, _ := tok.(string) // an object member always starts with a name

		if _, dup := seen[name]; dup {
			return errDuplicateMember
		}

		seen[name] = struct{}{}

		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err //nolint:wrapcheck // mapped to errClaimsParameter
		}

		if err := member(name, value); err != nil {
			return err
		}
	}

	if _, err := dec.Token(); err != nil { // the closing brace
		return err //nolint:wrapcheck // mapped to errClaimsParameter
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errNotObject
	}

	return nil
}

// parseClaimsMember parses the userinfo or id_token member.
func parseClaimsMember(doc json.RawMessage) ([]ClaimRequest, error) {
	list := []ClaimRequest{}

	err := walkObject(doc, func(name string, value json.RawMessage) error {
		if !validClaimName(name) || len(list) == maxClaimsPerMember {
			return errClaimShape
		}

		c, err := parseClaimRequest(name, value)
		list = append(list, c)

		return err
	})

	return list, err
}

// parseClaimRequest parses one individual claim request: null, or an
// object of essential, value and values (Core §5.5.1).
func parseClaimRequest(name string, doc json.RawMessage) (ClaimRequest, error) {
	c := ClaimRequest{Name: name}

	if string(doc) == jsonNull {
		return c, nil
	}

	err := walkObject(doc, func(member string, value json.RawMessage) error {
		switch member {
		case "essential":
			return json.Unmarshal(value, &c.Essential) //nolint:wrapcheck // mapped to errClaimsParameter
		case "value":
			return c.addValue(value)
		case "values":
			var values []json.RawMessage
			if err := json.Unmarshal(value, &values); err != nil {
				return err //nolint:wrapcheck // mapped to errClaimsParameter
			}

			for _, v := range values {
				if err := c.addValue(v); err != nil {
					return err
				}
			}
		}

		return nil
	})
	if err != nil {
		return c, errClaimShape
	}

	return c, nil
}

// addValue records an acceptable value, compacted.
func (c *ClaimRequest) addValue(value json.RawMessage) error {
	var compact bytes.Buffer
	if err := json.Compact(&compact, value); err != nil {
		return err //nolint:wrapcheck // mapped to errClaimsParameter
	}

	if compact.Len() > maxClaimValueLength || len(c.Values) == maxClaimValues {
		return errClaimShape
	}

	c.Values = append(c.Values, compact.Bytes())

	return nil
}

// validate checks what the request means: sub and acr values that are
// non-empty strings — a null or empty one designates no end-user and names
// no authentication context (Core §5.5.1.1: an essential acr requirement
// cannot be met by an authentication without acr) —, and the stored form
// within its budget.
func (r ClaimsRequest) validate() error {
	for _, list := range [][]ClaimRequest{r.IDToken, r.UserInfo} {
		for _, c := range list {
			if (c.Name == claimSub || c.Name == claimACR) && stringValues(c.Values) == nil && len(c.Values) > 0 {
				return errClaimShape
			}
		}
	}

	stored, err := json.Marshal(grantContext{IDToken: storedClaims(r.IDToken), UserInfo: storedClaims(r.UserInfo)})
	if err != nil || len(stored) > maxStoredClaimsLength {
		return errClaimShape
	}

	return nil
}

// stringValues decodes values that are all non-empty JSON strings, or
// returns nil. JSON null decodes without an error, as an empty string:
// refused with the empty strings.
func stringValues(values []json.RawMessage) []string {
	out := make([]string, 0, len(values))

	for _, v := range values {
		var s string
		if json.Unmarshal(v, &s) != nil || s == "" {
			return nil
		}

		out = append(out, s)
	}

	return out
}

// essentialACR returns the values of an essential acr request for the ID
// Token (Core §5.5.1.1) — from value and values.
func (r ClaimsRequest) essentialACR() []string {
	var out []string

	for _, c := range r.IDToken {
		if c.Name == claimACR && c.Essential {
			out = append(out, stringValues(c.Values)...)
		}
	}

	return out
}

// subjects returns the end-users every sub constraint of the request
// allows — nil without one; an empty, non-nil set when they conflict
// (Core §5.5.1: "If the Claim was sub, a mismatch MUST cause the
// authentication to fail").
func (r ClaimsRequest) subjects() []string {
	var out []string

	for _, list := range [][]ClaimRequest{r.IDToken, r.UserInfo} {
		for _, c := range list {
			if c.Name == claimSub && len(c.Values) > 0 {
				out = intersect(out, stringValues(c.Values))
			}
		}
	}

	return out
}

// releases reports whether the release list of a Decision covers the
// requested claim name: the same name, or the untagged name of a
// language-tagged one ("name" releases "name#fr").
func releases(released []string, name string) bool {
	for _, r := range released {
		if r == name || (!strings.Contains(r, "#") && strings.HasPrefix(name, r+"#")) {
			return true
		}
	}

	return false
}
