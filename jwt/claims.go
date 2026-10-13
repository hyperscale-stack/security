// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	josejson "github.com/go-jose/go-jose/v4/json"
)

// The JSON types of the registered claims StandardClaims decodes (RFC 7519
// §4.1; scope: RFC 8693 §4.2). A member of another type — null included —
// is refused, never read as an absent claim: "nbf": null must not disable
// the not-before check.
var (
	stringClaims = []string{claimIss, claimSub, claimJti, claimScope}
	dateClaims   = []string{claimExp, claimNbf, claimIat}
)

// Claim names (RFC 7519 §4.1, RFC 8693 §4.2-§4.3, RFC 9068 §2.2).
const (
	claimIss      = "iss"
	claimSub      = "sub"
	claimAud      = "aud"
	claimExp      = "exp"
	claimNbf      = "nbf"
	claimIat      = "iat"
	claimJti      = "jti"
	claimScope    = "scope"
	claimClientID = "client_id"
)

// decodeClaims reads a verified JWS payload as a JWT Claims Set: one UTF-8
// JSON object whose member names are unique, case-sensitive and free of
// case-folding collisions (RFC 7519 §4, §7.2 step 10, §10.1.1; see
// validateJSON), with registered claims of their JSON type, decoded with
// exact name matching.
func decodeClaims(payload []byte) (*StandardClaims, error) {
	var members map[string]josejson.RawMessage
	if err := decodeStrict(payload, &members); err != nil {
		return nil, err
	}

	if err := checkClaimTypes(members); err != nil {
		return nil, err
	}

	var std StandardClaims
	if err := unmarshalExact(payload, &std); err != nil {
		return nil, err
	}

	return &std, nil
}

// checkClaimTypes refuses a registered claim of the wrong JSON type.
func checkClaimTypes(members map[string]josejson.RawMessage) error {
	for _, name := range stringClaims {
		if raw, ok := members[name]; ok && jsonKind(raw) != '"' {
			return fmt.Errorf("%w: %s is not a string", errJSON, name)
		}
	}

	for _, name := range dateClaims {
		if raw, ok := members[name]; ok && !isJSONNumber(raw) {
			return fmt.Errorf("%w: %s is not a number", errJSON, name)
		}
	}

	if raw, ok := members[claimAud]; ok && !isAudience(raw) {
		return fmt.Errorf("%w: aud is neither a string nor an array of strings", errJSON)
	}

	return nil
}

// jsonKind returns the first byte of a JSON value: '"', '{', '[', 't',
// 'f', 'n', or a number's first character; 0 for an empty value.
func jsonKind(raw []byte) byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return 0
	}

	return raw[0]
}

// isJSONNumber reports whether raw is a JSON number (RFC 8259 §6).
func isJSONNumber(raw []byte) bool {
	k := jsonKind(raw)

	return k == '-' || (k >= '0' && k <= '9')
}

// isAudience reports whether raw is a string or an array of strings (RFC
// 7519 §4.1.3).
func isAudience(raw []byte) bool {
	switch jsonKind(raw) {
	case '"':
		return true
	case '[':
		var elems []josejson.RawMessage
		if unmarshalExact(raw, &elems) != nil {
			return false
		}

		for _, e := range elems {
			if jsonKind(e) != '"' {
				return false
			}
		}

		return true
	default:
		return false
	}
}

// StandardClaims maps the RFC 7519 registered claims plus the OAuth2-friendly
// `scope` claim (RFC 9068 §2.2.3). Custom claims belong in caller-defined
// structs that embed StandardClaims.
type StandardClaims struct {
	// Issuer is the `iss` claim — who minted the token.
	Issuer string `json:"iss,omitempty"`
	// Subject is the `sub` claim — the principal the token represents.
	Subject string `json:"sub,omitempty"`
	// Audience is the `aud` claim. Per RFC 7519 §4.1.3 it is either a
	// string or an array of strings; we always (de)serialize it as a
	// slice for predictability.
	Audience Audience `json:"aud,omitempty"`
	// ExpiresAt is the `exp` claim — token expiry.
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	// NotBefore is the `nbf` claim — earliest valid timestamp.
	NotBefore *NumericDate `json:"nbf,omitempty"`
	// IssuedAt is the `iat` claim — issuance timestamp.
	IssuedAt *NumericDate `json:"iat,omitempty"`
	// JWTID is the `jti` claim — unique token identifier.
	JWTID string `json:"jti,omitempty"`
	// Scope is the OAuth2 scope claim, space-separated per RFC 9068 §2.2.3.
	Scope string `json:"scope,omitempty"`
}

// Audience is a flexible JSON representation of the `aud` claim. It marshals
// as a string when single-valued and as an array otherwise; unmarshaling
// accepts both shapes.
type Audience []string

// MarshalJSON implements [json.Marshaler].
func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return []byte("null"), nil
	case 1:
		b, err := json.Marshal(a[0])
		if err != nil {
			return nil, fmt.Errorf("jwt: marshal audience: %w", err)
		}

		return b, nil
	default:
		b, err := json.Marshal([]string(a))
		if err != nil {
			return nil, fmt.Errorf("jwt: marshal audience: %w", err)
		}

		return b, nil
	}
}

// UnmarshalJSON implements [json.Unmarshaler]; accepts string or []string.
func (a *Audience) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err //nolint:wrapcheck // pass-through json error
		}

		*a = Audience{s}

		return nil
	}

	var s []string
	if err := json.Unmarshal(b, &s); err != nil {
		return err //nolint:wrapcheck // pass-through json error
	}

	*a = Audience(s)

	return nil
}

// maxNumericDate is 9999-12-31T23:59:59Z, the last NumericDate the package
// reads or writes.
const maxNumericDate = 253402300799

// errNumericDate reports a NumericDate outside the accepted range.
var errNumericDate = errors.New("NumericDate is not a number between 1970 and year 9999")

// NumericDate wraps a UNIX timestamp encoded as a JSON number per RFC 7519
// §2. The pointer-wrapped form on StandardClaims lets callers distinguish
// "no claim" from "claim = 0" (epoch). The package reads and writes the
// dates from 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z only: a date
// outside — the zero time.Time, which encodes as year 1, included — is
// refused both ways, so that no wrapped-around or sentinel value can make a
// token immortal.
type NumericDate time.Time

// NewNumericDate constructs a NumericDate from a time.Time, truncating to
// second precision per RFC 7519.
func NewNumericDate(t time.Time) *NumericDate {
	n := NumericDate(t.Truncate(time.Second))

	return &n
}

// Time returns the underlying time.Time value.
func (n *NumericDate) Time() time.Time {
	if n == nil {
		return time.Time{}
	}

	return time.Time(*n)
}

// MarshalJSON implements [json.Marshaler]: a UNIX integer. A date outside
// the accepted range fails — and so does signing claims that carry it.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	sec := time.Time(n).Unix()
	if sec < 0 || sec > maxNumericDate {
		return nil, fmt.Errorf("jwt: %w", errNumericDate)
	}

	return strconv.AppendInt(nil, sec, 10), nil
}

// UnmarshalJSON implements [json.Unmarshaler]: a JSON number of seconds,
// fractions allowed, within the accepted range. null leaves n unchanged,
// the encoding/json convention (decoders handle a null pointer field
// themselves; the claims checks refuse a null registered date).
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		return nil
	}

	if !isJSONNumber(b) || !json.Valid(b) {
		return fmt.Errorf("jwt: %w", errNumericDate)
	}

	seconds, err := strconv.ParseFloat(string(b), 64)
	if err != nil || seconds < 0 || seconds > maxNumericDate {
		return fmt.Errorf("jwt: %w", errNumericDate)
	}

	whole, frac := math.Modf(seconds)
	*n = NumericDate(time.Unix(int64(whole), int64(frac*float64(time.Second))).UTC())

	return nil
}
