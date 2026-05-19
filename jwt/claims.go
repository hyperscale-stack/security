// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

import (
	"encoding/json"
	"fmt"
	"time"
)

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

// NumericDate wraps a UNIX timestamp encoded as a JSON number per RFC 7519
// §2. The pointer-wrapped form on StandardClaims lets callers distinguish
// "no claim" from "claim = 0" (epoch).
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

// MarshalJSON implements [json.Marshaler]; emits a UNIX integer.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(time.Time(n).Unix())
	if err != nil {
		return nil, fmt.Errorf("jwt: marshal numeric date: %w", err)
	}

	return b, nil
}

// UnmarshalJSON implements [json.Unmarshaler]; accepts integer or float.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err //nolint:wrapcheck // pass-through json error
	}

	sec, nsec := int64(f), int64((f-float64(int64(f)))*1e9)
	*n = NumericDate(time.Unix(sec, nsec).UTC())

	return nil
}
