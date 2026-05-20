// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// marshalJSON wraps json.Marshal so callers return a package-scoped error
// (satisfying wrapcheck) rather than the bare encoding/json error.
func marshalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("redisstore: marshal: %w", err)
	}

	return b, nil
}

// The DTO types below are the on-wire JSON shapes persisted in Redis. They
// deliberately omit the raw Token / Code fields — only hashes are keys, and
// the raw secret is never stored. Timestamps are Unix seconds for compact,
// unambiguous encoding. The `consumed` field name is load-bearing: the
// rotate-refresh Lua script reads it via cjson.

type codeDTO struct {
	ClientID            string `json:"client_id"`
	Subject             string `json:"subject"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Nonce               string `json:"nonce"`
	IssuedAt            int64  `json:"issued_at"`
	ExpiresAt           int64  `json:"expires_at"`
}

func encodeCode(c *oauth2.AuthorizationCode) ([]byte, error) {
	return marshalJSON(codeDTO{
		ClientID:            c.ClientID,
		Subject:             c.Subject,
		RedirectURI:         c.RedirectURI,
		Scope:               c.Scope,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		Nonce:               c.Nonce,
		IssuedAt:            c.IssuedAt.Unix(),
		ExpiresAt:           c.ExpiresAt.Unix(),
	})
}

func decodeCode(hash string, raw []byte) (*oauth2.AuthorizationCode, error) {
	var d codeDTO
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err //nolint:wrapcheck // caller wraps
	}

	return &oauth2.AuthorizationCode{
		CodeHash:            hash,
		ClientID:            d.ClientID,
		Subject:             d.Subject,
		RedirectURI:         d.RedirectURI,
		Scope:               d.Scope,
		CodeChallenge:       d.CodeChallenge,
		CodeChallengeMethod: d.CodeChallengeMethod,
		Nonce:               d.Nonce,
		IssuedAt:            time.Unix(d.IssuedAt, 0),
		ExpiresAt:           time.Unix(d.ExpiresAt, 0),
	}, nil
}

type accessDTO struct {
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scope     string `json:"scope"`
	FamilyID  string `json:"family_id"`
	Audience  string `json:"audience"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

func encodeAccess(t *oauth2.AccessToken) ([]byte, error) {
	return marshalJSON(accessDTO{
		ClientID:  t.ClientID,
		Subject:   t.Subject,
		Scope:     t.Scope,
		FamilyID:  t.FamilyID,
		Audience:  t.Audience,
		IssuedAt:  t.IssuedAt.Unix(),
		ExpiresAt: t.ExpiresAt.Unix(),
	})
}

func decodeAccess(hash string, raw []byte) (*oauth2.AccessToken, error) {
	var d accessDTO
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err //nolint:wrapcheck // caller wraps
	}

	return &oauth2.AccessToken{
		TokenHash: hash,
		ClientID:  d.ClientID,
		Subject:   d.Subject,
		Scope:     d.Scope,
		FamilyID:  d.FamilyID,
		Audience:  d.Audience,
		IssuedAt:  time.Unix(d.IssuedAt, 0),
		ExpiresAt: time.Unix(d.ExpiresAt, 0),
	}, nil
}

type refreshDTO struct {
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scope     string `json:"scope"`
	FamilyID  string `json:"family_id"`
	Consumed  bool   `json:"consumed"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

func encodeRefresh(t *oauth2.RefreshToken) ([]byte, error) {
	return marshalJSON(refreshDTO{
		ClientID:  t.ClientID,
		Subject:   t.Subject,
		Scope:     t.Scope,
		FamilyID:  t.FamilyID,
		Consumed:  t.Consumed,
		IssuedAt:  t.IssuedAt.Unix(),
		ExpiresAt: t.ExpiresAt.Unix(),
	})
}

func decodeRefresh(hash string, raw []byte) (*oauth2.RefreshToken, error) {
	var d refreshDTO
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err //nolint:wrapcheck // caller wraps
	}

	return &oauth2.RefreshToken{
		TokenHash: hash,
		ClientID:  d.ClientID,
		Subject:   d.Subject,
		Scope:     d.Scope,
		FamilyID:  d.FamilyID,
		Consumed:  d.Consumed,
		IssuedAt:  time.Unix(d.IssuedAt, 0),
		ExpiresAt: time.Unix(d.ExpiresAt, 0),
	}, nil
}

// ttlUntil returns the duration from now until t, clamped to a 1-second
// minimum so a token that is technically already expired still gets a
// short-lived key (the grant layer rejects it on its own clock anyway).
func ttlUntil(t time.Time) time.Duration {
	d := time.Until(t)
	if d < time.Second {
		return time.Second
	}

	return d
}
