// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	josejson "github.com/go-jose/go-jose/v4/json"
)

// Identity is the verified result of a login: everything in it comes from
// an ID Token validated per OpenID Connect Core §3.1.3.7, delivered by the
// provider's token endpoint for the transaction the user agent started.
//
// Issuer and Subject, together, are the only stable identifier of the user
// (Core §5.7). Key accounts on (Issuer, Subject) — or on (ConnectionID,
// Issuer, Subject) when connections are tenant-scoped and several tenants
// may configure the same issuer. Never link or merge accounts by email,
// phone number or preferred_username: another subject, or another provider,
// can assert the same value. With pairwise subject identifiers the same
// person has a different Subject for every client.
//
// Tokens holds credentials. fmt and log/slog print Identity without them,
// but encoding/json writes them — deliberately, so that an application can
// persist an Identity (the golang.org/x/oauth2 convention for tokens). An
// Identity nested in a value that log/slog's JSON handler logs (a struct
// field, a map) is therefore written in full, tokens and claims included:
// log it as an attribute of its own, which LogValue redacts.
type Identity struct {
	// ConnectionID is the Config.ConnectionID of the Client.
	ConnectionID string
	// Issuer is the provider's issuer identifier.
	Issuer string
	// Subject is the sub claim: 1 to 255 printable ASCII characters.
	Subject string
	// Audience is the aud claim: the client ID, plus trusted audiences.
	Audience []string
	// AuthTime is the auth_time claim, zero when absent.
	AuthTime time.Time
	// ACR is the acr claim, "" when absent.
	ACR string
	// AMR is the amr claim, nil when absent.
	AMR []string
	// IssuedAt and ExpiresAt are the iat and exp claims of the ID Token.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Claims is the verified claims set of the ID Token: one JSON object
	// without duplicate or case-variant member names at any level.
	Claims json.RawMessage
	// Tokens are the tokens the provider issued for the login.
	Tokens Tokens
	// AppState is the AuthOptions.AppState of the login.
	AppState string
}

// LogValue implements slog.LogValuer: the identifiers of the login, never
// its tokens nor its claims.
func (id Identity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("connection_id", id.ConnectionID),
		slog.String("issuer", id.Issuer),
		slog.String("subject", id.Subject),
		slog.Time("auth_time", id.AuthTime),
		slog.String("acr", id.ACR),
	)
}

// DecodeClaims decodes the verified ID Token claims into v, matching
// member names exactly (OpenID Connect Core §14), as the Client did.
func (id *Identity) DecodeClaims(v any) error {
	if err := josejson.Unmarshal(id.Claims, v); err != nil {
		return fmt.Errorf("oidcclient: decode claims: %w", err)
	}

	return nil
}

// Tokens are the tokens of a login. They are credentials: String, GoString,
// Format and LogValue redact them, but encoding/json writes them —
// deliberately, for persistence — including when log/slog's JSON handler
// encodes Tokens nested in another value.
type Tokens struct {
	// AccessToken authorizes calls to the provider's APIs and UserInfo.
	AccessToken string
	// TokenType is the token_type, Bearer.
	TokenType string
	// RefreshToken is the refresh token, "" when none was issued. The
	// application redeems it itself.
	RefreshToken string
	// IDToken is the compact ID Token the Identity was validated from.
	IDToken string
	// Scope is the granted scope when the response states it.
	Scope string
	// Expiry is when the access token expires, zero when unstated.
	Expiry time.Time
}

// String implements fmt.Stringer without the tokens.
func (t Tokens) String() string {
	return fmt.Sprintf("oidcclient.Tokens{TokenType: %s, Scope: %q, Expiry: %s, tokens: REDACTED}",
		t.TokenType, t.Scope, t.Expiry.Format(time.RFC3339))
}

// GoString implements fmt.GoStringer without the tokens.
func (t Tokens) GoString() string { return t.String() }

// LogValue implements slog.LogValuer without the tokens.
func (t Tokens) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_type", t.TokenType), slog.String("scope", t.Scope),
		slog.Time("expiry", t.Expiry), slog.String("tokens", "REDACTED"))
}
