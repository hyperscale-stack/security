// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	josejson "github.com/go-jose/go-jose/v4/json"
)

// mediaJWT is the media type of a signed or encrypted UserInfo response.
const mediaJWT = "application/jwt"

// UserInfo are UserInfo claims whose subject was verified to be the
// identity's (OpenID Connect Core §5.3.2). fmt and log/slog print the
// subject only; encoding/json writes the claims, which are personal data,
// not secrets.
type UserInfo struct {
	// Subject is the sub claim, equal to Identity.Subject.
	Subject string
	// Claims is the UserInfo response: one JSON object without duplicate
	// or case-variant member names at any level. Like ID Token claims other
	// than iss and sub, its values are not stable identifiers (Core §5.7):
	// never link accounts on them.
	Claims json.RawMessage
}

// Decode decodes the claims into v, matching member names exactly (Core
// §14).
func (u *UserInfo) Decode(v any) error {
	if err := josejson.Unmarshal(u.Claims, v); err != nil {
		return fmt.Errorf("oidcclient: decode UserInfo claims: %w", err)
	}

	return nil
}

// String implements fmt.Stringer with the subject only: the claims —
// personal data — are left out, as from LogValue.
func (u UserInfo) String() string {
	return fmt.Sprintf("oidcclient.UserInfo{Subject: %q}", u.Subject)
}

// GoString implements fmt.GoStringer like String.
func (u UserInfo) GoString() string { return u.String() }

// LogValue implements slog.LogValuer without the claims.
func (u UserInfo) LogValue() slog.Value {
	return slog.GroupValue(slog.String("subject", u.Subject))
}

// UserInfo fetches the UserInfo claims of id (OpenID Connect Core §5.3): a
// GET with id's access token as a Bearer token in the Authorization header
// (RFC 6750 §2.1), never redirected. It refuses an identity of another
// connection or issuer — the token is only ever sent to the provider that
// issued it — and returns the claims only when the response is a JSON
// object (signed or encrypted responses, application/jwt, are not
// supported: ErrUserInfoUnsupported) whose sub is exactly id.Subject;
// otherwise the values MUST NOT be used and nothing is returned
// (ErrUserInfoSubject).
func (c *Client) UserInfo(ctx context.Context, id *Identity) (*UserInfo, error) {
	if err := c.checkUserInfoRequest(id); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.md.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUserInfo, err)
	}

	req.Header.Set("Authorization", "Bearer "+id.Tokens.AccessToken)
	req.Header.Set("Accept", mediaJSON)

	resp, err := c.send.Do(req) //nolint:gosec // G107/G704: endpoint from validated metadata, outbound policy enforced
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUserInfo, clipped(err)) // a refused redirect names its Location
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)

	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: read response: %w", ErrUserInfo, err)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%w: unexpected status %d", ErrUserInfo, resp.StatusCode)
	case hasMediaType(resp.Header.Get("Content-Type"), mediaJWT):
		return nil, ErrUserInfoUnsupported
	case !hasMediaType(resp.Header.Get("Content-Type"), mediaJSON):
		return nil, fmt.Errorf("%w: unexpected content type", ErrUserInfo)
	}

	var claims struct {
		Subject *string `json:"sub"`
	}

	if err := decodeStrict(body, &claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUserInfo, err)
	}

	if claims.Subject == nil || *claims.Subject != id.Subject {
		return nil, ErrUserInfoSubject
	}

	return &UserInfo{Subject: id.Subject, Claims: body}, nil
}

// checkUserInfoRequest refuses an identity this Client did not produce
// and a provider without a UserInfo endpoint.
func (c *Client) checkUserInfoRequest(id *Identity) error {
	switch {
	case id == nil:
		return fmt.Errorf("%w: no identity", ErrUserInfo)
	case id.ConnectionID != c.cfg.ConnectionID || id.Issuer != c.md.Issuer:
		return fmt.Errorf("%w: identity of another connection", ErrUserInfo)
	case id.Subject == "" || id.Tokens.AccessToken == "":
		return fmt.Errorf("%w: identity without subject or access token", ErrUserInfo)
	case c.md.UserInfoEndpoint == "":
		return fmt.Errorf("%w: the provider has no UserInfo endpoint", ErrUserInfo)
	}

	return nil
}
